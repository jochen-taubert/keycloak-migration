package de.usermigration.infrastructure.keycloak;

import de.usermigration.domain.model.entity.RoleGroupEntity;
import de.usermigration.domain.model.entity.UserEntity;
import de.usermigration.domain.model.enums.RoleEnum;
import de.usermigration.infrastructure.persistence.repositories.UserRepository;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.*;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@ConditionalOnProperty(name = "keycloak.migration.migrate-users", havingValue = "true")
@RequiredArgsConstructor
@Slf4j
public class KeycloakMigrationService {

    private final KeycloakAdminClient keycloakAdminClient;
    private final UserRepository userRepository;
    private final KeycloakProperties keycloakProperties;

    private String getRealm() {
        return keycloakProperties.getRealm();
    }

    private boolean isSendPasswordEmail() {
        return keycloakProperties.getMigration().isSendPasswordEmail();
    }

    private boolean isDryRun() {
        return keycloakProperties.getMigration().isDryRun();
    }

    // ===================================================================
    // Public API - Haupt-Migrationsmethoden
    // ===================================================================

    public boolean existsInKeycloak(String username) {
        if (username == null || username.isBlank()) {
            return false;
        }

        try {
            Keycloak keycloak = keycloakAdminClient.getInstance();
            UsersResource usersResource = keycloak.realm(getRealm()).users();

            List<UserRepresentation> users = usersResource.search(username, true);
            boolean exists = !users.isEmpty();

            log.debug("User {} exists in Keycloak: {}", username, exists);
            return exists;

        } catch (Exception e) {
            log.error("Error checking if user exists in Keycloak: {}", username, e);
            return false;
        }
    }

    /**
     * Migrates a user to Keycloak with the given password.
     * Loads the user fresh in a new transaction to avoid version conflicts.
     *
     * @param username      the username to migrate
     * @param plainPassword the plain text password
     * @return the Keycloak user ID of the migrated user
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public String migrateUserWithRoles(String username, String plainPassword) {
        // Load user fresh in this transaction to avoid version conflicts
        UserEntity user = userRepository.findByLoginWithRoles(username)
                .orElseThrow(() -> new KeycloakMigrationException("User not found: " + username));

        validateUserForMigration(user);

        Set<RoleEnum> roleEnums = user.getRoleEnums();
        Set<String> keycloakRoleNames = user.getKeycloakRoleNames();

        log.info("Starting migration for user: {} (ID: {}) with {} roles: {}",
                user.getLogin(),
                user.getId(),
                roleEnums.size(),
                roleEnums.stream().map(RoleEnum::getDisplayName).collect(Collectors.joining(", "))
        );

        if (isDryRun()) {
            log.info("[DRY-RUN] Would migrate user {} with roles: {}",
                    user.getLogin(), keycloakRoleNames);
            return null;
        }

        try {
            Keycloak keycloak = keycloakAdminClient.getInstance();
            UsersResource usersResource = keycloak.realm(getRealm()).users();

            if (existsInKeycloak(user.getLogin())) {
                log.warn("User {} already exists in Keycloak, skipping migration", user.getLogin());
                updateUserKeycloakId(user, usersResource);
                return user.getKeycloakId();
            }

            // Create user with role_ids attribute set during creation
            UserRepresentation userRep = createUserRepresentation(user, roleEnums);

            log.info("Creating user in Keycloak: {} with attributes: {}", user.getLogin(), userRep.getAttributes());
            Response response = usersResource.create(userRep);

            if (response.getStatus() != 201) {
                String errorBody = extractErrorBody(response);
                throw new KeycloakMigrationException(
                        String.format("Failed to create user %s in Keycloak. Status: %d, Error: %s",
                                user.getLogin(), response.getStatus(), errorBody)
                );
            }

            String keycloakUserId = extractUserIdFromResponse(response);
            log.info("User {} created in Keycloak with ID: {}", user.getLogin(), keycloakUserId);

            // Explicitly update role_ids attribute after creation (Keycloak may not accept attributes during create)
            if (!roleEnums.isEmpty()) {
                updateUserRoleIdsAttribute(keycloakUserId, roleEnums);
            }

            // Assign RoleGroups as composite roles
            assignRoleGroupsToUser(keycloak, keycloakUserId, user);

            // Not temporary: this is the user's real, already-verified password (they just
            // typed it successfully at /auth/login), so there's no need to force a Keycloak
            // "update password" required action - that would block direct/password grant
            // logins with "Account is not fully set up" for a password they already know.
            setUserPassword(usersResource, keycloakUserId, plainPassword, false);

            user.setKeycloakId(keycloakUserId);
            user.setMigratedAt(LocalDateTime.now());
            userRepository.save(user);

            log.info("Successfully migrated user {} (ID: {}) with {} role groups to Keycloak (KC-ID: {})",
                    user.getLogin(), user.getId(), user.getActiveRoleGroups().size(), keycloakUserId);

            return keycloakUserId;

        } catch (KeycloakMigrationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error migrating user {}", user.getLogin(), e);
            throw new KeycloakMigrationException(
                    "Migration failed for user: %s".formatted(user.getLogin()), e
            );
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void migrateUserWithoutPassword(UserEntity user) {
        validateUserForMigration(user);

        // Load roles BEFORE any DB operations to avoid detached entity issues
        Set<RoleEnum> roleEnums = user.getRoleEnums();
        Set<String> keycloakRoleNames = user.getKeycloakRoleNames();

        log.info("Starting batch migration for user: {} with {} roles",
                user.getLogin(), keycloakRoleNames.size());

        if (isDryRun()) {
            log.info("[DRY-RUN] Would migrate user {} with roles: {}",
                    user.getLogin(), keycloakRoleNames);
            return;
        }

        try {
            Keycloak keycloak = keycloakAdminClient.getInstance();
            UsersResource usersResource = keycloak.realm(getRealm()).users();

            // Create user with role_ids attribute set during creation
            UserRepresentation userRep = createUserRepresentation(user, roleEnums);
            Response response = usersResource.create(userRep);

            if (response.getStatus() != 201) {
                String errorBody = extractErrorBody(response);
                throw new KeycloakMigrationException(
                        String.format("Failed to create user %s. Status: %d, Error: %s",
                                user.getLogin(), response.getStatus(), errorBody)
                );
            }

            String keycloakUserId = extractUserIdFromResponse(response);

            // Assign RoleGroups as composite roles
            assignRoleGroupsToUser(keycloak, keycloakUserId, user);

            // Temporary: unlike migrateUserWithRoles, this path never has the real password -
            // this is a random one nobody knows yet, so a forced update is required here.
            String tempPassword = generateTemporaryPassword();
            setUserPassword(usersResource, keycloakUserId, tempPassword, true);

            if (isSendPasswordEmail()) {
                sendPasswordResetEmail(usersResource, keycloakUserId);
            }

            user.setKeycloakId(keycloakUserId);
            user.setMigratedAt(LocalDateTime.now());
            userRepository.save(user);

            log.info("Successfully migrated user {} (batch mode) with {} role groups to Keycloak",
                    user.getLogin(), user.getActiveRoleGroups().size());

        } catch (KeycloakMigrationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error in batch migration for user {}", user.getLogin(), e);
            throw new KeycloakMigrationException(
                    "Batch migration failed for user: %s".formatted(user.getLogin()), e
            );
        }
    }

    // ===================================================================
    // Private Helper Methods
    // ===================================================================

    private UserRepresentation createUserRepresentation(UserEntity user, Set<RoleEnum> roleEnums) {
        UserRepresentation userRep = new UserRepresentation();
        userRep.setUsername(user.getLogin());
        userRep.setEmail(user.getEmail());
        userRep.setFirstName(user.getFirstName());
        userRep.setLastName(user.getLastName());
        userRep.setEnabled(user.isActive());
        userRep.setEmailVerified(user.getEmail() != null && !user.getEmail().isBlank());

        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put("legacy_user_id", List.of(user.getId().toString()));

        if (user.getPersonalNr() != null && !user.getPersonalNr().isBlank()) {
            attributes.put("personal_nr", List.of(user.getPersonalNr()));
        }

        attributes.put("migrated_at", List.of(LocalDateTime.now().toString()));
        attributes.put("migration_source", List.of("test-api"));

        // Add role_ids attribute during user creation to ensure it's set
        if (roleEnums != null && !roleEnums.isEmpty()) {
            List<String> roleIds = roleEnums.stream()
                    .map(r -> String.valueOf(r.getRoleId()))
                    .sorted()
                    .collect(Collectors.toList());
            attributes.put("role_ids", roleIds);
            log.info("Setting role_ids attribute for user {}: {}", user.getLogin(), roleIds);
        } else {
            log.warn("No roleEnums for user {}, role_ids attribute will not be set", user.getLogin());
        }

        log.info("Final attributes for user {}: {}", user.getLogin(), attributes);
        userRep.setAttributes(attributes);

        return userRep;
    }

    private void validateUserForMigration(UserEntity user) {
        if (user == null) {
            throw new KeycloakMigrationException("User cannot be null");
        }

        if (user.getLogin() == null || user.getLogin().isBlank()) {
            throw new KeycloakMigrationException("User login cannot be null or blank");
        }

        if (user.getEmail() == null || user.getEmail().isBlank()) {
            log.warn("User {} has no email address", user.getLogin());
        }

        if (user.getRoleGroups().isEmpty()) {
            log.warn("User {} has no role groups assigned", user.getLogin());
        }
    }

    private void assignRolesToUser(Keycloak keycloak, String userId, Set<String> roleNames) {
        log.debug("Assigning {} roles to user {}", roleNames.size(), userId);

        try {
            RealmResource realmResource = keycloak.realm(getRealm());
            UserResource userResource = realmResource.users().get(userId);
            RolesResource rolesResource = realmResource.roles();

            List<RoleRepresentation> rolesToAssign = new ArrayList<>();

            for (String roleName : roleNames) {
                try {
                    RoleRepresentation role = rolesResource.get(roleName).toRepresentation();
                    // Ensure role_id attribute exists on existing roles
                    ensureRoleHasRoleIdAttribute(rolesResource, role, roleName);
                    rolesToAssign.add(role);
                    log.debug("Found existing role {} for assignment", roleName);

                } catch (NotFoundException e) {
                    log.info("Role {} not found in Keycloak, creating it", roleName);
                    createRoleInKeycloak(rolesResource, roleName);

                    RoleRepresentation role = rolesResource.get(roleName).toRepresentation();
                    rolesToAssign.add(role);
                }
            }

            if (!rolesToAssign.isEmpty()) {
                userResource.roles().realmLevel().add(rolesToAssign);
                log.info("Assigned {} roles to user {}: {}",
                        rolesToAssign.size(),
                        userId,
                        rolesToAssign.stream()
                                .map(RoleRepresentation::getName)
                                .collect(Collectors.joining(", "))
                );
            }

        } catch (Exception e) {
            log.error("Error assigning roles to user {}", userId, e);
            throw new KeycloakMigrationException(
                    "Failed to assign roles to user: %s".formatted(userId), e
            );
        }
    }

    private void createRoleInKeycloak(RolesResource rolesResource, String keycloakRoleName) {
        try {
            RoleEnum role = RoleEnum.fromString(keycloakRoleName);

            RoleRepresentation newRole = new RoleRepresentation();
            newRole.setName(keycloakRoleName);
            newRole.setDescription(role.getDescription());

            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("role_id", List.of(String.valueOf(role.getRoleId())));
            attributes.put("display_name", List.of(role.getDisplayName()));
            attributes.put("hierarchy_level", List.of(String.valueOf(role.getHierarchyLevel())));
            attributes.put("created_by", List.of("migration-service"));
            attributes.put("created_at", List.of(LocalDateTime.now().toString()));
            newRole.setAttributes(attributes);

            rolesResource.create(newRole);
            log.info("Created role in Keycloak: {} (id={}, {})", keycloakRoleName, role.getRoleId(), role.getDisplayName());

        } catch (IllegalArgumentException e) {
            log.error("Invalid role name: {}", keycloakRoleName, e);
            throw new KeycloakMigrationException(
                    "Invalid role name: %s".formatted(keycloakRoleName), e
            );
        } catch (Exception e) {
            log.error("Failed to create role: {}", keycloakRoleName, e);
            throw new KeycloakMigrationException(
                    "Failed to create role: %s".formatted(keycloakRoleName), e
            );
        }
    }

    /**
     * Ensures an existing role has the role_id attribute set.
     * Updates the role if the attribute is missing.
     */
    private void ensureRoleHasRoleIdAttribute(RolesResource rolesResource, RoleRepresentation existingRole, String roleName) {
        try {
            // Check if role_id attribute already exists
            if (existingRole.getAttributes() != null && existingRole.getAttributes().containsKey("role_id")) {
                log.debug("Role {} already has role_id attribute: {}", roleName, existingRole.getAttributes().get("role_id"));
                return;
            }

            // Get RoleEnum to find the role_id
            RoleEnum roleEnum = RoleEnum.fromString(roleName);

            // Update role with missing attributes
            Map<String, List<String>> attributes = existingRole.getAttributes() != null
                    ? new HashMap<>(existingRole.getAttributes())
                    : new HashMap<>();

            attributes.put("role_id", List.of(String.valueOf(roleEnum.getRoleId())));
            attributes.put("display_name", List.of(roleEnum.getDisplayName()));
            attributes.put("hierarchy_level", List.of(String.valueOf(roleEnum.getHierarchyLevel())));
            attributes.put("updated_by", List.of("migration-service"));
            attributes.put("updated_at", List.of(LocalDateTime.now().toString()));

            existingRole.setAttributes(attributes);
            rolesResource.get(roleName).update(existingRole);

            log.info("Updated role {} with role_id attribute: {}", roleName, roleEnum.getRoleId());

        } catch (IllegalArgumentException e) {
            log.warn("Could not find RoleEnum for role {}, skipping role_id attribute update", roleName);
        } catch (Exception e) {
            log.error("Error updating role_id attribute for role {}: {}", roleName, e.getMessage());
        }
    }

    /**
     * Creates or updates a RoleGroup as a composite role in Keycloak.
     * The composite role contains all individual roles from the RoleGroup.
     */
    private void ensureRoleGroupCompositeRole(Keycloak keycloak, RoleGroupEntity roleGroup) {
        String compositeRoleName = roleGroup.getKeycloakRoleName();
        Set<String> memberRoleNames = roleGroup.getKeycloakRoleNames();

        log.debug("Ensuring composite role {} with {} member roles", compositeRoleName, memberRoleNames.size());

        try {
            RealmResource realmResource = keycloak.realm(getRealm());
            RolesResource rolesResource = realmResource.roles();

            // 1. Ensure all member roles exist with role_id attribute
            for (String memberRoleName : memberRoleNames) {
                try {
                    RoleRepresentation existingRole = rolesResource.get(memberRoleName).toRepresentation();
                    // Check if role_id attribute exists, update if missing
                    ensureRoleHasRoleIdAttribute(rolesResource, existingRole, memberRoleName);
                } catch (NotFoundException e) {
                    createRoleInKeycloak(rolesResource, memberRoleName);
                }
            }

            // 2. Create or get composite role
            RoleResource compositeRoleResource;
            try {
                compositeRoleResource = rolesResource.get(compositeRoleName);
                compositeRoleResource.toRepresentation(); // Check if exists
                log.debug("Composite role {} already exists", compositeRoleName);
            } catch (NotFoundException e) {
                // Create composite role
                RoleRepresentation compositeRole = new RoleRepresentation();
                compositeRole.setName(compositeRoleName);
                compositeRole.setDescription("RoleGroup: " + roleGroup.getDesignation());
                compositeRole.setComposite(true);

                Map<String, List<String>> attributes = new HashMap<>();
                attributes.put("rolegroup_id", List.of(roleGroup.getId().toString()));
                attributes.put("rolegroup_designation", List.of(roleGroup.getDesignation()));
                attributes.put("is_system", List.of(String.valueOf(roleGroup.isSystemRoleGroup())));
                attributes.put("created_by", List.of("migration-service"));
                attributes.put("created_at", List.of(LocalDateTime.now().toString()));
                compositeRole.setAttributes(attributes);

                rolesResource.create(compositeRole);
                log.info("Created composite role: {} for RoleGroup: {}", compositeRoleName, roleGroup.getDesignation());

                compositeRoleResource = rolesResource.get(compositeRoleName);
            }

            // 3. Add member roles as composites
            List<RoleRepresentation> memberRoles = memberRoleNames.stream()
                    .map(name -> rolesResource.get(name).toRepresentation())
                    .toList();

            if (!memberRoles.isEmpty()) {
                // Get current composites to avoid duplicates
                Set<String> currentComposites = compositeRoleResource.getRoleComposites().stream()
                        .map(RoleRepresentation::getName)
                        .collect(Collectors.toSet());

                List<RoleRepresentation> newComposites = memberRoles.stream()
                        .filter(r -> !currentComposites.contains(r.getName()))
                        .collect(Collectors.toList());

                if (!newComposites.isEmpty()) {
                    compositeRoleResource.addComposites(newComposites);
                    log.info("Added {} member roles to composite {}: {}",
                            newComposites.size(),
                            compositeRoleName,
                            newComposites.stream().map(RoleRepresentation::getName).collect(Collectors.joining(", ")));
                }
            }

        } catch (Exception e) {
            log.error("Error creating composite role for RoleGroup {}", roleGroup.getDesignation(), e);
            throw new KeycloakMigrationException(
                    "Failed to create composite role for RoleGroup: %s".formatted(roleGroup.getDesignation()), e
            );
        }
    }

    /**
     * Assigns RoleGroup composite roles to a user.
     * Each RoleGroup the user belongs to becomes a composite role assignment.
     */
    private void assignRoleGroupsToUser(Keycloak keycloak, String userId, UserEntity user) {
        Set<RoleGroupEntity> roleGroups = user.getActiveRoleGroups();

        if (roleGroups.isEmpty()) {
            log.warn("User {} has no active role groups to assign", user.getLogin());
            return;
        }

        log.debug("Assigning {} role groups to user {}", roleGroups.size(), user.getLogin());

        try {
            RealmResource realmResource = keycloak.realm(getRealm());
            UserResource userResource = realmResource.users().get(userId);
            RolesResource rolesResource = realmResource.roles();

            List<RoleRepresentation> compositeRolesToAssign = new ArrayList<>();

            for (RoleGroupEntity roleGroup : roleGroups) {
                // Ensure composite role exists
                ensureRoleGroupCompositeRole(keycloak, roleGroup);

                // Get composite role for assignment
                String compositeRoleName = roleGroup.getKeycloakRoleName();
                RoleRepresentation compositeRole = rolesResource.get(compositeRoleName).toRepresentation();
                compositeRolesToAssign.add(compositeRole);
            }

            if (!compositeRolesToAssign.isEmpty()) {
                userResource.roles().realmLevel().add(compositeRolesToAssign);
                log.info("Assigned {} role groups to user {}: {}",
                        compositeRolesToAssign.size(),
                        user.getLogin(),
                        compositeRolesToAssign.stream()
                                .map(RoleRepresentation::getName)
                                .collect(Collectors.joining(", ")));
            }

        } catch (Exception e) {
            log.error("Error assigning role groups to user {}", user.getLogin(), e);
            throw new KeycloakMigrationException(
                    "Failed to assign role groups to user: %s".formatted(user.getLogin()), e
            );
        }
    }

    private void removeAllUserRoles(Keycloak keycloak, String userId) {
        try {
            RealmResource realmResource = keycloak.realm(getRealm());
            UserResource userResource = realmResource.users().get(userId);

            List<RoleRepresentation> currentRoles = userResource.roles().realmLevel().listAll();

            if (!currentRoles.isEmpty()) {
                // Filter for roles that match known RoleEnum values OR are RoleGroup composites (RG_*)
                Set<String> knownRoleNames = Arrays.stream(RoleEnum.values())
                        .map(RoleEnum::getKeycloakRoleName)
                        .collect(Collectors.toSet());

                List<RoleRepresentation> managedRoles = currentRoles.stream()
                        .filter(role -> knownRoleNames.contains(role.getName())
                                || role.getName().startsWith("RG_"))
                        .collect(Collectors.toList());

                if (!managedRoles.isEmpty()) {
                    userResource.roles().realmLevel().remove(managedRoles);
                    log.debug("Removed {} managed roles from user {}", managedRoles.size(), userId);
                }
            }

        } catch (Exception e) {
            log.error("Error removing roles from user {}", userId, e);
            throw new KeycloakMigrationException(
                    "Failed to remove roles from user: %s".formatted(userId), e
            );
        }
    }

    private void setUserPassword(UsersResource usersResource, String userId,
                                 String password, boolean temporary) {
        try {
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(password);
            credential.setTemporary(temporary);

            usersResource.get(userId).resetPassword(credential);
            log.debug("Password set for user {} (temporary: {})", userId, temporary);

        } catch (Exception e) {
            log.error("Error setting password for user {}", userId, e);
            throw new KeycloakMigrationException(
                    "Failed to set password for user: %s".formatted(userId), e
            );
        }
    }

    private void sendPasswordResetEmail(UsersResource usersResource, String userId) {
        try {
            usersResource.get(userId).executeActionsEmail(
                    List.of("UPDATE_PASSWORD")
            );
            log.info("Password reset email sent for user: {}", userId);

        } catch (Exception e) {
            log.error("Failed to send password reset email for user: {}", userId, e);
        }
    }

    private String generateTemporaryPassword() {
        return UUID.randomUUID().toString();
    }

    private String extractUserIdFromResponse(Response response) {
        String location = response.getHeaderString("Location");
        if (location == null || location.isBlank()) {
            throw new KeycloakMigrationException(
                    "No Location header in create user response"
            );
        }

        String userId = location.substring(location.lastIndexOf('/') + 1);

        if (userId.isBlank()) {
            throw new KeycloakMigrationException(
                    "Could not extract user ID from Location header: %s".formatted(location)
            );
        }

        return userId;
    }

    private String extractErrorBody(Response response) {
        try {
            return response.readEntity(String.class);
        } catch (Exception e) {
            return "Could not read error body";
        }
    }

    private void updateUserKeycloakId(UserEntity user, UsersResource usersResource) {
        try {
            log.info("User {} already exists in Keycloak, updating keycloakId and attributes", user.getLogin());
            List<UserRepresentation> users = usersResource.search(user.getLogin(), true);
            if (!users.isEmpty()) {
                String keycloakId = users.getFirst().getId();
                user.setKeycloakId(keycloakId);
                user.setMigratedAt(LocalDateTime.now());
                userRepository.save(user);

                // Also update user attributes in Keycloak to ensure role_ids etc. are set
                Set<RoleEnum> roleEnums = user.getRoleEnums();
                log.info("Updating attributes for existing user {}, roleEnums: {}", user.getLogin(), roleEnums);
                if (roleEnums != null && !roleEnums.isEmpty()) {
                    updateUserRoleIdsAttribute(keycloakId, roleEnums);
                } else {
                    log.warn("No roleEnums found for user {}, skipping attribute update", user.getLogin());
                }

                log.info("Updated Keycloak ID for existing user {}: {}",
                        user.getLogin(), keycloakId);
            }
        } catch (Exception e) {
            log.error("Error updating Keycloak ID for user {}", user.getLogin(), e);
        }
    }

    // ===================================================================
    // Public API - Protocol Mapper Setup
    // ===================================================================

    /**
     * Creates a protocol mapper to include role_ids in the JWT token.
     * This mapper extracts role_id attributes from assigned roles and adds them to the token.
     */
    public void ensureRoleIdsProtocolMapper() {
        log.info("Ensuring role_ids protocol mapper exists...");

        try {
            Keycloak keycloak = keycloakAdminClient.getInstance();
            RealmResource realmResource = keycloak.realm(getRealm());

            // Find "roles" client scope (default scope that handles realm roles)
            ClientScopeRepresentation rolesScope = realmResource.clientScopes().findAll().stream()
                    .filter(cs -> "roles".equals(cs.getName()))
                    .findFirst()
                    .orElse(null);

            if (rolesScope == null) {
                log.warn("'roles' client scope not found, creating custom scope for role_ids");
                createRoleIdsClientScope(realmResource);
                return;
            }

            // Check if mapper already exists
            ClientScopeResource scopeResource = realmResource.clientScopes().get(rolesScope.getId());
            boolean mapperExists = scopeResource.getProtocolMappers().getMappers().stream()
                    .anyMatch(m -> "role_ids".equals(m.getName()));

            if (!mapperExists) {
                createRoleIdsMapper(scopeResource);
            } else {
                log.debug("role_ids protocol mapper already exists");
            }

        } catch (Exception e) {
            log.error("Error ensuring role_ids protocol mapper: {}", e.getMessage());
            throw new KeycloakMigrationException("Failed to ensure role_ids mapper", e);
        }
    }

    private void createRoleIdsClientScope(RealmResource realmResource) {
        // Create a new client scope for role_ids
        ClientScopeRepresentation scope = new ClientScopeRepresentation();
        scope.setName("role_ids");
        scope.setDescription("Provides role IDs in JWT token");
        scope.setProtocol("openid-connect");

        Response response = realmResource.clientScopes().create(scope);
        if (response.getStatus() != 201) {
            log.error("Failed to create role_ids client scope: {}", response.getStatus());
            return;
        }

        String scopeId = extractIdFromResponse(response);
        ClientScopeResource scopeResource = realmResource.clientScopes().get(scopeId);
        createRoleIdsMapper(scopeResource);

        // Add as default scope
        realmResource.addDefaultDefaultClientScope(scopeId);
        log.info("Created and added 'role_ids' client scope as default");
    }

    private void createRoleIdsMapper(ClientScopeResource scopeResource) {
        // Create a script mapper to extract role_ids from role attributes
        // Note: Script mappers require 'scripts' feature enabled in Keycloak
        // Alternative: Use hardcoded mapper or user attribute mapper

        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName("role_ids");
        mapper.setProtocol("openid-connect");
        mapper.setProtocolMapper("oidc-usermodel-attribute-mapper");

        Map<String, String> config = new HashMap<>();
        config.put("claim.name", "role_ids");
        config.put("user.attribute", "role_ids");
        config.put("jsonType.label", "String");
        config.put("id.token.claim", "true");
        config.put("access.token.claim", "true");
        config.put("userinfo.token.claim", "true");
        config.put("multivalued", "true");
        mapper.setConfig(config);

        scopeResource.getProtocolMappers().createMapper(mapper);
        log.info("Created role_ids protocol mapper");
    }

    private String extractIdFromResponse(Response response) {
        String location = response.getHeaderString("Location");
        return location.substring(location.lastIndexOf('/') + 1);
    }

    /**
     * Updates user attributes with their role_ids for JWT inclusion.
     * Call this after assigning roles to a user.
     */
    public void updateUserRoleIdsAttribute(String keycloakUserId, Set<RoleEnum> roles) {
        log.info("updateUserRoleIdsAttribute called with keycloakUserId={}, roles={}", keycloakUserId, roles);
        if (keycloakUserId == null || roles == null || roles.isEmpty()) {
            log.warn("Skipping role_ids update: keycloakUserId={}, roles={}", keycloakUserId, roles);
            return;
        }

        try {
            Keycloak keycloak = keycloakAdminClient.getInstance();
            UserResource userResource = keycloak.realm(getRealm()).users().get(keycloakUserId);

            // Get current user to preserve existing fields
            UserRepresentation currentUser = userResource.toRepresentation();

            List<String> roleIds = roles.stream()
                    .map(r -> String.valueOf(r.getRoleId()))
                    .sorted()
                    .collect(Collectors.toList());

            // Build attributes map
            Map<String, List<String>> attributes = new HashMap<>();
            if (currentUser.getAttributes() != null) {
                attributes.putAll(currentUser.getAttributes());
            }
            attributes.put("role_ids", roleIds);

            // Create a new UserRepresentation for update with all required fields
            UserRepresentation updateUser = new UserRepresentation();
            updateUser.setId(keycloakUserId);
            updateUser.setUsername(currentUser.getUsername());
            updateUser.setEmail(currentUser.getEmail());
            updateUser.setFirstName(currentUser.getFirstName());
            updateUser.setLastName(currentUser.getLastName());
            updateUser.setEnabled(currentUser.isEnabled());
            updateUser.setEmailVerified(currentUser.isEmailVerified());
            updateUser.setAttributes(attributes);

            userResource.update(updateUser);
            log.info("Updated role_ids attribute for user {}: {}", keycloakUserId, roleIds);

            // Verify the update worked by reading back
            UserRepresentation verifyUser = userResource.toRepresentation();
            log.info("Verification - user attributes after update: {}", verifyUser.getAttributes());

        } catch (Exception e) {
            log.error("Error updating role_ids attribute for user {}: {}", keycloakUserId, e.getMessage(), e);
            throw new KeycloakMigrationException("Failed to update role_ids for user: " + keycloakUserId, e);
        }
    }
}
