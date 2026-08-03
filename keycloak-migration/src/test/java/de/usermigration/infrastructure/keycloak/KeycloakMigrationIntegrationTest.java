package de.usermigration.infrastructure.keycloak;

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;

import de.usermigration.IntegrationTest;
import de.usermigration.RequiresDocker;
import de.usermigration.domain.model.enums.RoleEnum;
import de.usermigration.domain.model.entity.RoleEntity;
import de.usermigration.domain.model.entity.RoleGroupEntity;
import de.usermigration.domain.model.entity.UserEntity;
import de.usermigration.domain.model.enums.SystemOrigin;
import de.usermigration.infrastructure.persistence.repositories.UserRepository;
import de.usermigration.infrastructure.rest.LegacyLoginResponseWrapper;
import de.usermigration.infrastructure.rest.LoginRequest;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.userprofile.config.UPConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@IntegrationTest
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("Keycloak Migration Integration Tests")
@RequiresDocker
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@Slf4j
class KeycloakMigrationIntegrationTest {

    // Inline (in-process, no Docker) PostgreSQL instance - replaces the former Testcontainers PostgreSQLContainer
    static EmbeddedPostgres embeddedPostgres;

    static {
        try {
            embeddedPostgres = EmbeddedPostgres.start();
        } catch (IOException e) {
            throw new RuntimeException("Failed to start embedded PostgreSQL", e);
        }
    }

    private static final String TEST_USERNAME = "test.migration.user";
    private static final String TEST_PASSWORD = "SecurePassword123!";
    private static final String TEST_EMAIL = "test.migration@example.com";
    private static final String TEST_REALM = "integration-test";

    @Container
    static KeycloakContainer keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:26.0.7")
            .withAdminUsername("admin")
            .withAdminPassword("admin");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private KeycloakMigrationService migrationService;

    @Autowired
    private LegacyJwtService legacyJwtService;

    @Autowired
    private org.springframework.transaction.PlatformTransactionManager transactionManager;

    private static boolean keycloakSetupDone = false;

    @DynamicPropertySource
    static void configureKeycloak(DynamicPropertyRegistry registry) {
        // PostgreSQL configuration (inline/embedded instance, no Docker)
        registry.add("spring.datasource.url", () -> embeddedPostgres.getJdbcUrl("postgres", "postgres"));
        registry.add("spring.datasource.username", () -> "postgres");
        registry.add("spring.datasource.password", () -> "postgres");
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.liquibase.enabled", () -> "false");

        // Keycloak configuration
        registry.add("keycloak.server-url", keycloak::getAuthServerUrl);
        registry.add("keycloak.realm", () -> TEST_REALM);
        registry.add("keycloak.admin.username", () -> "admin");
        registry.add("keycloak.admin.password", () -> "admin");
        registry.add("keycloak.admin.client-id", () -> "admin-cli");
        // Resource server config (needed for security configuration)
        registry.add("keycloak.resource-server.client-id", () -> "test-api");
        registry.add("keycloak.resource-server.client-secret", () -> "test-client-secret");
        // Migration config - use correct property name 'migrate-users' not 'enabled'
        registry.add("keycloak.migration.migrate-users", () -> true);
        registry.add("keycloak.migration.dry-run", () -> false);
        registry.add("keycloak.jwk-set-uri", () -> keycloak.getAuthServerUrl() + "/realms/" + TEST_REALM + "/protocol/openid-connect/certs");
        registry.add("jwt.secret", () -> "this-is-a-test-secret-key-that-must-be-at-least-256-bits-long-for-hmac-sha256-algorithm");
    }

    @BeforeAll
    static void setupKeycloak() {
        if (keycloakSetupDone) {
            return;
        }

        try (Keycloak keycloakAdmin = KeycloakBuilder.builder()
                .serverUrl(keycloak.getAuthServerUrl())
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build()) {

            // Create test realm
            if (keycloakAdmin.realms().findAll().stream().noneMatch(r -> r.getRealm().equals(TEST_REALM))) {
                RealmRepresentation realm = new RealmRepresentation();
                realm.setRealm(TEST_REALM);
                realm.setEnabled(true);
                realm.setDisplayName("Integration Test Realm");
                realm.setSslRequired("none");
                realm.setRegistrationAllowed(false);
                realm.setLoginWithEmailAllowed(true);
                realm.setResetPasswordAllowed(true);
                realm.setAccessTokenLifespan(3600);
                realm.setAccessTokenLifespanForImplicitFlow(900);
                realm.setSsoSessionIdleTimeout(1800);
                realm.setSsoSessionMaxLifespan(36000);

                keycloakAdmin.realms().create(realm);

                // Configure User Profile to allow unmanaged attributes (required for Keycloak 24+)
                // This must be done AFTER realm creation
                try {
                    UPConfig upConfig = keycloakAdmin.realm(TEST_REALM).users().userProfile().getConfiguration();
                    upConfig.setUnmanagedAttributePolicy(UPConfig.UnmanagedAttributePolicy.ENABLED);
                    keycloakAdmin.realm(TEST_REALM).users().userProfile().update(upConfig);
                    log.info("User Profile configured to allow unmanaged attributes");
                } catch (Exception e) {
	                log.info("Warning: Could not configure User Profile: {}", e.getMessage());
                }
            }

            // Create roles with role_id attribute
            createRole(keycloakAdmin, "SYSTEM_ADMIN", "System Administrator", "100", "1002");
            createRole(keycloakAdmin, "PERSONNEL", "Personalverwaltung", "60", "1006");
            createRole(keycloakAdmin, "FU_FACILITY_WORKPLAN", "Einrichtungs-Arbeitsplan", "40", "1010");

            // Create client
            ClientRepresentation client = new ClientRepresentation();
            client.setClientId("test-api");
            client.setName("Test API");
            client.setEnabled(true);
            client.setClientAuthenticatorType("client-secret");
            client.setSecret("test-client-secret");
            client.setRedirectUris(List.of("*"));
            client.setWebOrigins(List.of("*"));
            client.setPublicClient(false);
            client.setDirectAccessGrantsEnabled(true);
            client.setServiceAccountsEnabled(true);
            client.setStandardFlowEnabled(true);
            client.setProtocol("openid-connect");
            client.setFullScopeAllowed(true);

            Response clientResponse = keycloakAdmin.realm(TEST_REALM).clients().create(client);
            clientResponse.close();

            // Create test admin user
            UserRepresentation testAdmin = new UserRepresentation();
            testAdmin.setUsername("test-admin");
            testAdmin.setEmail("test-admin@example.com");
            testAdmin.setFirstName("Test");
            testAdmin.setLastName("Admin");
            testAdmin.setEnabled(true);
            testAdmin.setEmailVerified(true);

            Response userResponse = keycloakAdmin.realm(TEST_REALM).users().create(testAdmin);
            String userId = getCreatedId(userResponse);
            userResponse.close();

            // Set password
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue("admin123");
            credential.setTemporary(false);
            keycloakAdmin.realm(TEST_REALM).users().get(userId).resetPassword(credential);

            // Assign roles
            List<RoleRepresentation> rolesToAssign = List.of(
                    keycloakAdmin.realm(TEST_REALM).roles().get("SYSTEM_ADMIN").toRepresentation(),
                    keycloakAdmin.realm(TEST_REALM).roles().get("PERSONNEL").toRepresentation(),
                    keycloakAdmin.realm(TEST_REALM).roles().get("FU_FACILITY_WORKPLAN").toRepresentation()
            );
            keycloakAdmin.realm(TEST_REALM).users().get(userId).roles().realmLevel().add(rolesToAssign);

            keycloakSetupDone = true;
            log.info("Keycloak test realm setup completed successfully");

        } catch (Exception e) {
            throw new RuntimeException("Failed to setup Keycloak", e);
        }
    }

    @AfterAll
    static void cleanup() {
        // Force cleanup of any Keycloak admin clients
        keycloakSetupDone = false;
        try {
            embeddedPostgres.close();
        } catch (IOException e) {
            log.warn("Failed to close embedded PostgreSQL", e);
        }
        log.info("Keycloak Migration Integration Test cleanup completed");
    }

    private static void createRole(Keycloak keycloakAdmin, String name, String displayName,
                                     String hierarchyLevel, String roleId) {
        RoleRepresentation role = new RoleRepresentation();
        role.setName(name);
        role.setDescription(displayName);
        role.setAttributes(Map.of(
                "role_id", List.of(roleId),
                "display_name", List.of(displayName),
                "hierarchy_level", List.of(hierarchyLevel)
        ));
        keycloakAdmin.realm(TEST_REALM).roles().create(role);
    }

    private static String getCreatedId(Response response) {
        String location = response.getLocation().getPath();
        return location.substring(location.lastIndexOf('/') + 1);
    }

    @BeforeEach
    void setUp() {
        // Clean up all test data in a transaction
        new org.springframework.transaction.support.TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> {
                    // Delete user (this also removes user-rolegroup associations)
                    userRepository.findByLogin(TEST_USERNAME).ifPresent(user -> {
                        userRepository.delete(user);
                    });
                    userRepository.flush();

                    // Use native SQL to clean up join tables and entities
                    // Order matters due to foreign key constraints

                    // 1. Clear rolegroup-role join table for test rolegroups
                    entityManager.createNativeQuery(
                            "DELETE FROM test_role_group_x_role WHERE rolegroup_id IN " +
                            "(SELECT id FROM test_role_group WHERE designation IN ('Admin Group', 'Viewer Group', 'Test Role Group'))")
                            .executeUpdate();

                    // 2. Delete test role groups
                    entityManager.createNativeQuery(
                            "DELETE FROM test_role_group WHERE designation IN ('Admin Group', 'Viewer Group', 'Test Role Group')")
                            .executeUpdate();

                    // 3. Delete test roles (only if not referenced elsewhere)
                    entityManager.createNativeQuery(
                            "DELETE FROM test_role WHERE roletype IN ('SYSTEM_ADMIN', 'PERSONNEL', 'FU_FACILITY_WORKPLAN') " +
                            "AND id NOT IN (SELECT role_id FROM test_role_group_x_role)")
                            .executeUpdate();

                    entityManager.flush();
                    entityManager.clear();
                });

        // Clean up Keycloak user before each test
        cleanupKeycloakUser(TEST_USERNAME);
    }

    private void cleanupKeycloakUser(String username) {
        try (Keycloak keycloakAdmin = KeycloakBuilder.builder()
                .serverUrl(keycloak.getAuthServerUrl())
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build()) {

            List<UserRepresentation> users = keycloakAdmin.realm(TEST_REALM)
                    .users()
                    .search(username, true);

            for (UserRepresentation user : users) {
                keycloakAdmin.realm(TEST_REALM).users().get(user.getId()).remove();
            }
        } catch (Exception e) {
            // Ignore cleanup errors
        }
    }

    // ===================================================================
    // Test: Kompletter Migration Flow
    // ===================================================================

    @Test
    @Order(1)
    @DisplayName("Login: Nicht-migrierter User wird automatisch zu Keycloak migriert")
    void loginWithAutomaticMigration() throws Exception {
        // GIVEN: User in DB ohne Keycloak-ID - created in separate committed transaction
        new org.springframework.transaction.support.TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> createTestUserInTransaction());

        // Verify user was actually created and has the expected password
        UserEntity createdUser = userRepository.findByLogin(TEST_USERNAME)
                .orElseThrow(() -> new AssertionError("User was not created in database!"));
        assertThat(createdUser.getPasswd()).as("Password should be set").isNotNull();
        assertThat(createdUser.isActive()).as("User should be active").isTrue();
	    log.debug("User created with password hash: {}", createdUser.getPasswd());
	    log.debug("User active: {}", createdUser.isActive());

        // WHEN: Login Request
        LoginRequest loginRequest = LoginRequest.builder()
                .username(TEST_USERNAME)
                .password(TEST_PASSWORD)
                .build();

        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andDo(mvcResult -> {
                    // Print error body if not 200
                    if (mvcResult.getResponse().getStatus() != 200) {
	                    log.debug("Login failed with status {}", mvcResult.getResponse().getStatus());
	                    log.debug("Response body: {}", mvcResult.getResponse().getContentAsString());
                    }
                })
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].lastUsed").exists())
                .andExpect(jsonPath("$[0].authXBVO.token").isNotEmpty())
                .andExpect(jsonPath("$[0].authXBVO.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$[0].authXBVO.login").value(TEST_USERNAME))
                .andExpect(jsonPath("$[0].authXBVO.firstName").value("Test"))
                .andExpect(jsonPath("$[0].authXBVO.lastName").value("User"))
                .andExpect(jsonPath("$[0].authXBVO.roles").isArray())
                .andReturn();

        // Parse response
        String responseString = result.getResponse().getContentAsString();
        List<LegacyLoginResponseWrapper> responseList = objectMapper.readValue(
                responseString,
                objectMapper.getTypeFactory().constructCollectionType(List.class, LegacyLoginResponseWrapper.class)
        );

        assertThat(responseList).hasSize(1);
        LegacyLoginResponseWrapper response = responseList.get(0);

        assertThat(response.getAuthXBVO().getToken()).isNotBlank();
        assertThat(response.getAuthXBVO().getRefreshToken()).isNotBlank();
        assertThat(response.getAuthXBVO().getLogin()).isEqualTo(TEST_USERNAME);

        // THEN: User in DB has Keycloak-ID
        UserEntity migratedUser = userRepository.findByLogin(TEST_USERNAME).orElseThrow();
        assertThat(migratedUser.getKeycloakId()).isNotNull();

        // AND: User exists in Keycloak
        assertThat(migrationService.existsInKeycloak(TEST_USERNAME)).isTrue();

        // AND: Roles are correct (Legacy format uses numeric IDs from RoleEnum.roleId)
        // SYSTEM_ADMIN -> 1002
        // PERSONNEL -> 1006
        assertThat(response.getAuthXBVO().getRoles()).containsExactlyInAnyOrder("1002", "1006");
    }

    @Test
    @Order(2)
    @DisplayName("Login: Bereits migrierter User kann sich normal einloggen")
    void loginAlreadyMigratedUser() throws Exception {
        // GIVEN: User bereits migriert (hat Keycloak-ID) - created in separate committed transaction
        String fakeKcId = "already-migrated-id";
        new org.springframework.transaction.support.TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> {
                    createTestUserInTransaction();
                    UserEntity user = userRepository.findByLogin(TEST_USERNAME).orElseThrow();
                    user.setKeycloakId(fakeKcId);
                    userRepository.saveAndFlush(user);
                });

        // WHEN: Login Request
        LoginRequest loginRequest = LoginRequest.builder()
                .username(TEST_USERNAME)
                .password(TEST_PASSWORD)
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].authXBVO.login").value(TEST_USERNAME));

        // THEN: Keycloak-ID bleibt gleich
        UserEntity updatedUser = userRepository.findByLogin(TEST_USERNAME).orElseThrow();
        assertThat(updatedUser.getKeycloakId()).isEqualTo(fakeKcId);
    }

    // ===================================================================
    // Tests: Roles and Composite Roles created from DB
    // ===================================================================

    @Test
    @Order(3)
    @DisplayName("Migration creates individual roles in Keycloak based on RoleEnum")
    void migrationCreatesRolesFromRoleEnum() throws Exception {
        // GIVEN: User with roles from DB - created in separate committed transaction
        new org.springframework.transaction.support.TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> createTestUserInTransaction());

        // WHEN: User logs in (triggers migration)
        LoginRequest loginRequest = LoginRequest.builder()
                .username(TEST_USERNAME)
                .password(TEST_PASSWORD)
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk());

        // THEN: Verify individual roles exist in Keycloak
        try (Keycloak keycloakAdmin = KeycloakBuilder.builder()
                .serverUrl(keycloak.getAuthServerUrl())
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build()) {

            RolesResource rolesResource = keycloakAdmin.realm(TEST_REALM).roles();

            // Check SYSTEM_ADMIN role exists
            RoleRepresentation systemAdminRole = rolesResource.get("SYSTEM_ADMIN").toRepresentation();
            assertThat(systemAdminRole).isNotNull();
            assertThat(systemAdminRole.getName()).isEqualTo("SYSTEM_ADMIN");

            // Check PERSONNEL role exists
            RoleRepresentation personnelRole = rolesResource.get("PERSONNEL").toRepresentation();
            assertThat(personnelRole).isNotNull();
            assertThat(personnelRole.getName()).isEqualTo("PERSONNEL");
        }
    }

    @Test
    @Order(4)
    @DisplayName("Migration creates composite role for RoleGroup with correct member roles")
    void migrationCreatesCompositeRoleForRoleGroup() throws Exception {
        // GIVEN: User with RoleGroup containing multiple roles - created in separate committed transaction
        new org.springframework.transaction.support.TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> createTestUserInTransaction());

        // WHEN: User logs in (triggers migration)
        LoginRequest loginRequest = LoginRequest.builder()
                .username(TEST_USERNAME)
                .password(TEST_PASSWORD)
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk());

        // THEN: Verify composite role exists with correct member roles
        try (Keycloak keycloakAdmin = KeycloakBuilder.builder()
                .serverUrl(keycloak.getAuthServerUrl())
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build()) {

            RolesResource rolesResource = keycloakAdmin.realm(TEST_REALM).roles();

            // Composite role should be named RG_ADMIN_GROUP
            RoleRepresentation compositeRole = rolesResource.get("RG_ADMIN_GROUP").toRepresentation();
            assertThat(compositeRole).isNotNull();
            assertThat(compositeRole.getName()).isEqualTo("RG_ADMIN_GROUP");
            assertThat(compositeRole.isComposite()).isTrue();
            assertThat(compositeRole.getDescription()).contains("Admin Group");

            // Verify composite contains the member roles
            Set<RoleRepresentation> composites = rolesResource.get("RG_ADMIN_GROUP").getRoleComposites();
            Set<String> compositeNames = composites.stream()
                    .map(RoleRepresentation::getName)
                    .collect(Collectors.toSet());

            assertThat(compositeNames).containsExactlyInAnyOrder("SYSTEM_ADMIN", "PERSONNEL");
        }
    }

    @Test
    @Order(5)
    @DisplayName("Migrated user is assigned composite role (not individual roles)")
    void migratedUserHasCompositeRoleAssigned() throws Exception {
        // GIVEN: User with RoleGroup - created in separate committed transaction
        new org.springframework.transaction.support.TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> createTestUserInTransaction());

        // WHEN: User logs in (triggers migration)
        LoginRequest loginRequest = LoginRequest.builder()
                .username(TEST_USERNAME)
                .password(TEST_PASSWORD)
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk());

        // Get migrated user's Keycloak ID
        UserEntity migratedUser = userRepository.findByLogin(TEST_USERNAME).orElseThrow();
        String keycloakUserId = migratedUser.getKeycloakId();
        assertThat(keycloakUserId).isNotNull();

        // THEN: Verify user has composite role assigned (directly)
        try (Keycloak keycloakAdmin = KeycloakBuilder.builder()
                .serverUrl(keycloak.getAuthServerUrl())
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build()) {

            UserResource userResource = keycloakAdmin.realm(TEST_REALM).users().get(keycloakUserId);

            // Get directly assigned roles (not effective/inherited)
            List<RoleRepresentation> assignedRoles = userResource.roles().realmLevel().listAll();
            Set<String> assignedRoleNames = assignedRoles.stream()
                    .map(RoleRepresentation::getName)
                    .collect(Collectors.toSet());

            // User should have composite role RG_ADMIN_GROUP assigned
            assertThat(assignedRoleNames).contains("RG_ADMIN_GROUP");

            // Get effective roles (includes inherited from composites)
            List<RoleRepresentation> effectiveRoles = userResource.roles().realmLevel().listEffective();
            Set<String> effectiveRoleNames = effectiveRoles.stream()
                    .map(RoleRepresentation::getName)
                    .collect(Collectors.toSet());

            // Effective roles should include inherited roles from composite
            assertThat(effectiveRoleNames).contains("RG_ADMIN_GROUP", "SYSTEM_ADMIN", "PERSONNEL");
        }
    }

    @Test
    @Order(6)
    @DisplayName("Multiple RoleGroups create multiple composite roles")
    void multipleRoleGroupsCreateMultipleCompositeRoles() throws Exception {
        // GIVEN: User with multiple RoleGroups - created in separate committed transaction
        new org.springframework.transaction.support.TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> createTestUserWithMultipleRoleGroupsInTransaction());

        // WHEN: User logs in (triggers migration)
        LoginRequest loginRequest = LoginRequest.builder()
                .username(TEST_USERNAME)
                .password(TEST_PASSWORD)
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk());

        // Get migrated user
        UserEntity migratedUser = userRepository.findByLogin(TEST_USERNAME).orElseThrow();
        String keycloakUserId = migratedUser.getKeycloakId();

        // THEN: Verify both composite roles exist and are assigned
        try (Keycloak keycloakAdmin = KeycloakBuilder.builder()
                .serverUrl(keycloak.getAuthServerUrl())
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build()) {

            RolesResource rolesResource = keycloakAdmin.realm(TEST_REALM).roles();

            // Both composite roles should exist
            RoleRepresentation adminComposite = rolesResource.get("RG_ADMIN_GROUP").toRepresentation();
            RoleRepresentation viewerComposite = rolesResource.get("RG_VIEWER_GROUP").toRepresentation();

            assertThat(adminComposite).isNotNull();
            assertThat(viewerComposite).isNotNull();
            assertThat(adminComposite.isComposite()).isTrue();
            assertThat(viewerComposite.isComposite()).isTrue();

            // User should have both composite roles assigned
            UserResource userResource = keycloakAdmin.realm(TEST_REALM).users().get(keycloakUserId);
            List<RoleRepresentation> assignedRoles = userResource.roles().realmLevel().listAll();
            Set<String> assignedRoleNames = assignedRoles.stream()
                    .map(RoleRepresentation::getName)
                    .collect(Collectors.toSet());

            assertThat(assignedRoleNames).contains("RG_ADMIN_GROUP", "RG_VIEWER_GROUP");
        }
    }

    @Test
    @Order(7)
    @DisplayName("Roles in Keycloak have role_id attribute")
    void rolesHaveRoleIdAttribute() throws Exception {
        // GIVEN: User with roles from DB - created in separate committed transaction
        new org.springframework.transaction.support.TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> createTestUserInTransaction());

        // WHEN: User logs in (triggers migration, which creates roles)
        LoginRequest loginRequest = LoginRequest.builder()
                .username(TEST_USERNAME)
                .password(TEST_PASSWORD)
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk());

        // THEN: Verify roles have role_id attribute
        try (Keycloak keycloakAdmin = KeycloakBuilder.builder()
                .serverUrl(keycloak.getAuthServerUrl())
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build()) {

            RolesResource rolesResource = keycloakAdmin.realm(TEST_REALM).roles();

            // SYSTEM_ADMIN should have role_id = 1002
            RoleRepresentation systemAdminRole = rolesResource.get("SYSTEM_ADMIN").toRepresentation();
            assertThat(systemAdminRole.getAttributes()).containsKey("role_id");
            assertThat(systemAdminRole.getAttributes().get("role_id")).contains("1002");

            // PERSONNEL should have role_id = 1006
            RoleRepresentation personnelRole = rolesResource.get("PERSONNEL").toRepresentation();
            assertThat(personnelRole.getAttributes()).containsKey("role_id");
            assertThat(personnelRole.getAttributes().get("role_id")).contains("1006");
        }
    }

    @Test
    @Order(8)
    @DisplayName("Migrated user has role_ids user attribute")
    void migratedUserHasRoleIdsAttribute() throws Exception {
        // GIVEN: User with roles - created in separate committed transaction
        // to avoid version conflicts with REQUIRES_NEW migration transaction
        new org.springframework.transaction.support.TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> {
                    createTestUserInTransaction();
                });

        // WHEN: User logs in (triggers migration)
        LoginRequest loginRequest = LoginRequest.builder()
                .username(TEST_USERNAME)
                .password(TEST_PASSWORD)
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk());

        // Get migrated user's Keycloak ID
        UserEntity migratedUser = userRepository.findByLogin(TEST_USERNAME).orElseThrow();
        String keycloakUserId = migratedUser.getKeycloakId();
        assertThat(keycloakUserId).as("User should have been migrated with keycloakId").isNotNull();

        // THEN: Verify user has role_ids attribute in Keycloak
        try (Keycloak keycloakAdmin = KeycloakBuilder.builder()
                .serverUrl(keycloak.getAuthServerUrl())
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build()) {

            UserResource userResource = keycloakAdmin.realm(TEST_REALM).users().get(keycloakUserId);
            UserRepresentation userRep = userResource.toRepresentation();

            // Debug output
	        log.debug("Keycloak user ID: {}", keycloakUserId);
	        log.debug("Username: {}", userRep.getUsername());
	        log.debug("Attributes: {}", userRep.getAttributes());

            // Check if user was found by searching (alternative approach)
            List<UserRepresentation> searchResults = keycloakAdmin.realm(TEST_REALM)
                    .users().search(TEST_USERNAME, true);
	        log.debug("Search found {} users", searchResults.size());
            if (!searchResults.isEmpty()) {
	            log.debug("Search result attributes: {}", searchResults.get(0).getAttributes());
            }

            assertThat(userRep.getAttributes())
                    .as("User should have attributes set")
                    .isNotNull()
                    .containsKey("role_ids");
            List<String> roleIds = userRep.getAttributes().get("role_ids");

            // Should contain role_ids for SYSTEM_ADMIN (1002) and PERSONNEL (1006)
            assertThat(roleIds).containsExactlyInAnyOrder("1002", "1006");
        }
    }

    @Test
    @Order(9)
    @DisplayName("Keycloak token contains role_ids claim")
    void keycloakTokenContainsRoleIdsClaim() throws Exception {
        // GIVEN: User migrated to Keycloak
        new org.springframework.transaction.support.TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> createTestUserInTransaction());

        // Migrate user via login
        LoginRequest loginRequest = LoginRequest.builder()
                .username(TEST_USERNAME)
                .password(TEST_PASSWORD)
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk());

        // Ensure protocol mapper is installed
        migrationService.ensureRoleIdsProtocolMapper();

        // Verify protocol mapper was actually created in Keycloak
        try (Keycloak keycloakAdmin = KeycloakBuilder.builder()
                .serverUrl(keycloak.getAuthServerUrl())
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build()) {

            // Check if mapper exists in "roles" scope or custom "role_ids" scope
            var clientScopes = keycloakAdmin.realm(TEST_REALM).clientScopes().findAll();
            boolean mapperFound = clientScopes.stream()
                    .filter(cs -> "roles".equals(cs.getName()) || "role_ids".equals(cs.getName()))
                    .flatMap(cs -> keycloakAdmin.realm(TEST_REALM).clientScopes()
                            .get(cs.getId()).getProtocolMappers().getMappers().stream())
                    .anyMatch(m -> "role_ids".equals(m.getName()));

	        log.debug("Protocol mapper 'role_ids' found in Keycloak: {}", mapperFound);
            assertThat(mapperFound).as("Protocol mapper 'role_ids' should be created in Keycloak").isTrue();
        }

        // WHEN: Get Keycloak token via password grant
        String tokenEndpoint = keycloak.getAuthServerUrl() + "/realms/" + TEST_REALM + "/protocol/openid-connect/token";

        String tokenResponse = org.springframework.web.client.RestClient.create()
                .post()
                .uri(tokenEndpoint)
                .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                .body("grant_type=password&client_id=test-api&client_secret=test-client-secret&username="
                        + TEST_USERNAME + "&password=" + TEST_PASSWORD)
                .retrieve()
                .body(String.class);

        // Parse token response
        Map<String, Object> tokenMap = objectMapper.readValue(tokenResponse,
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
        String accessToken = (String) tokenMap.get("access_token");
        assertThat(accessToken).as("Should receive access token from Keycloak").isNotNull();

        // THEN: Decode JWT and verify role_ids claim
        String[] jwtParts = accessToken.split("\\.");
        assertThat(jwtParts).as("JWT should have 3 parts").hasSize(3);

        String payloadJson = new String(java.util.Base64.getUrlDecoder().decode(jwtParts[1]));
        Map<String, Object> payload = objectMapper.readValue(payloadJson,
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});

        // Log role-related parts of the token
        log.debug("=".repeat(60));
        log.debug("KEYCLOAK TOKEN - ROLE INFORMATION");
        log.debug("=".repeat(60));
	    log.debug("role_ids claim: {}", payload.get("role_ids"));
	    log.debug("realm_access: {}", payload.get("realm_access"));
	    log.debug("Full token payload: {}", payloadJson);
        log.debug("=".repeat(60));

        // Verify role_ids claim exists and contains expected values
        assertThat(payload).as("Token payload should contain role_ids claim").containsKey("role_ids");

        @SuppressWarnings("unchecked")
        List<String> roleIdsInToken = (List<String>) payload.get("role_ids");
	    log.debug("role_ids in token: {}", roleIdsInToken);
        assertThat(roleIdsInToken)
                .as("role_ids claim should contain SYSTEM_ADMIN (1002) and PERSONNEL (1006)")
                .containsExactlyInAnyOrder("1002", "1006");

        // Also verify realm_access.roles contains the role names
        @SuppressWarnings("unchecked")
        Map<String, Object> realmAccess = (Map<String, Object>) payload.get("realm_access");
        assertThat(realmAccess).as("Token should have realm_access").isNotNull();

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) realmAccess.get("roles");
	    log.debug("realm_access.roles in token: {}", roles);
        assertThat(roles).as("realm_access.roles should contain role names")
                .contains("RG_ADMIN_GROUP", "SYSTEM_ADMIN", "PERSONNEL");
    }

    @Test
    @Order(15)
    @DisplayName("Genuine Keycloak bearer token reaches role-gated endpoints (phase 2 resource-server path)")
    void keycloakBearerTokenReachesRoleGatedEndpoints() throws Exception {
        // GIVEN: user migrated to Keycloak with a role group containing SYSTEM_ADMIN + PERSONNEL
        new org.springframework.transaction.support.TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> createTestUserInTransaction());

        LoginRequest loginRequest = LoginRequest.builder()
                .username(TEST_USERNAME)
                .password(TEST_PASSWORD)
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk());

        // WHEN: get a genuine Keycloak token via password grant - this is what phase2_oauth_client.http
        // does manually to stand in for "user just completed Keycloak's hosted login form"
        String tokenEndpoint = keycloak.getAuthServerUrl() + "/realms/" + TEST_REALM + "/protocol/openid-connect/token";

        String tokenResponse = org.springframework.web.client.RestClient.create()
                .post()
                .uri(tokenEndpoint)
                .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                .body("grant_type=password&client_id=test-api&client_secret=test-client-secret&username="
                        + TEST_USERNAME + "&password=" + TEST_PASSWORD)
                .retrieve()
                .body(String.class);

        Map<String, Object> tokenMap = objectMapper.readValue(tokenResponse,
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
        String accessToken = (String) tokenMap.get("access_token");
        assertThat(accessToken).as("Should receive access token from Keycloak").isNotNull();

        // THEN: unlike keycloakTokenContainsRoleIdsClaim (which only decodes the token's claims),
        // this actually sends it through the resource-server bearer path (SecurityConfig's
        // Keycloak JWKS decoder + KeycloakAuthorityMapper) to role-gated endpoints.
        mockMvc.perform(get("/admin/whoami").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").value(org.hamcrest.Matchers.hasItem("ROLE_SYSTEM_ADMIN")));

        mockMvc.perform(get("/personnel/whoami").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").value(org.hamcrest.Matchers.hasItem("ROLE_PERSONNEL")));
    }

    // ===================================================================
    // Tests: Token Handling (401 responses, legacy tokens)
    // ===================================================================

    @Test
    @Order(10)
    @DisplayName("Expired/invalid token returns 401")
    void expiredTokenReturns401() throws Exception {
        mockMvc.perform(get("/facilities")
                        .header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(11)
    @DisplayName("Missing token returns 401")
    void noTokenReturns401() throws Exception {
        mockMvc.perform(get("/facilities"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(12)
    @DisplayName("Refresh token returns new legacy token")
    @Transactional
    void refreshTokenReturnsLegacyToken() throws Exception {
        UserEntity user = createTestUserWithRoles();
        String refreshToken = legacyJwtService.generateRefreshToken(user);

        mockMvc.perform(post("/auth/refresh")
                        .header("Authorization", "Bearer " + refreshToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].authXBVO.token").isNotEmpty());
    }

    @Test
    @Order(13)
    @DisplayName("Valid legacy token is accepted")
    @Transactional
    void validLegacyTokenAccepted() throws Exception {
        UserEntity user = createTestUserWithRoles();
        user.setKeycloakId("test-kc-id"); // Mark as migrated to skip migration
        userRepository.saveAndFlush(user);

        String legacyToken = legacyJwtService.generateAccessToken(user);

        mockMvc.perform(get("/facilities")
                        .header("Authorization", "Bearer " + legacyToken))
                .andDo(print())
                .andExpect(result -> assertThat(result.getResponse().getStatus()).isNotEqualTo(401));
    }

    // ===================================================================
    // Helper Methods
    // ===================================================================

    /**
     * Creates test user with roles inside a transaction (no return value).
     * Use this with TransactionTemplate for tests that need committed data.
     */
    void createTestUserInTransaction() {
        // Role: SYSTEM_ADMIN
        RoleEntity adminRole = RoleEntity.builder()
                .roleEnumType(RoleEnum.SYSTEM_ADMIN)
                .roleOrigin(SystemOrigin.TEST)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();
        entityManager.persist(adminRole);

        // Role: PERSONNEL
        RoleEntity personnelRole = RoleEntity.builder()
                .roleEnumType(RoleEnum.PERSONNEL)
                .roleOrigin(SystemOrigin.TEST)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();
        entityManager.persist(personnelRole);

        // RoleGroup: Admin Group
        RoleGroupEntity adminGroup = RoleGroupEntity.builder()
                .designation("Admin Group")
                .description("Test Admin Role Group")
                .system(true)
                .userInternal(false)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();
        adminGroup.getRoles().add(adminRole);
        adminGroup.getRoles().add(personnelRole);
        entityManager.persist(adminGroup);

        // User
        UserEntity user = UserEntity.builder()
                .login(TEST_USERNAME)
                .email(TEST_EMAIL)
                .firstName("Test")
                .lastName("User")
                .passwd(passwordEncoder.encode(TEST_PASSWORD))
                .active(true)
                .build();
        user.getRoleGroups().add(adminGroup);
        entityManager.persist(user);

        entityManager.flush();
    }

    /**
     * Creates test user with multiple role groups inside a transaction (no return value).
     * Use this with TransactionTemplate for tests that need committed data.
     */
    void createTestUserWithMultipleRoleGroupsInTransaction() {
        // Role: SYSTEM_ADMIN
        RoleEntity adminRole = RoleEntity.builder()
                .roleEnumType(RoleEnum.SYSTEM_ADMIN)
                .roleOrigin(SystemOrigin.TEST)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();
        entityManager.persist(adminRole);

        // Role: PERSONNEL
        RoleEntity personnelRole = RoleEntity.builder()
                .roleEnumType(RoleEnum.PERSONNEL)
                .roleOrigin(SystemOrigin.TEST)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();
        entityManager.persist(personnelRole);

        // Role: FU_FACILITY_WORKPLAN (for second group)
        RoleEntity workplanRole = RoleEntity.builder()
                .roleEnumType(RoleEnum.FU_FACILITY_WORKPLAN)
                .roleOrigin(SystemOrigin.TEST)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();
        entityManager.persist(workplanRole);

        // RoleGroup 1: Admin Group
        RoleGroupEntity adminGroup = RoleGroupEntity.builder()
                .designation("Admin Group")
                .description("Test Admin Role Group")
                .system(true)
                .userInternal(false)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();
        adminGroup.getRoles().add(adminRole);
        adminGroup.getRoles().add(personnelRole);
        entityManager.persist(adminGroup);

        // RoleGroup 2: Viewer Group
        RoleGroupEntity viewerGroup = RoleGroupEntity.builder()
                .designation("Viewer Group")
                .description("Test Viewer Role Group")
                .system(false)
                .userInternal(false)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();
        viewerGroup.getRoles().add(workplanRole);
        entityManager.persist(viewerGroup);

        // User with multiple RoleGroups
        UserEntity user = UserEntity.builder()
                .login(TEST_USERNAME)
                .email(TEST_EMAIL)
                .firstName("Test")
                .lastName("User")
                .passwd(passwordEncoder.encode(TEST_PASSWORD))
                .active(true)
                .build();
        user.getRoleGroups().add(adminGroup);
        user.getRoleGroups().add(viewerGroup);
        entityManager.persist(user);

        entityManager.flush();
    }

    @Transactional
    UserEntity createTestUserWithRoles() {
        // Role: SYSTEM_ADMIN
        RoleEntity adminRole = RoleEntity.builder()
                .roleEnumType(RoleEnum.SYSTEM_ADMIN)
                .roleOrigin(SystemOrigin.TEST)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();
        entityManager.persist(adminRole);

        // Role: PERSONNEL
        RoleEntity personnelRole = RoleEntity.builder()
                .roleEnumType(RoleEnum.PERSONNEL)
                .roleOrigin(SystemOrigin.TEST)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();
        entityManager.persist(personnelRole);

        // RoleGroup: Admin Group
        RoleGroupEntity adminGroup = RoleGroupEntity.builder()
                .designation("Admin Group")
                .description("Test Admin Role Group")
                .system(true)
                .userInternal(false)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();
        adminGroup.getRoles().add(adminRole);
        adminGroup.getRoles().add(personnelRole);
        entityManager.persist(adminGroup);

        // User
        UserEntity user = UserEntity.builder()
                .login(TEST_USERNAME)
                .email(TEST_EMAIL)
                .firstName("Test")
                .lastName("User")
                .passwd(passwordEncoder.encode(TEST_PASSWORD))
                .active(true)
                .build();
        user.getRoleGroups().add(adminGroup);
        entityManager.persist(user);

        entityManager.flush();
        entityManager.clear();

        return userRepository.findByLoginWithRoles(TEST_USERNAME).orElseThrow();
    }
}
