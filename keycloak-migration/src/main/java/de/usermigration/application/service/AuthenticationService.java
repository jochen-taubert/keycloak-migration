package de.usermigration.application.service;


import de.usermigration.domain.model.enums.RoleEnum;
import de.usermigration.infrastructure.keycloak.service.KeycloakMigrationService;
import de.usermigration.infrastructure.keycloak.config.KeycloakProperties;
import de.usermigration.domain.model.entity.UserEntity;
import de.usermigration.infrastructure.keycloak.service.LegacyJwtService;
import de.usermigration.infrastructure.persistence.repositories.UserRepository;
import de.usermigration.infrastructure.rest.LoginResponse;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Set;

/**
 * Authentication Service
 * Hauptlogik für:
 * - User Authentication
 * - Automatische Keycloak Migration beim Login
 * - Token Generation (Legacy & Keycloak)
 * - Refresh Token Handling
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    @Autowired(required = false)
    private KeycloakMigrationService keycloakMigrationService;
    private final LegacyJwtService legacyJwtService;
    private final KeycloakProperties keycloakProperties;
    private final EntityManager entityManager;

    // ===================================================================
    // Authentication
    // ===================================================================

    /**
     * Authentifiziert User und migriert zu Keycloak falls nötig
     *
     * @param username User Login
     * @param password Klartext Password
     * @return LoginResponse mit Token und User-Info
     * @throws RuntimeException bei Authentication-Fehler
     */
    @Transactional
    public LoginResponse authenticate(String username, String password) {
        log.info("Authentication attempt for user: {}", username);

        // 1. User aus DB laden MIT Rollen (eager fetch!)
        UserEntity user = userRepository.findByLoginWithRoles(username)
                .orElseThrow(() -> {
                    log.warn("User not found: {}", username);
                    return new RuntimeException("Invalid credentials");
                });

        // 2. Validierungen
        validateUser(user);

        // 3. Password prüfen
        if (user.getPasswd() == null) {
            log.error("Password is null for user: {}", username);
            throw new RuntimeException("User account is not properly configured");
        }
        log.info("Matching password for user: {}. Encoded in DB: {}", username, user.getPasswd());
        if (!matchesPassword(password, user.getPasswd())) {
            log.warn("Invalid password for user: {}", username);
            throw new RuntimeException("Invalid credentials");
        }

        // 4. Rollen laden
        Set<RoleEnum> roleEnums = user.getRoleEnums();
        Set<String> keycloakRoleNames = user.getKeycloakRoleNames();

        log.info("User {} authenticated successfully with {} roles from {} role groups",
                username, roleEnums.size(), user.getRoleGroups().size());

        // 5. Migration zu Keycloak (falls noch nicht migriert)
        if (user.getKeycloakId() == null) {
            // Detach user entity so migration (which may run in a REQUIRES_NEW transaction)
            // operates on its own copy
            entityManager.detach(user);

            return handleMigrationDuringLogin(user, password, roleEnums, keycloakRoleNames);
        } else {
            return handleAlreadyMigratedUser(user, roleEnums, keycloakRoleNames);
        }
    }

    // ===================================================================
    // Migration Handling
    // ===================================================================

    /**
     * Behandelt Migration während Login
     */
    private LoginResponse handleMigrationDuringLogin(UserEntity user, String password,
                                                     Set<RoleEnum> roleEnums,
                                                     Set<String> keycloakRoleNames) {
        // Skip migration if disabled or service not available
        if (!keycloakProperties.getMigration().isMigrateUsers() || keycloakMigrationService == null) {
            log.debug("Keycloak migration is disabled, skipping migration for user {}", user.getLogin());
            return buildLegacyResponse(user, keycloakRoleNames, false, null, null);
        }

        log.info("User {} not yet migrated, attempting Keycloak migration", user.getLogin());

        try {
            // Migration mit Username (nicht Entity) um Version-Konflikte zu vermeiden
            // Die Migration läuft in einer separaten REQUIRES_NEW Transaktion
            String keycloakUserId = keycloakMigrationService.migrateUserWithRoles(user.getLogin(), password);

            log.info("Successfully migrated user {} to Keycloak (KC-ID: {})",
                    user.getLogin(), keycloakUserId);

            // TODO: Keycloak Token holen
            // Aktuell: Legacy Token als Fallback
            String token = legacyJwtService.generateAccessToken(user);
            String refreshToken = legacyJwtService.generateRefreshToken(user);

            return LoginResponse.builder()
                    .accessToken(token)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .roles(keycloakRoleNames)
                    .username(user.getLogin())
                    .firstName(user.getFirstName())
                    .lastName(user.getLastName())
                    .migrated(true)
                    .keycloakUserId(keycloakUserId)
                    .source("legacy") // TODO: Später "keycloak" wenn Keycloak Token
                    .build();

        } catch (Exception e) {
            // Catch ALL exceptions from Keycloak migration (connection errors, timeouts, etc.)
            // Login should never fail just because Keycloak is unavailable
            log.warn("Keycloak migration failed for user {} (Keycloak may be unavailable): {}",
                    user.getLogin(), e.getMessage());
            log.debug("Migration exception details:", e);

            // Fallback: Legacy Token generieren (User kann trotzdem arbeiten)
            String token = legacyJwtService.generateAccessToken(user);
            String refreshToken = legacyJwtService.generateRefreshToken(user);

            return LoginResponse.builder()
                    .accessToken(token)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .roles(keycloakRoleNames)
                    .username(user.getLogin())
                    .firstName(user.getFirstName())
                    .lastName(user.getLastName())
                    .migrated(false)
                    .migrationError("Migration skipped: " + e.getMessage())
                    .source("legacy")
                    .build();
        }
    }

    /**
     * Behandelt bereits migrierte User
     */
    private LoginResponse handleAlreadyMigratedUser(UserEntity user,
                                                    Set<RoleEnum> roleEnums,
                                                    Set<String> keycloakRoleNames) {
        log.info("User {} already migrated to Keycloak (KC-ID: {})",
                user.getLogin(), user.getKeycloakId());

        // TODO: Keycloak Token über Password Grant holen
        // POST /realms/{realm}/protocol/openid-connect/token
        // grant_type=password&username=...&password=...

        // Aktuell: Legacy Token
        String token = legacyJwtService.generateAccessToken(user);
        String refreshToken = legacyJwtService.generateRefreshToken(user);

        return LoginResponse.builder()
                .accessToken(token)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(3600L)
                .roles(keycloakRoleNames)
                .username(user.getLogin())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .migrated(true)
                .keycloakUserId(user.getKeycloakId())
                .source("legacy") // TODO: Später "keycloak"
                .build();
    }

    /**
     * Prüft Password - Fallback für legacy MD5 -> Base64
     */
    private boolean matchesPassword(String rawPassword, String encodedPassword) {
        if (encodedPassword == null) {
            return false;
        }

        // 1. Standard matching (BCrypt, Delegating etc.)
        try {
            if (passwordEncoder.matches(rawPassword, encodedPassword)) {
                return true;
            }
        } catch (Exception e) {
            log.warn("Standard password matching failed for user, trying legacy fallback", e);
        }

        // 2. Legacy Fallback: MD5 -> Base64
        return matchesLegacyMd5(rawPassword, encodedPassword);
    }

    private boolean matchesLegacyMd5(String rawPassword, String encodedPassword) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            String md5Base64 = Base64.getEncoder().encodeToString(digest);

            // Clean encoded password (remove prefix if present)
            String targetHash = encodedPassword;
            if (encodedPassword.startsWith("{")) {
                int closingBrace = encodedPassword.indexOf("}");
                if (closingBrace != -1) {
                    targetHash = encodedPassword.substring(closingBrace + 1);
                }
            }

            return md5Base64.equals(targetHash);
        } catch (Exception e) {
            log.error("Legacy password matching failed", e);
            return false;
        }
    }

    // ===================================================================
    // User Validation
    // ===================================================================

    /**
     * Validiert User Status
     */
    private void validateUser(UserEntity user) {
        if (!user.isActive()) {
            log.warn("Inactive user {} attempted login", user.getLogin());
            throw new RuntimeException("User account is inactive");
        }

        if (user.getPasswd() == null || user.getPasswd().isBlank()) {
            log.error("User {} has no password set", user.getLogin());
            throw new RuntimeException("User account is not properly configured");
        }
    }

    // ===================================================================
    // Refresh Token
    // ===================================================================

    /**
     * Erneuert Token mit Refresh Token
     *
     * @param authHeader Authorization Header mit Refresh Token
     * @return LoginResponse mit neuem Access Token
     */
    @Transactional(readOnly = true)
    public LoginResponse refreshToken(String authHeader) {
        log.info("Refresh token request");

        // Extract token from "Bearer ..." header
        String refreshToken = authHeader.replace("Bearer ", "").trim();

        try {
            // Username aus Refresh Token extrahieren
            String username = legacyJwtService.extractUsername(refreshToken);

            if (username == null || username.isBlank()) {
                throw new RuntimeException("Invalid refresh token");
            }

            // User aus DB laden
            UserEntity user = userRepository.findByLoginWithRoles(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Validierungen
            validateUser(user);

            // Rollen laden
            Set<RoleEnum> roleEnums = user.getRoleEnums();
            Set<String> keycloakRoleNames = user.getKeycloakRoleNames();

            // Neuen Access Token generieren
            String newAccessToken = legacyJwtService.generateAccessToken(user);

            log.info("Successfully refreshed token for user: {}", username);

            return LoginResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(refreshToken) // Refresh Token bleibt gleich
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .roles(keycloakRoleNames)
                    .username(username)
                    .firstName(user.getFirstName())
                    .lastName(user.getLastName())
                    .migrated(user.getKeycloakId() != null)
                    .keycloakUserId(user.getKeycloakId())
                    .source("legacy")
                    .build();

        } catch (Exception e) {
            log.error("Refresh token failed: {}", e.getMessage());
            throw new RuntimeException("Invalid or expired refresh token");
        }
    }

    // ===================================================================
    // Helper Methods
    // ===================================================================

    /**
     * Prüft ob User existiert
     */
    public boolean userExists(String username) {
        return userRepository.existsByLogin(username);
    }

    /**
     * Prüft ob User bereits migriert ist
     */
    public boolean isUserMigrated(String username) {
        return userRepository.findByLogin(username)
                .map(user -> user.getKeycloakId() != null)
                .orElse(false);
    }

    /**
     * Baut eine Legacy LoginResponse
     */
    private LoginResponse buildLegacyResponse(UserEntity user, Set<String> keycloakRoleNames,
                                               boolean migrated, String keycloakId, String migrationError) {
        String token = legacyJwtService.generateAccessToken(user);
        String refreshToken = legacyJwtService.generateRefreshToken(user);

        return LoginResponse.builder()
                .accessToken(token)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(3600L)
                .roles(keycloakRoleNames)
                .username(user.getLogin())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .migrated(migrated)
                .keycloakUserId(keycloakId)
                .migrationError(migrationError)
                .source("legacy")
                .build();
    }
}
