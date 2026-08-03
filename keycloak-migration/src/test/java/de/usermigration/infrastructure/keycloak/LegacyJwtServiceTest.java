package de.usermigration.infrastructure.keycloak;

import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import de.usermigration.UnitTest;
import de.usermigration.domain.model.enums.RoleEnum;
import de.usermigration.domain.model.entity.RoleEntity;
import de.usermigration.domain.model.entity.RoleGroupEntity;
import de.usermigration.domain.model.entity.UserEntity;
import de.usermigration.infrastructure.keycloak.service.LegacyJwtService;
import de.usermigration.infrastructure.keycloak.dto.LegacyUserInfo;
import de.usermigration.domain.model.enums.SystemOrigin;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@UnitTest
@Slf4j
@DisplayName("Legacy JWT Service Tests")
class LegacyJwtServiceTest {

    private LegacyJwtService legacyJwtService;

    private static final String TEST_SECRET = "this-is-a-test-secret-key-that-must-be-at-least-256-bits-long-for-hmac-sha256-algorithm";
    private static final String TEST_ISSUER = "test-issuer";
    private static final long EXPIRY_SECONDS = 3600L;
    private static final long REFRESH_EXPIRY_SECONDS = 2592000L;

    @BeforeEach
    void setUp() {
        log.info("Setting up LegacyJwtService test");

        byte[] secretBytes = TEST_SECRET.getBytes(StandardCharsets.UTF_8);
        SecretKey secretKey = new SecretKeySpec(secretBytes, "HmacSHA256");

        JwtDecoder jwtDecoder = NimbusJwtDecoder.withSecretKey(secretKey).build();

        // Lambda-Lösung - funktioniert in ALLEN Spring Security Versionen
        OctetSequenceKey jwk = new OctetSequenceKey.Builder(secretBytes)
                .keyID("test-key")
                .algorithm(com.nimbusds.jose.JWSAlgorithm.HS256)
                .build();

        JWKSource<SecurityContext> jwkSource = (selector, context) -> List.of(jwk);
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);

        legacyJwtService = new LegacyJwtService(jwtEncoder, jwtDecoder);

        ReflectionTestUtils.setField(legacyJwtService, "accessTokenIssuer", TEST_ISSUER);
        ReflectionTestUtils.setField(legacyJwtService, "refreshTokenIssuer", TEST_ISSUER);
        ReflectionTestUtils.setField(legacyJwtService, "accessTokenExpirySeconds", EXPIRY_SECONDS);
        ReflectionTestUtils.setField(legacyJwtService, "refreshTokenExpirySeconds", REFRESH_EXPIRY_SECONDS);
    }

    @Test
    @DisplayName("Generate access token with UserEntity")
    void generateAccessToken() {
        log.info("=== Starting generateAccessToken test ===");

        // Given
        UserEntity user = createTestUser();
        log.info("Test user created: {}", user.getLogin());

        // When
        log.info("Calling generateAccessToken...");
        try {
            String token = legacyJwtService.generateAccessToken(user);
            log.info("Token generated successfully: {}", token.substring(0, Math.min(50, token.length())));

            // Then
            assertThat(token).isNotBlank();
            assertThat(legacyJwtService.validateToken(token)).isTrue();

            var jwt = legacyJwtService.extractClaims(token);
            assertThat(jwt.getSubject()).isEqualTo("testuser");
            assertThat(jwt.getClaimAsString("USER_NAME")).isEqualTo("Test");
            assertThat(jwt.getClaimAsString("USER_EMAIL")).isEqualTo("test@example.com");
            assertThat(jwt.getClaimAsString("SSO_ORIGIN")).isEqualTo("test");
            assertThat(jwt.getClaimAsString("AUTH_ROLES")).contains("SYSTEM_ADMIN");

            log.info("generateAccessToken test passed");

        } catch (Exception e) {
            log.error("Error generating token", e);
            throw e;
        }
    }

    @Test
    @DisplayName("Generate refresh token")
    void generateRefreshToken() {
        log.info("Testing generateRefreshToken");

        // Given
        UserEntity user = createTestUser();

        // When
        String refreshToken = legacyJwtService.generateRefreshToken(user);
        log.info("Generated refresh token");

        // Then
        assertThat(refreshToken).isNotBlank();
        assertThat(legacyJwtService.validateToken(refreshToken)).isTrue();

        var jwt = legacyJwtService.extractClaims(refreshToken);
        assertThat(jwt.getClaimAsString("SSO_ORIGIN")).isEqualTo("test");
        assertThat(jwt.getClaimAsString("token_type")).isNull();

        log.info("generateRefreshToken test passed");
    }

    @Test
    @DisplayName("Validate token returns true for valid token")
    void validateToken_validToken() {
        log.info("Testing validateToken_validToken");

        // Given
        UserEntity user = createTestUser();
        String token = legacyJwtService.generateAccessToken(user);

        // When
        boolean isValid = legacyJwtService.validateToken(token);
        log.info("Token validation result: {}", isValid);

        // Then
        assertThat(isValid).isTrue();

        log.info("validateToken_validToken test passed");
    }

    @Test
    @DisplayName("Validate token returns false for invalid token")
    void validateToken_invalidToken() {
        log.info("Testing validateToken_invalidToken");

        // Given
        String invalidToken = "invalid.token.here";

        // When
        boolean isValid = legacyJwtService.validateToken(invalidToken);
        log.info("Invalid token validation result: {}", isValid);

        // Then
        assertThat(isValid).isFalse();

        log.info("validateToken_invalidToken test passed");
    }

    @Test
    @DisplayName("Extract username from token")
    void extractUsername() {
        log.info("Testing extractUsername");

        // Given
        UserEntity user = createTestUser();
        String token = legacyJwtService.generateAccessToken(user);

        // When
        String username = legacyJwtService.extractUsername(token);
        log.info("Extracted username: {}", username);

        // Then
        assertThat(username).isEqualTo("testuser");

        log.info("extractUsername test passed");
    }

    @Test
    @DisplayName("Extract username throws exception for invalid token")
    void extractUsername_invalidToken() {
        log.info("Testing extractUsername_invalidToken");

        // Given
        String invalidToken = "invalid.token.here";

        // When/Then
        assertThatThrownBy(() -> legacyJwtService.extractUsername(invalidToken))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid token");

        log.info("extractUsername_invalidToken test passed");
    }

    @Test
    @DisplayName("Validate and parse token returns user info")
    void validateAndParse() {
        log.info("Testing validateAndParse");

        // Given
        UserEntity user = createTestUser();
        String token = legacyJwtService.generateAccessToken(user);

        // When
        LegacyUserInfo userInfo = legacyJwtService.validateAndParse(token);
        log.info("Parsed user info: {}", userInfo);

        // Then
        assertThat(userInfo.getUsername()).isEqualTo("testuser");
        assertThat(userInfo.getEmail()).isEqualTo("test@example.com");
        assertThat(userInfo.getOrigin()).isEqualTo("test");
        assertThat(userInfo.getRoles()).contains("SYSTEM_ADMIN", "PERSONNEL");

        log.info("validateAndParse test passed");
    }

    @Test
    @DisplayName("Is legacy token returns true for legacy tokens")
    void isLegacyToken_true() {
        log.info("Testing isLegacyToken_true");

        // Given
        UserEntity user = createTestUser();
        String token = legacyJwtService.generateAccessToken(user);
        log.info("Generated token for legacy check");

        // When
        boolean isLegacy = legacyJwtService.isLegacyToken(token);
        log.info("isLegacyToken result: {}", isLegacy);

        // Then
        assertThat(isLegacy).isTrue();

        log.info("isLegacyToken_true test passed");
    }

    @Test
    @DisplayName("Is legacy token returns false for invalid tokens")
    void isLegacyToken_false() {
        log.info("Testing isLegacyToken_false");

        // Given
        String invalidToken = "invalid.token.here";

        // When
        boolean isLegacy = legacyJwtService.isLegacyToken(invalidToken);
        log.info("Invalid token legacy check: {}", isLegacy);

        // Then
        assertThat(isLegacy).isFalse();

        log.info("isLegacyToken_false test passed");
    }

    @Test
    @DisplayName("Token is not expired immediately after creation")
    void isTokenExpired_false() {
        log.info("Testing isTokenExpired_false");

        // Given
        UserEntity user = createTestUser();
        String token = legacyJwtService.generateAccessToken(user);

        // When
        boolean isExpired = legacyJwtService.isTokenExpired(token);
        log.info("Token expiration status: {}", isExpired);

        // Then
        assertThat(isExpired).isFalse();

        log.info("isTokenExpired_false test passed");
    }

    @Test
    @DisplayName("Generate token with username and roles (backward compatibility)")
    void generateToken_withUsernameAndRoles() {
        log.info("Testing generateToken_withUsernameAndRoles");

        // Given
        String username = "testuser";
        Set<RoleEnum> roles = Set.of(RoleEnum.SYSTEM_ADMIN, RoleEnum.PERSONNEL);

        // When
        String token = legacyJwtService.generateToken(username, roles);
        log.info("Generated token with username and roles");

        // Then
        assertThat(token).isNotBlank();
        assertThat(legacyJwtService.validateToken(token)).isTrue();
        assertThat(legacyJwtService.extractUsername(token)).isEqualTo(username);

        log.info("generateToken_withUsernameAndRoles test passed");
    }

    @Test
    @DisplayName("Generate refresh token with username (backward compatibility)")
    void generateRefreshToken_withUsername() {
        log.info("Testing generateRefreshToken_withUsername");

        // Given
        String username = "testuser";

        // When
        String refreshToken = legacyJwtService.generateRefreshToken(username);
        log.info("Generated refresh token with username");

        // Then
        assertThat(refreshToken).isNotBlank();
        assertThat(legacyJwtService.validateToken(refreshToken)).isTrue();

        log.info("generateRefreshToken_withUsername test passed");
    }

    // Helper method to create test user
    private UserEntity createTestUser() {
        log.debug("Creating test user");

        // Create role entities
        RoleEntity adminRole = RoleEntity.builder()
                .roleEnumType(RoleEnum.SYSTEM_ADMIN)
                .roleOrigin(SystemOrigin.TEST)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();

        RoleEntity personnelRole = RoleEntity.builder()
                .roleEnumType(RoleEnum.PERSONNEL)
                .roleOrigin(SystemOrigin.TEST)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();

        // Create role group
        RoleGroupEntity roleGroup = RoleGroupEntity.builder()
                .designation("Test Group")
                .description("Test Role Group")
                .system(true)
                .userInternal(false)
                .created(LocalDateTime.now())
                .deleted(0)
                .build();

        roleGroup.getRoles().add(adminRole);
        roleGroup.getRoles().add(personnelRole);

        // Create user
        UserEntity user = UserEntity.builder()
                .login("testuser")
                .email("test@example.com")
                .firstName("Test")
                .lastName("User")
                .passwd("encoded-password")
                .active(true)
                .build();

        user.getRoleGroups().add(roleGroup);

        log.debug("Test user created: {}", user.getLogin());
        return user;
    }
}
