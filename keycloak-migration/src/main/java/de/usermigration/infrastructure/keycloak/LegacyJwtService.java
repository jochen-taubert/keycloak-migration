package de.usermigration.infrastructure.keycloak;

import de.usermigration.domain.model.enums.RoleEnum;
import de.usermigration.domain.model.entity.RoleEntity;
import de.usermigration.domain.model.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;  // ← WICHTIG
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class LegacyJwtService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

    @Value("${legacy.jwt.issuer:test-token-issuer}")
    private String accessTokenIssuer;

    @Value("${legacy.jwt.refresh-issuer:test-refresh-token-issuer}")
    private String refreshTokenIssuer;

    @Value("${legacy.jwt.access-token-expiry-seconds:3600}")
    private long accessTokenExpirySeconds;

    @Value("${legacy.jwt.refresh-token-expiry-seconds:2592000}")
    private long refreshTokenExpirySeconds;

    public String generateAccessToken(UserEntity user) {
        log.debug("Generating access token for user: {}", user.getLogin());

        Instant now = Instant.now();
        Instant expiry = now.plus(accessTokenExpirySeconds, ChronoUnit.SECONDS);

        String roles = user.getRoleGroups().stream()
                .flatMap(roleGroup -> roleGroup.getRoles().stream())
                .map(RoleEntity::getRoleEnumType)
                .map(RoleEnum::name)
                .distinct()
                .collect(Collectors.joining(","));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(accessTokenIssuer)
                .subject(user.getLogin())
                .issuedAt(now)
                .expiresAt(expiry)
                .claim("SSO_ORIGIN", "test")
                .claim("USER_NAME", user.getFirstName())
                .claim("USER_EMAIL", user.getEmail())
                .claim("AUTH_ROLES", roles)
                .build();

        // ✅ WICHTIG: Explizit HS256 setzen!
        JwtEncoderParameters parameters = JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),
                claims
        );

        String token = jwtEncoder.encode(parameters).getTokenValue();

        log.info("Generated access token for user: {}", user.getLogin());
        return token;
    }

    public String generateRefreshToken(UserEntity user) {
        log.debug("Generating refresh token for user: {}", user.getLogin());
        return generateRefreshToken(user.getLogin(), "test");
    }

    public String generateRefreshToken(String username) {
        return generateRefreshToken(username, "test"); // Default origin
    }

    public String generateRefreshToken(String username, String ssoOrigin) {
        log.debug("Generating refresh token for username: {} with origin: {}", username, ssoOrigin);

        Instant now = Instant.now();
        Instant expiry = now.plus(refreshTokenExpirySeconds, ChronoUnit.SECONDS);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(refreshTokenIssuer)
                .subject(username)
                .issuedAt(now)
                .expiresAt(expiry)
                .claim("SSO_ORIGIN", ssoOrigin)
                .build();

        // ✅ WICHTIG: Explizit HS256 setzen!
        JwtEncoderParameters parameters = JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),
                claims
        );

        String token = jwtEncoder.encode(parameters).getTokenValue();

        log.info("Generated refresh token for username: {}", username);
        return token;
    }

    public String generateToken(String username, Set<RoleEnum> roles) {
        log.debug("Generating token for username: {} with roles: {}", username, roles);

        Instant now = Instant.now();
        Instant expiry = now.plus(accessTokenExpirySeconds, ChronoUnit.SECONDS);

        String rolesStr = roles.stream()
                .map(RoleEnum::name)
                .collect(Collectors.joining(","));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(accessTokenIssuer)
                .subject(username)
                .issuedAt(now)
                .expiresAt(expiry)
                .claim("AUTH_ROLES", rolesStr)
                .build();

        // ✅ WICHTIG: Explizit HS256 setzen!
        JwtEncoderParameters parameters = JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),
                claims
        );

        String token = jwtEncoder.encode(parameters).getTokenValue();

        log.info("Generated token for username: {}", username);
        return token;
    }

    // Rest der Methoden bleiben gleich...

    public boolean validateToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);

            if (jwt.getExpiresAt() == null || jwt.getExpiresAt().isBefore(Instant.now())) {
                log.debug("Token is expired");
                return false;
            }

            log.debug("Token is valid for subject: {}", jwt.getSubject());
            return true;

        } catch (JwtException e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    public String extractUsername(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            String username = jwt.getSubject();
            log.debug("Extracted username from token: {}", username);
            return username;
        } catch (JwtException e) {
            log.error("Failed to extract username from token: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid token: %s".formatted(e.getMessage()), e);
        }
    }

    public Jwt extractClaims(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            log.debug("Extracted claims from token for subject: {}", jwt.getSubject());
            return jwt;
        } catch (JwtException e) {
            log.error("Failed to extract claims from token: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid token: %s".formatted(e.getMessage()), e);
        }
    }

    public LegacyUserInfo validateAndParse(String token) {
        if (!validateToken(token)) {
            log.error("Token validation failed in validateAndParse");
            throw new IllegalArgumentException("Invalid or expired token");
        }

        Jwt jwt = extractClaims(token);

        String roles = jwt.getClaimAsString("AUTH_ROLES");
        Set<String> roleSet = roles != null
                ? Set.of(roles.split(",\\s*"))
                : Set.of();

        LegacyUserInfo userInfo = LegacyUserInfo.builder()
                .username(jwt.getSubject())
                .email(jwt.getClaimAsString("USER_EMAIL"))
                .origin(jwt.getClaimAsString("SSO_ORIGIN"))
                .roles(roleSet)
                .build();

        log.debug("Parsed legacy user info for: {}", userInfo.getUsername());
        return userInfo;
    }

    public boolean isLegacyToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);

            // Check if issuer matches either access or refresh token issuer
            String issuer = jwt.getClaimAsString("iss");
            boolean isLegacy = accessTokenIssuer.equals(issuer) || refreshTokenIssuer.equals(issuer);

            log.debug("Token issuer: {}, expected access: {}, expected refresh: {}, isLegacy: {}",
                    issuer, accessTokenIssuer, refreshTokenIssuer, isLegacy);

            return isLegacy;

        } catch (JwtException e) {
            log.debug("Token is not a legacy token: {}", e.getMessage());
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);

            if (jwt.getExpiresAt() == null) {
                log.warn("Token has no expiration date");
                return true;
            }

            boolean expired = jwt.getExpiresAt().isBefore(Instant.now());
            log.debug("Token expiration check: expired={}", expired);
            return expired;

        } catch (JwtException e) {
            log.debug("Cannot check expiration for invalid token: {}", e.getMessage());
            return true;
        }
    }
}
