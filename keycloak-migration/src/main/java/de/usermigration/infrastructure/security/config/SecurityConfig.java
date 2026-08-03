package de.usermigration.infrastructure.security.config;

import de.usermigration.infrastructure.keycloak.KeycloakProperties;
import de.usermigration.infrastructure.keycloak.LegacyJwtMigrationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Set;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    @Value("${jwt.secret}")
    private String jwtSecret;

    private final KeycloakProperties keycloakProperties;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            ObjectProvider<LegacyJwtMigrationFilter> migrationFilterProvider
            //@Lazy AuditContextFilter auditContextFilter
    ) throws Exception {

        boolean oauthClientEnabled = keycloakProperties.getMigration().isOauthClientEnabled();

        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/**").permitAll()
                        .requestMatchers("/test/**").permitAll()
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/oauth2/**", "/login/**").permitAll()
                        .requestMatchers("/v1/loga_transfer/**").permitAll()
                        .requestMatchers("/v1/**").permitAll()
                        .requestMatchers("/admin/**").hasRole("SYSTEM_ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder())
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                        .authenticationEntryPoint(jsonAuthenticationEntryPoint())
                )
                .sessionManagement(session -> session
                        // oauth2Login needs a session to hold the authorization request between
                        // the redirect to Keycloak and the callback - can't stay fully stateless.
                        .sessionCreationPolicy(oauthClientEnabled
                                ? SessionCreationPolicy.IF_REQUIRED
                                : SessionCreationPolicy.STATELESS)
                );

        // Step 2 of the migration (keycloak.migration.oauth-client-enabled): once migration is
        // (almost) done, act as an OAuth2 Client too and send requests with no valid token
        // straight into Keycloak's own login instead of the legacy JSON 401. /auth/login keeps
        // working as a fallback either way, for callers that haven't switched over yet.
        if (oauthClientEnabled) {
            http
                    .oauth2Login(oauth2Login -> oauth2Login
                            .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService()))
                    )
                    .exceptionHandling(exceptions -> exceptions
                            .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/oauth2/authorization/keycloak"))
                    );
        }

        // Only register migration filter when Keycloak migration is enabled
        LegacyJwtMigrationFilter migrationFilter = migrationFilterProvider.getIfAvailable();
        if (migrationFilter != null) {
            http.addFilterBefore(migrationFilter, BearerTokenAuthenticationFilter.class);
        }
        // AuditContextFilter runs after authentication to capture user context
        //.addFilterAfter(auditContextFilter, BearerTokenAuthenticationFilter.class);

        return http.build();
    }

    private AuthenticationEntryPoint jsonAuthenticationEntryPoint() {
        return (request, response, authException) -> {
            log.debug("Authentication failed: {}", authException.getMessage());
            response.setStatus(401);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"%s\"}"
                    .formatted(authException.getMessage()));
        };
    }

    /**
     * Composite JwtDecoder that supports both Legacy and Keycloak tokens.
     * First tries Legacy decoder, then Keycloak decoder.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        log.info("=== Creating Composite JwtDecoder (Legacy + Keycloak) ===");

        // Legacy decoder (symmetric key)
        JwtDecoder legacyDecoder = createLegacyDecoder();

        // Keycloak decoder (asymmetric key from JWKS)
        JwtDecoder keycloakDecoder = createKeycloakDecoder();

        // Composite decoder: try Legacy first, then Keycloak
        return token -> {
            // Try Legacy decoder first
            try {
                Jwt jwt = legacyDecoder.decode(token);
                log.debug("Token decoded with Legacy decoder for subject: {}", jwt.getSubject());
                return jwt;
            } catch (JwtException legacyEx) {
                log.debug("Legacy decoder failed, trying Keycloak decoder: {}", legacyEx.getMessage());
            }

            // Try Keycloak decoder
            if (keycloakDecoder != null) {
                try {
                    Jwt jwt = keycloakDecoder.decode(token);
                    log.debug("Token decoded with Keycloak decoder for subject: {}", jwt.getSubject());
                    return jwt;
                } catch (JwtException keycloakEx) {
                    log.debug("Keycloak decoder failed: {}", keycloakEx.getMessage());
                    throw new BadJwtException("Token could not be validated by any decoder", keycloakEx);
                }
            }

            throw new BadJwtException("Token could not be validated");
        };
    }

    private JwtDecoder createLegacyDecoder() {
        log.info("Creating Legacy JwtDecoder with secret length: {}", jwtSecret.length());
        SecretKey secretKey = new SecretKeySpec(
                jwtSecret.getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
        );
        return NimbusJwtDecoder.withSecretKey(secretKey).build();
    }

    private JwtDecoder createKeycloakDecoder() {
        try {
            String jwkSetUri = keycloakProperties.getResourceServer().getClientSecret() != null
                    ? "%s/realms/%s/protocol/openid-connect/certs".formatted(
                            keycloakProperties.getServerUrl(), keycloakProperties.getRealm())
                    : null;

            if (jwkSetUri != null) {
                log.info("Creating Keycloak JwtDecoder with JWKS URI: {}", jwkSetUri);
                return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
            }
        } catch (Exception e) {
            log.warn("Could not create Keycloak decoder: {}", e.getMessage());
        }
        return null;
    }

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        return new KeycloakOidcUserService(new OidcUserService(), keycloakProperties);
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        SecretKey secretKey = new SecretKeySpec(
                jwtSecret.getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
        );
        JWKSource<SecurityContext> jwkSource = new ImmutableSecret<>(secretKey);
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * Custom JwtAuthenticationConverter that supports both:
     * - Legacy tokens: roles in "AUTH_ROLES" claim (comma-separated)
     * - Keycloak tokens: roles in "realm_access.roles" or "resource_access.{client}.roles"
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Set<GrantedAuthority> authorities = KeycloakAuthorityMapper.mapAuthorities(
                    jwt.getClaims(), keycloakProperties.getResourceServer().getClientId());
            log.debug("Total authorities for subject {}: {}", jwt.getSubject(), authorities);
            return authorities;
        });

        return converter;
    }
}
