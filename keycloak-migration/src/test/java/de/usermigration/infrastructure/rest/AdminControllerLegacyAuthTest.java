package de.usermigration.infrastructure.rest;

import de.usermigration.UnitTest;
import de.usermigration.infrastructure.keycloak.config.KeycloakProperties;
import de.usermigration.infrastructure.security.filter.LegacyJwtMigrationFilter;
import de.usermigration.infrastructure.security.config.SecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Phase 1 (legacy token -> validate -> roles from DB/token -> migrate -> return legacy token):
 * proves the legacy JWT bearer path (default, oauth-client-enabled=false) reaches a role-gated
 * endpoint using roles carried in the token's AUTH_ROLES claim, via the shared
 * KeycloakAuthorityMapper feeding SecurityConfig's resource-server jwtAuthenticationConverter.
 */
@UnitTest
@WebMvcTest(
        controllers = AdminController.class,
        excludeFilters = @ComponentScan.Filter(
                type = FilterType.ASSIGNABLE_TYPE,
                classes = LegacyJwtMigrationFilter.class
        ),
        excludeAutoConfiguration = {
                DataSourceAutoConfiguration.class,
                DataSourceTransactionManagerAutoConfiguration.class,
                HibernateJpaAutoConfiguration.class,
                JpaRepositoriesAutoConfiguration.class,
                LiquibaseAutoConfiguration.class
        }
)
@Import(SecurityConfig.class)
@EnableConfigurationProperties(KeycloakProperties.class)
@DisplayName("Phase 1: /admin/whoami reachable via legacy bearer JWT (AUTH_ROLES claim)")
class AdminControllerLegacyAuthTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Test
    @DisplayName("no token -> 401")
    void noToken_unauthorized() throws Exception {
        mockMvc.perform(get("/admin/whoami"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("legacy JWT with SYSTEM_ADMIN role -> 200, roles mapped to ROLE_SYSTEM_ADMIN")
    void legacyAdminToken_allowed() throws Exception {
        String token = legacyToken("admin.user", "SYSTEM_ADMIN");

        mockMvc.perform(get("/admin/whoami").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin.user"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_SYSTEM_ADMIN"));
    }

    @Test
    @DisplayName("legacy JWT without SYSTEM_ADMIN role -> 403")
    void legacyNonAdminToken_forbidden() throws Exception {
        String token = legacyToken("regular.user", "PERSONNEL");

        mockMvc.perform(get("/admin/whoami").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    private String legacyToken(String username, String authRoles) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("test-token-issuer")
                .subject(username)
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.HOURS))
                .claim("AUTH_ROLES", authRoles)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims))
                .getTokenValue();
    }
}
