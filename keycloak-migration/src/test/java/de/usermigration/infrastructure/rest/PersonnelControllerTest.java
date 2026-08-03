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
 * Proves /personnel/whoami's access control, which - unlike /admin/**'s SecurityConfig URL
 * matcher - is enforced entirely by method-level @PreAuthorize("hasAnyRole('PERSONNEL',
 * 'SYSTEM_ADMIN')") on PersonnelController.whoami(). Mirrors AdminControllerLegacyAuthTest's
 * approach: legacy JWTs minted directly via the JwtEncoder bean, no DB/Keycloak needed.
 */
@UnitTest
@WebMvcTest(
        controllers = PersonnelController.class,
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
@DisplayName("/personnel/whoami access control (@PreAuthorize, not a SecurityConfig URL matcher)")
class PersonnelControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Test
    @DisplayName("no token -> 401")
    void noToken_unauthorized() throws Exception {
        mockMvc.perform(get("/personnel/whoami"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("legacy JWT with PERSONNEL role -> 200, roles mapped to ROLE_PERSONNEL")
    void personnelToken_allowed() throws Exception {
        String token = legacyToken("personnel.user", "PERSONNEL");

        mockMvc.perform(get("/personnel/whoami").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("personnel.user"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_PERSONNEL"));
    }

    @Test
    @DisplayName("legacy JWT with SYSTEM_ADMIN role -> 200 (override, hasAnyRole)")
    void systemAdminToken_allowedAsOverride() throws Exception {
        String token = legacyToken("admin.user", "SYSTEM_ADMIN");

        mockMvc.perform(get("/personnel/whoami").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin.user"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_SYSTEM_ADMIN"));
    }

    @Test
    @DisplayName("legacy JWT with neither PERSONNEL nor SYSTEM_ADMIN -> 403")
    void unrelatedRoleToken_forbidden() throws Exception {
        String token = legacyToken("facility.user", "FU_FACILITY_WORKPLAN");

        mockMvc.perform(get("/personnel/whoami").header("Authorization", "Bearer " + token))
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
