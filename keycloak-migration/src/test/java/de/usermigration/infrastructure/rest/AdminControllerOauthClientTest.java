package de.usermigration.infrastructure.rest;

import de.usermigration.UnitTest;
import de.usermigration.infrastructure.keycloak.KeycloakProperties;
import de.usermigration.infrastructure.keycloak.LegacyJwtMigrationFilter;
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
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Phase 2 (keycloak.migration.oauth-client-enabled=true): a request with no valid token must be
 * redirected into Keycloak's own login (Authorization Code flow) instead of getting the legacy
 * JSON 401 - proving SecurityConfig's oauth2Login + LoginUrlAuthenticationEntryPoint wiring
 * actually kicks in for a protected endpoint like /admin/whoami.
 *
 * The full round trip (redirect -> real Keycloak login -> callback -> role-gated access) needs a
 * live Keycloak and is covered by KeycloakOidcUserServiceTest for the role-mapping half; this
 * test only proves the entry-point redirect, using an in-memory ClientRegistrationRepository so
 * it stays Docker-free.
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
@Import({SecurityConfig.class, AdminControllerOauthClientTest.TestClientRegistrationConfig.class})
@EnableConfigurationProperties(KeycloakProperties.class)
@TestPropertySource(properties = "keycloak.migration.oauth-client-enabled=true")
@DisplayName("Phase 2: unauthenticated request redirects into Keycloak's own login")
class AdminControllerOauthClientTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("no session/token, oauth-client-enabled=true -> redirect to Keycloak authorization endpoint")
    void noAuth_redirectsToKeycloakLogin() throws Exception {
        mockMvc.perform(get("/admin/whoami"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/oauth2/authorization/keycloak"));
    }

    @TestConfiguration
    static class TestClientRegistrationConfig {
        @Bean
        ClientRegistrationRepository clientRegistrationRepository() {
            ClientRegistration registration = ClientRegistration.withRegistrationId("keycloak")
                    .clientId("test-api")
                    .clientSecret("secret")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/keycloak")
                    .scope("openid", "profile", "email")
                    .authorizationUri("http://localhost:8081/realms/test/protocol/openid-connect/auth")
                    .tokenUri("http://localhost:8081/realms/test/protocol/openid-connect/token")
                    .userInfoUri("http://localhost:8081/realms/test/protocol/openid-connect/userinfo")
                    .jwkSetUri("http://localhost:8081/realms/test/protocol/openid-connect/certs")
                    .userNameAttributeName("preferred_username")
                    .build();
            return new InMemoryClientRegistrationRepository(registration);
        }
    }
}
