package de.usermigration.infrastructure.security.config;

import de.usermigration.UnitTest;
import de.usermigration.infrastructure.keycloak.KeycloakProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Phase 2 (oauth-client-enabled): proves that once a browser session authenticates against
 * Keycloak's own login (oauth2Login), the resulting principal gets the same ROLE_* authorities
 * a bearer-token login would get - the gap that previously left role-gated endpoints
 * (e.g. "/admin/**", hasRole("SYSTEM_ADMIN")) unreachable after a real Keycloak login.
 */
@UnitTest
@ExtendWith(MockitoExtension.class)
@DisplayName("KeycloakOidcUserService")
class KeycloakOidcUserServiceTest {

    @Mock
    private OAuth2UserService<OidcUserRequest, OidcUser> delegate;

    private KeycloakProperties keycloakProperties;
    private KeycloakOidcUserService service;

    @BeforeEach
    void setUp() {
        keycloakProperties = new KeycloakProperties();
        KeycloakProperties.ResourceServer resourceServer = new KeycloakProperties.ResourceServer();
        resourceServer.setClientId("test-api");
        keycloakProperties.setResourceServer(resourceServer);

        service = new KeycloakOidcUserService(delegate, keycloakProperties);
    }

    @Test
    @DisplayName("maps realm_access.roles from the ID token into ROLE_* authorities")
    void mapsRealmRolesFromIdToken() {
        OidcIdToken idToken = idTokenWithClaims(Map.of(
                IdTokenClaimNames.SUB, "keycloak-user-id",
                "preferred_username", "jdoe",
                "realm_access", Map.of("roles", List.of("SYSTEM_ADMIN"))
        ));
        OidcUser delegateResult = new DefaultOidcUser(Set.of(), idToken);
        when(delegate.loadUser(any())).thenReturn(delegateResult);

        OidcUserRequest request = userRequest("preferred_username");

        OidcUser result = service.loadUser(request);

        assertThat(result.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_SYSTEM_ADMIN");
        assertThat(result.getName()).isEqualTo("jdoe");
    }

    @Test
    @DisplayName("user without SYSTEM_ADMIN role gets no ROLE_SYSTEM_ADMIN authority")
    void userWithoutAdminRoleGetsNoAdminAuthority() {
        OidcIdToken idToken = idTokenWithClaims(Map.of(
                IdTokenClaimNames.SUB, "keycloak-user-id",
                "preferred_username", "regular.user",
                "realm_access", Map.of("roles", List.of("PERSONNEL"))
        ));
        when(delegate.loadUser(any())).thenReturn(new DefaultOidcUser(Set.of(), idToken));

        OidcUser result = service.loadUser(userRequest("preferred_username"));

        assertThat(result.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_PERSONNEL");
    }

    private static OidcIdToken idTokenWithClaims(Map<String, Object> claims) {
        return new OidcIdToken("id-token-value", Instant.now(), Instant.now().plusSeconds(300), claims);
    }

    private static OidcUserRequest userRequest(String userNameAttribute) {
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
                .userNameAttributeName(userNameAttribute)
                .build();

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "access-token-value",
                Instant.now(), Instant.now().plusSeconds(300));

        return new OidcUserRequest(registration, accessToken,
                idTokenWithClaims(Map.of(IdTokenClaimNames.SUB, "keycloak-user-id")));
    }
}
