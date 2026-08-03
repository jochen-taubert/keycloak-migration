package de.usermigration.infrastructure.security.config;

import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import de.usermigration.infrastructure.keycloak.config.KeycloakProperties;
import lombok.RequiredArgsConstructor;

/**
 * Phase 2: after a browser session logs in via Keycloak's own login page (oauth2Login),
 * re-derives {@code ROLE_*} authorities from the ID token's Keycloak claims using the same
 * mapping the resource-server path uses for bearer tokens (phase 1), so role-gated endpoints
 * (e.g. {@code hasRole("SYSTEM_ADMIN")}) work the same regardless of which auth path was used.
 */
@RequiredArgsConstructor
class KeycloakOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OAuth2UserService<OidcUserRequest, OidcUser> delegate;
    private final KeycloakProperties keycloakProperties;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = delegate.loadUser(userRequest);

        Set<GrantedAuthority> authorities = new LinkedHashSet<>(
                KeycloakAuthorityMapper.mapAuthorities(
                        oidcUser.getIdToken().getClaims(),
                        keycloakProperties.getResourceServer().getClientId()));
        authorities.addAll(oidcUser.getAuthorities());

        String nameAttributeKey = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        if (nameAttributeKey == null || nameAttributeKey.isBlank()) {
            nameAttributeKey = IdTokenClaimNames.SUB;
        }

        return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo(), nameAttributeKey);
    }
}
