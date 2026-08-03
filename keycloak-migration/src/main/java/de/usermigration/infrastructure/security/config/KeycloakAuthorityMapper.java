package de.usermigration.infrastructure.security.config;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Maps role claims from either a legacy JWT ({@code AUTH_ROLES}) or a genuine
 * Keycloak token/session ({@code realm_access.roles}, {@code resource_access.{client}.roles})
 * onto Spring's {@code ROLE_*} authorities. Shared between the resource-server JWT converter
 * (bearer tokens, phase 1) and the OIDC login user service (browser session login, phase 2)
 * so both authentication paths enforce the same roles the same way.
 */
final class KeycloakAuthorityMapper {

    private KeycloakAuthorityMapper() {
    }

    static Set<GrantedAuthority> mapAuthorities(Map<String, Object> claims, String resourceServerClientId) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        String authRoles = (String) claims.get("AUTH_ROLES");
        if (authRoles != null && !authRoles.isBlank()) {
            for (String role : authRoles.split(",")) {
                String trimmedRole = role.trim();
                if (!trimmedRole.isEmpty()) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_%s".formatted(trimmedRole)));
                }
            }
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
        if (realmAccess != null) {
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) realmAccess.get("roles");
            addNormalizedRoles(authorities, roles);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> resourceAccess = (Map<String, Object>) claims.get("resource_access");
        if (resourceAccess != null && resourceServerClientId != null) {
            @SuppressWarnings("unchecked")
            Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(resourceServerClientId);
            if (clientAccess != null) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) clientAccess.get("roles");
                addNormalizedRoles(authorities, roles);
            }
        }

        return authorities;
    }

    private static void addNormalizedRoles(Set<GrantedAuthority> authorities, List<String> roles) {
        if (roles == null) {
            return;
        }
        for (String role : roles) {
            authorities.add(new SimpleGrantedAuthority("ROLE_%s".formatted(role)));
        }
    }
}
