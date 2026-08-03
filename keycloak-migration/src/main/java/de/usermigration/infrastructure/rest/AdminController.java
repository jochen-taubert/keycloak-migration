package de.usermigration.infrastructure.rest;

import java.util.List;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Example role-gated endpoint reachable via either authentication path this app supports:
 * phase 1's legacy JWT bearer token (roles from the {@code AUTH_ROLES} claim) or phase 2's
 * Keycloak browser login (roles from {@code realm_access.roles}). Access is restricted to
 * {@code hasRole("SYSTEM_ADMIN")} by {@code SecurityConfig}'s {@code /admin/**} matcher.
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping("/whoami")
    public Map<String, Object> whoami(Authentication authentication) {
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return Map.of(
                "username", authentication.getName(),
                "roles", roles,
                "authType", authentication.getClass().getSimpleName()
        );
    }
}
