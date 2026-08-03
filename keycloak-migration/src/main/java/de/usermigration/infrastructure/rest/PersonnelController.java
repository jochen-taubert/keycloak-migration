package de.usermigration.infrastructure.rest;

import java.util.List;
import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Example role-gated endpoint reachable via either authentication path this app supports:
 * phase 1's legacy JWT bearer token (roles from the {@code AUTH_ROLES} claim) or phase 2's
 * Keycloak browser login (roles from {@code realm_access.roles}). Access is restricted to
 * {@code PERSONNEL} (or {@code SYSTEM_ADMIN}, as an override) via method-level
 * {@code @PreAuthorize} (not a URL pattern in {@code SecurityConfig}), enabled by
 * {@code @EnableMethodSecurity}.
 */
@RestController
@RequestMapping("/personnel")
public class PersonnelController {

    @GetMapping("/whoami")
    @PreAuthorize("hasAnyRole('PERSONNEL', 'SYSTEM_ADMIN')")
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
