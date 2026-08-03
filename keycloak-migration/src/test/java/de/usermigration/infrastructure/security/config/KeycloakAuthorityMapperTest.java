package de.usermigration.infrastructure.security.config;

import de.usermigration.UnitTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@UnitTest
@DisplayName("KeycloakAuthorityMapper - shared role mapping for phase 1 (bearer JWT) and phase 2 (OIDC login)")
class KeycloakAuthorityMapperTest {

    @Test
    @DisplayName("phase 1: maps legacy AUTH_ROLES claim (comma-separated) to ROLE_*")
    void mapsLegacyAuthRoles() {
        Map<String, Object> claims = Map.of("AUTH_ROLES", "SYSTEM_ADMIN, PERSONNEL");

        Set<GrantedAuthority> authorities = KeycloakAuthorityMapper.mapAuthorities(claims, "test-api");

        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_SYSTEM_ADMIN", "ROLE_PERSONNEL");
    }

    @Test
    @DisplayName("phase 2: maps Keycloak realm_access.roles to ROLE_*")
    void mapsRealmAccessRoles() {
        Map<String, Object> claims = Map.of(
                "realm_access", Map.of("roles", List.of("SYSTEM_ADMIN", "PERSONNEL", "offline_access"))
        );

        Set<GrantedAuthority> authorities = KeycloakAuthorityMapper.mapAuthorities(claims, "test-api");

        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_SYSTEM_ADMIN", "ROLE_PERSONNEL", "ROLE_offline_access");
    }

    @Test
    @DisplayName("phase 2: maps Keycloak resource_access.{client}.roles to ROLE_* for the configured client only")
    void mapsResourceAccessRolesForConfiguredClientOnly() {
        Map<String, Object> claims = Map.of(
                "resource_access", Map.of(
                        "test-api", Map.of("roles", List.of("SYSTEM_ADMIN")),
                        "other-client", Map.of("roles", List.of("SHOULD_NOT_APPEAR"))
                )
        );

        Set<GrantedAuthority> authorities = KeycloakAuthorityMapper.mapAuthorities(claims, "test-api");

        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_SYSTEM_ADMIN");
    }

    @Test
    @DisplayName("combines all three claim sources when present")
    void combinesAllSources() {
        Map<String, Object> claims = Map.of(
                "AUTH_ROLES", "PERSONNEL",
                "realm_access", Map.of("roles", List.of("SYSTEM_ADMIN")),
                "resource_access", Map.of("test-api", Map.of("roles", List.of("QM_MANAGER")))
        );

        Set<GrantedAuthority> authorities = KeycloakAuthorityMapper.mapAuthorities(claims, "test-api");

        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_PERSONNEL", "ROLE_SYSTEM_ADMIN", "ROLE_QM_MANAGER");
    }

    @Test
    @DisplayName("no role claims present yields no authorities")
    void noClaimsYieldsEmpty() {
        Set<GrantedAuthority> authorities = KeycloakAuthorityMapper.mapAuthorities(Map.of(), "test-api");

        assertThat(authorities).isEmpty();
    }
}
