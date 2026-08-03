package de.usermigration.infrastructure.keycloak;

import lombok.Builder;
import lombok.Data;

import java.util.Set;

@Data
@Builder
public class LegacyUserInfo {
    private String username;
    private String email;
    private String origin;
    private Set<String> roles;
}
