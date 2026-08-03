package de.usermigration.infrastructure.rest;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private Long expiresIn;
    private Set<String> roles;
    private String username;
    private String firstName;
    private String lastName;
    private Boolean migrated;
    private String keycloakUserId;
    private String source;
    private String migrationError;
}
