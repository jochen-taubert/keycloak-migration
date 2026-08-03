package de.usermigration.infrastructure.rest;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO für User Login
 * Beispiel:
 * {
 *   "username": "max.mustermann",
 *   "password": "secret123"
 * }
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    /**
     * Username / Login
     */
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 255, message = "Username must be between 3 and 255 characters")
    @JsonProperty("username")
    private String username;

    /**
     * Password (Klartext)
     */
    @NotBlank(message = "Password is required")
    @Size(min = 1, max = 255, message = "Password must not be empty")
    @JsonProperty("password")
    private String password;

    /**
     * Optional: Remember Me Flag
     */
    @JsonProperty("rememberMe")
    @Builder.Default
    private boolean rememberMe = false;

    /**
     * Überschreibe toString() um Password nicht zu loggen
     */
    @Override
    public String toString() {
        return "LoginRequest{username='%s', password='[PROTECTED]', rememberMe=%s}".formatted(username, rememberMe);
    }
}
