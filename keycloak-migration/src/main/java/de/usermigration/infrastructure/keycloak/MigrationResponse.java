package de.usermigration.infrastructure.keycloak;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response für manuelle Migration
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MigrationResponse {

    /**
     * Migration erfolgreich?
     */
    private boolean success;

    /**
     * Keycloak User ID
     */
    private String keycloakUserId;

    /**
     * Username
     */
    private String username;

    /**
     * Nachricht
     */
    private String message;

    /**
     * Muss User Password zurücksetzen?
     */
    private boolean passwordResetRequired;
}
