package de.usermigration.infrastructure.keycloak;

public class KeycloakMigrationException extends RuntimeException {

    public KeycloakMigrationException(String message) {
        super(message);
    }

    public KeycloakMigrationException(String message, Throwable cause) {
        super(message, cause);
    }
}
