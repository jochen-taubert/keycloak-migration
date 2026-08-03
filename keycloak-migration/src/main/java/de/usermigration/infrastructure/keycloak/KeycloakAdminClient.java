package de.usermigration.infrastructure.keycloak;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import jakarta.annotation.PreDestroy;

/**
 * Verwaltet Keycloak Admin Client Instanz
 */
@Component
@ConditionalOnProperty(name = "keycloak.migration.migrate-users", havingValue = "true")
@Slf4j
public class KeycloakAdminClient {

    @Value("${keycloak.server-url}")
    private String serverUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.admin.username}")
    private String username;

    @Value("${keycloak.admin.password}")
    private String password;

    @Value("${keycloak.admin.client-id}")
    private String clientId;

    private Keycloak keycloak;

    /**
     * Gibt Keycloak Admin Client Instanz zurück (Singleton)
     */
    public synchronized Keycloak getInstance() {
        if (keycloak == null) {
            log.info("Initializing Keycloak Admin Client for realm: {}", realm);

            keycloak = KeycloakBuilder.builder()
                    .serverUrl(serverUrl)
                    .realm("master")  // Admin Client authentifiziert sich gegen master realm
                    .username(username)
                    .password(password)
                    .clientId(clientId)
                    .build();

            log.info("Keycloak Admin Client initialized successfully");
        }

        return keycloak;
    }

    /**
     * Schließt Keycloak Client beim Shutdown
     */
    @PreDestroy
    public void cleanup() {
        if (keycloak != null) {
            log.info("Closing Keycloak Admin Client");
            keycloak.close();
            keycloak = null;
        }
    }
}
