package de.usermigration.infrastructure.keycloak;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "keycloak")
@Data
public class KeycloakProperties {

    private String serverUrl;
    private String realm;
    private Admin admin = new Admin();
    private ResourceServer resourceServer = new ResourceServer();
    private Migration migration = new Migration();

    @Data
    public static class Admin {
        private String username;
        private String password;
        private String clientId;
    }

    @Data
    public static class ResourceServer {
        private String clientId;
        private String clientSecret;
    }

    @Data
    public static class Migration {
        private boolean migrateUsers = false;
        private boolean sendPasswordEmail = false;
        private boolean dryRun = false;
        /**
         * Step 2 of the migration: once (almost) every user has been migrated, flip this on so
         * the app acts as an OAuth2 Client and redirects requests with no valid token straight
         * into Keycloak's own login (Authorization Code flow), instead of the legacy JSON 401.
         * {@code /auth/login} keeps working as a fallback either way, for callers not yet migrated.
         */
        private boolean oauthClientEnabled = false;
    }

    public String getTokenUrl() {
        return "%s/realms/%s/protocol/openid-connect/token".formatted(serverUrl, realm);
    }
}
