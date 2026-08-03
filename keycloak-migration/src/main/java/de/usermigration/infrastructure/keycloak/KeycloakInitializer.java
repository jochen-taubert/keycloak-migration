package de.usermigration.infrastructure.keycloak;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Initializes Keycloak configuration at application startup.
 * Runs once after the application is fully started.
 */
@Component
@ConditionalOnProperty(name = "keycloak.migration.migrate-users", havingValue = "true")
@RequiredArgsConstructor
@Slf4j
public class KeycloakInitializer {

    private final KeycloakMigrationService keycloakMigrationService;
    private final KeycloakProperties keycloakProperties;

    @Async
    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        if (!keycloakProperties.getMigration().isMigrateUsers()) {
            log.info("Keycloak migration is disabled, skipping initialization");
            return;
        }

        log.info("Initializing Keycloak configuration...");

        try {
            // Ensure protocol mapper for role_ids exists (one-time setup)
            keycloakMigrationService.ensureRoleIdsProtocolMapper();
            log.info("Keycloak initialization completed successfully");
        } catch (Exception e) {
            // Log error but don't fail startup - Keycloak might be temporarily unavailable
            log.warn("Keycloak initialization failed (Keycloak may be unavailable): {}", e.getMessage());
        }
    }
}
