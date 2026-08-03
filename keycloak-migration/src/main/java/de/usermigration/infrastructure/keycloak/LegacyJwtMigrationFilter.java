package de.usermigration.infrastructure.keycloak;

import de.usermigration.domain.model.entity.UserEntity;
import de.usermigration.infrastructure.persistence.repositories.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@ConditionalOnProperty(name = "keycloak.migration.migrate-users", havingValue = "true")
@Order(1)  // Execute before Spring Security filters
@RequiredArgsConstructor
@Slf4j
public class LegacyJwtMigrationFilter extends OncePerRequestFilter {

    private final LegacyJwtService legacyJwtService;
    private final KeycloakMigrationService keycloakMigrationService;
    private final UserRepository userRepository;
    private final KeycloakProperties keycloakProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (!keycloakProperties.getMigration().isMigrateUsers()) {
            filterChain.doFilter(request, response);
            return;
        }

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            if (legacyJwtService.isLegacyToken(token)) {
                log.debug("Processing legacy JWT token");
                attemptMigrationFromToken(token);
            }
        }

        filterChain.doFilter(request, response);
    }

    private void attemptMigrationFromToken(String token) {
        try {
            if (!legacyJwtService.validateToken(token)) {
                log.debug("Legacy token validation failed, skipping migration");
                return;
            }

            String username = legacyJwtService.extractUsername(token);
            if (username == null || username.isBlank()) {
                log.debug("Could not extract username from legacy token");
                return;
            }

            Optional<UserEntity> userOpt = userRepository.findByLoginWithRoles(username);
            if (userOpt.isEmpty()) {
                log.debug("User {} not found in database", username);
                return;
            }

            UserEntity user = userOpt.get();

            if (user.getKeycloakId() != null) {
                log.debug("User {} already migrated to Keycloak", username);
                return;
            }

            if (!user.isActive()) {
                log.debug("User {} is inactive, skipping migration", username);
                return;
            }

            log.info("Triggering Keycloak migration for user {} via legacy token access", username);
            keycloakMigrationService.migrateUserWithoutPassword(user);
            log.info("Successfully migrated user {} to Keycloak via legacy token access", username);

        } catch (Exception e) {
            log.warn("Failed to migrate user during legacy token access: {}", e.getMessage());
        }
    }
}
