package de.usermigration.infrastructure.keycloak;

import de.usermigration.UnitTest;
import de.usermigration.domain.model.entity.UserEntity;
import de.usermigration.infrastructure.persistence.repositories.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.mockito.Mockito.*;

@UnitTest
@ExtendWith(MockitoExtension.class)
@DisplayName("LegacyJwtMigrationFilter Unit Tests")
class LegacyJwtMigrationFilterTest {

    @Mock
    private LegacyJwtService legacyJwtService;

    @Mock
    private KeycloakMigrationService keycloakMigrationService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private KeycloakProperties keycloakProperties;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    private LegacyJwtMigrationFilter filter;

    @BeforeEach
    void setUp() {
        // Setup KeycloakProperties mock - migration enabled by default for tests
        KeycloakProperties.Migration migration = new KeycloakProperties.Migration();
        migration.setMigrateUsers(true);
        when(keycloakProperties.getMigration()).thenReturn(migration);

        filter = new LegacyJwtMigrationFilter(legacyJwtService, keycloakMigrationService, userRepository, keycloakProperties);
    }

    @Nested
    @DisplayName("Token Detection")
    class TokenDetection {

        @Test
        @DisplayName("No Authorization header - passes through")
        void noAuthHeader() throws Exception {
            when(request.getHeader("Authorization")).thenReturn(null);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verifyNoInteractions(legacyJwtService);
        }

        @Test
        @DisplayName("Non-Bearer token - passes through")
        void nonBearerToken() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verifyNoInteractions(legacyJwtService);
        }

        @Test
        @DisplayName("Keycloak token - passes through without migration")
        void keycloakToken() throws Exception {
            String keycloakToken = "keycloak.jwt.token";
            when(request.getHeader("Authorization")).thenReturn("Bearer " + keycloakToken);
            when(legacyJwtService.isLegacyToken(keycloakToken)).thenReturn(false);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verifyNoInteractions(keycloakMigrationService);
        }
    }

    @Nested
    @DisplayName("Legacy Token Migration")
    class LegacyTokenMigration {

        private static final String LEGACY_TOKEN = "legacy.jwt.token";
        private static final String USERNAME = "testuser";

        @Test
        @DisplayName("Valid legacy token triggers migration for non-migrated user")
        void validLegacyTokenTriggersMigration() throws Exception {
            // Given
            UserEntity user = UserEntity.builder()
                    .login(USERNAME)
                    .active(true)
                    .keycloakId(null)
                    .build();

            when(request.getHeader("Authorization")).thenReturn("Bearer " + LEGACY_TOKEN);
            when(legacyJwtService.isLegacyToken(LEGACY_TOKEN)).thenReturn(true);
            when(legacyJwtService.validateToken(LEGACY_TOKEN)).thenReturn(true);
            when(legacyJwtService.extractUsername(LEGACY_TOKEN)).thenReturn(USERNAME);
            when(userRepository.findByLoginWithRoles(USERNAME)).thenReturn(Optional.of(user));

            // When
            filter.doFilterInternal(request, response, filterChain);

            // Then
            verify(keycloakMigrationService).migrateUserWithoutPassword(user);
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Already migrated user - no re-migration")
        void alreadyMigratedUserNoReMigration() throws Exception {
            // Given
            UserEntity user = UserEntity.builder()
                    .login(USERNAME)
                    .active(true)
                    .keycloakId("existing-kc-id")
                    .build();

            when(request.getHeader("Authorization")).thenReturn("Bearer " + LEGACY_TOKEN);
            when(legacyJwtService.isLegacyToken(LEGACY_TOKEN)).thenReturn(true);
            when(legacyJwtService.validateToken(LEGACY_TOKEN)).thenReturn(true);
            when(legacyJwtService.extractUsername(LEGACY_TOKEN)).thenReturn(USERNAME);
            when(userRepository.findByLoginWithRoles(USERNAME)).thenReturn(Optional.of(user));

            // When
            filter.doFilterInternal(request, response, filterChain);

            // Then
            verify(keycloakMigrationService, never()).migrateUserWithoutPassword(any());
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Invalid legacy token - no migration")
        void invalidLegacyTokenNoMigration() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Bearer " + LEGACY_TOKEN);
            when(legacyJwtService.isLegacyToken(LEGACY_TOKEN)).thenReturn(true);
            when(legacyJwtService.validateToken(LEGACY_TOKEN)).thenReturn(false);

            filter.doFilterInternal(request, response, filterChain);

            verifyNoInteractions(keycloakMigrationService);
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("User not found - no migration")
        void userNotFoundNoMigration() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Bearer " + LEGACY_TOKEN);
            when(legacyJwtService.isLegacyToken(LEGACY_TOKEN)).thenReturn(true);
            when(legacyJwtService.validateToken(LEGACY_TOKEN)).thenReturn(true);
            when(legacyJwtService.extractUsername(LEGACY_TOKEN)).thenReturn(USERNAME);
            when(userRepository.findByLoginWithRoles(USERNAME)).thenReturn(Optional.empty());

            filter.doFilterInternal(request, response, filterChain);

            verifyNoInteractions(keycloakMigrationService);
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Inactive user - no migration")
        void inactiveUserNoMigration() throws Exception {
            UserEntity user = UserEntity.builder()
                    .login(USERNAME)
                    .active(false) // Inactive
                    .keycloakId(null)
                    .build();

            when(request.getHeader("Authorization")).thenReturn("Bearer " + LEGACY_TOKEN);
            when(legacyJwtService.isLegacyToken(LEGACY_TOKEN)).thenReturn(true);
            when(legacyJwtService.validateToken(LEGACY_TOKEN)).thenReturn(true);
            when(legacyJwtService.extractUsername(LEGACY_TOKEN)).thenReturn(USERNAME);
            when(userRepository.findByLoginWithRoles(USERNAME)).thenReturn(Optional.of(user));

            filter.doFilterInternal(request, response, filterChain);

            verify(keycloakMigrationService, never()).migrateUserWithoutPassword(any());
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Migration error - request still proceeds")
        void migrationErrorRequestProceeds() throws Exception {
            UserEntity user = UserEntity.builder()
                    .login(USERNAME)
                    .active(true)
                    .keycloakId(null)
                    .build();

            when(request.getHeader("Authorization")).thenReturn("Bearer " + LEGACY_TOKEN);
            when(legacyJwtService.isLegacyToken(LEGACY_TOKEN)).thenReturn(true);
            when(legacyJwtService.validateToken(LEGACY_TOKEN)).thenReturn(true);
            when(legacyJwtService.extractUsername(LEGACY_TOKEN)).thenReturn(USERNAME);
            when(userRepository.findByLoginWithRoles(USERNAME)).thenReturn(Optional.of(user));
            doThrow(new RuntimeException("Keycloak unavailable"))
                    .when(keycloakMigrationService).migrateUserWithoutPassword(user);

            // When
            filter.doFilterInternal(request, response, filterChain);

            // Then: Request should still proceed despite migration failure
            verify(filterChain).doFilter(request, response);
        }
    }
}
