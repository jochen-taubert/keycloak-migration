package de.usermigration.application.service;

import de.usermigration.UnitTest;
import de.usermigration.domain.model.entity.UserEntity;
import de.usermigration.domain.model.enums.RoleEnum;
import de.usermigration.infrastructure.keycloak.config.KeycloakProperties;
import de.usermigration.infrastructure.keycloak.service.KeycloakMigrationService;
import de.usermigration.infrastructure.keycloak.service.LegacyJwtService;
import de.usermigration.infrastructure.persistence.repositories.UserRepository;
import de.usermigration.infrastructure.rest.LoginResponse;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@UnitTest
@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private KeycloakMigrationService keycloakMigrationService;
    @Mock
    private LegacyJwtService legacyJwtService;
    @Mock
    private KeycloakProperties keycloakProperties;
    @Mock
    private EntityManager entityManager;

    @InjectMocks
    private AuthenticationService authenticationService;

    @Test
    @DisplayName("authenticate: Should throw exception if user not found")
    void authenticateUserNotFound() {
        when(userRepository.findByLoginWithRoles(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authenticationService.authenticate("unknown", "pass"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Invalid credentials");
    }

    @Test
    @DisplayName("authenticate: Should throw exception if password does not match")
    void authenticateInvalidPassword() {
        UserEntity user = new UserEntity();
        user.setLogin("user");
        user.setPasswd("encoded_pass");
        user.setActive(true);

        when(userRepository.findByLoginWithRoles("user")).thenReturn(Optional.of(user));
        // Mock standard matching to return false
        when(passwordEncoder.matches("wrong_pass", "encoded_pass")).thenReturn(false);

        assertThatThrownBy(() -> authenticationService.authenticate("user", "wrong_pass"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Invalid credentials");
    }

    @Test
    @DisplayName("authenticate: Should match legacy MD5 password")
    void authenticateLegacyMd5Success() {
        UserEntity user = new UserEntity();
        user.setLogin("user");
        // MD5 of "password" is 5f4dcc3b5aa765d61d8327deb882cf99
        // Base64 of that hash: X03MO1qnZdYdgyfeuILPmQ==
        user.setPasswd("X03MO1qnZdYdgyfeuILPmQ==");
        user.setActive(true);
        user.setKeycloakId("kc-123");

        when(userRepository.findByLoginWithRoles("user")).thenReturn(Optional.of(user));
        // Mock standard matching to return false or throw exception
        when(passwordEncoder.matches("password", "X03MO1qnZdYdgyfeuILPmQ==")).thenReturn(false);
        when(legacyJwtService.generateAccessToken(any(UserEntity.class))).thenReturn("legacy-token");

        LoginResponse response = authenticationService.authenticate("user", "password");

        assertThat(response.getAccessToken()).isEqualTo("legacy-token");
        assertThat(response.getMigrated()).isTrue();
    }

    @Test
    @DisplayName("authenticate: Should handle already migrated user")
    void authenticateAlreadyMigrated() {
        UserEntity user = new UserEntity();
        user.setLogin("user");
        user.setPasswd("encoded_pass");
        user.setActive(true);
        user.setKeycloakId("kc-123");

        when(userRepository.findByLoginWithRoles("user")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("pass", "encoded_pass")).thenReturn(true);
        when(legacyJwtService.generateAccessToken(any(UserEntity.class)))
                .thenReturn("legacy-token");

        LoginResponse response = authenticationService.authenticate("user", "pass");

        assertThat(response.getAccessToken()).isEqualTo("legacy-token");
        assertThat(response.getMigrated()).isTrue();
        verify(keycloakMigrationService, never()).migrateUserWithRoles(anyString(), anyString());
    }

    @Test
    @DisplayName("isUserMigrated: Should return true if user has keycloakId")
    void isUserMigratedTrue() {
        UserEntity user = new UserEntity();
        user.setKeycloakId("kc-123");
        when(userRepository.findByLogin("user")).thenReturn(Optional.of(user));

        assertThat(authenticationService.isUserMigrated("user")).isTrue();
    }

    @Test
    @DisplayName("isUserMigrated: Should return false if user has no keycloakId")
    void isUserMigratedFalse() {
        UserEntity user = new UserEntity();
        user.setKeycloakId(null);
        when(userRepository.findByLogin("user")).thenReturn(Optional.of(user));

        assertThat(authenticationService.isUserMigrated("user")).isFalse();
    }

    @Test
    @DisplayName("refreshToken: Should refresh token successfully")
    void refreshTokenSuccess() {
        UserEntity user = new UserEntity();
        user.setLogin("user");
        user.setActive(true);
        user.setPasswd("pass");

        when(legacyJwtService.extractUsername(anyString())).thenReturn("user");
        when(userRepository.findByLoginWithRoles("user")).thenReturn(Optional.of(user));
        when(legacyJwtService.generateAccessToken(user)).thenReturn("new-access-token");

        LoginResponse response = authenticationService.refreshToken("Bearer old-refresh-token");

        assertThat(response.getAccessToken()).isEqualTo("new-access-token");
        assertThat(response.getRefreshToken()).isEqualTo("old-refresh-token");
    }

    @Test
    @DisplayName("validateUser: Should throw if user inactive")
    void validateUserInactive() {
        UserEntity user = new UserEntity();
        user.setLogin("user");
        user.setActive(false);

        when(userRepository.findByLoginWithRoles("user")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authenticationService.authenticate("user", "pass"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("User account is inactive");
    }

    @Test
    @DisplayName("validateUser: Should throw if password blank")
    void validateUserPasswordBlank() {
        UserEntity user = new UserEntity();
        user.setLogin("user");
        user.setActive(true);
        user.setPasswd("");

        when(userRepository.findByLoginWithRoles("user")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authenticationService.authenticate("user", "pass"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("User account is not properly configured");
    }
}
