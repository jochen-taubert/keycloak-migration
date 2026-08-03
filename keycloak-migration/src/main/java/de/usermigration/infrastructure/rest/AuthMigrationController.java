package de.usermigration.infrastructure.rest;

import de.usermigration.domain.model.enums.RoleEnum;
import de.usermigration.application.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthMigrationController {

    private final AuthenticationService authenticationService;

    /**
     * Legacy login endpoint - returns array with single element
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        log.info("Login attempt for user: {}", request.getUsername());

        try {
            // Authenticate - returns LoginResponse
            LoginResponse loginResponse = authenticationService.authenticate(
                    request.getUsername(),
                    request.getPassword()
            );

            // Convert to legacy format
            LegacyLoginResponseWrapper response = convertToLegacyFormat(loginResponse);

            log.info("Login successful for user: {}", request.getUsername());

            // Return as single-element array for legacy compatibility
            return ResponseEntity.ok(List.of(response));
        } catch (Exception e) {
            log.error("Login failed for user: {} - Error: {}", request.getUsername(), e.getMessage(), e);
            return ResponseEntity.status(401).body(e.getMessage());
        }
    }

    /**
     * Refresh token endpoint
     */
    @PostMapping("/refresh")
    public ResponseEntity<List<LegacyLoginResponseWrapper>> refresh(
            @RequestHeader("Authorization") String authHeader) {

        log.info("Refresh token request");

        // Use AuthenticationService to refresh
        LoginResponse loginResponse = authenticationService.refreshToken(authHeader);

        // Convert to legacy format
        LegacyLoginResponseWrapper response = convertToLegacyFormat(loginResponse);

        return ResponseEntity.ok(List.of(response));
    }

    /**
     * Convert modern LoginResponse to legacy format
     */
    private LegacyLoginResponseWrapper convertToLegacyFormat(LoginResponse loginResponse) {
        // Map roles to numeric IDs using RoleEnum
        String[] roleIds = loginResponse.getRoles().stream()
                .map(this::mapRoleToNumericId)
                .toArray(String[]::new);

        LegacyLoginResponseWrapper.AuthXBVO authXBVO = LegacyLoginResponseWrapper.AuthXBVO.builder()
                .roles(roleIds)
                .token(loginResponse.getAccessToken())
                .refreshToken(loginResponse.getRefreshToken())
                .login(loginResponse.getUsername())
                .lastName(loginResponse.getLastName())
                .firstName(loginResponse.getFirstName())
                .rfid(null)
                .newMsgs(null)
                .alert(null)
                .code(null)
                .error(null)
                .errorDescription(null)
                .generated(null)
                .ver(null)
                .migrated(loginResponse.getMigrated())
                .keycloakUserId(loginResponse.getKeycloakUserId())
                .migrationError(loginResponse.getMigrationError())
                .build();

        return LegacyLoginResponseWrapper.builder()
                .lastUsed(Instant.now())
                .authXBVO(authXBVO)
                .build();
    }

    /**
     * Maps a Keycloak role name (e.g., "SYSTEM_ADMIN") to its numeric ID
     */
    private String mapRoleToNumericId(String keycloakRoleName) {
        try {
            RoleEnum roleEnum = RoleEnum.fromString(keycloakRoleName);
            return roleEnum.getRoleIdString();
        } catch (IllegalArgumentException e) {
            log.warn("Unknown role: {}, using default ID", keycloakRoleName);
            return "9999";
        }
    }
}
