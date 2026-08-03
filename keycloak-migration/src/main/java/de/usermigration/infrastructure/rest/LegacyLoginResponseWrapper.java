package de.usermigration.infrastructure.rest;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Legacy login response wrapper
 * Returns array with single element for backward compatibility
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LegacyLoginResponseWrapper {

    @JsonProperty("lastUsed")
    private Instant lastUsed;

    @JsonProperty("authXBVO")
    private AuthXBVO authXBVO;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AuthXBVO {

        @JsonProperty("roles")
        private String[] roles;  // Role IDs as strings (e.g., "1002", "2071")

        @JsonProperty("code")
        private String code;

        @JsonProperty("error")
        private String error;

        @JsonProperty("errorDescription")
        private String errorDescription;

        @JsonProperty("generated")
        private String generated;

        @JsonProperty("ver")
        private String ver;

        @JsonProperty("token")
        private String token;  // Access token

        @JsonProperty("refreshToken")
        private String refreshToken;

        @JsonProperty("login")
        private String login;

        @JsonProperty("lastName")
        private String lastName;

        @JsonProperty("firstName")
        private String firstName;

        @JsonProperty("rfid")
        private String rfid;

        @JsonProperty("newMsgs")
        private Integer newMsgs;

        @JsonProperty("alert")
        private String alert;

        @JsonProperty("migrated")
        private Boolean migrated;

        @JsonProperty("keycloakUserId")
        private String keycloakUserId;

        @JsonProperty("migrationError")
        private String migrationError;
    }
}
