package de.usermigration.infrastructure.rest;

import com.fasterxml.jackson.databind.ObjectMapper;

import de.usermigration.UnitTest;
import de.usermigration.application.service.AuthenticationService;
import de.usermigration.infrastructure.security.filter.LegacyJwtMigrationFilter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;


import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@UnitTest
@Slf4j
@WebMvcTest(
        controllers = AuthMigrationController.class,
        excludeFilters = @ComponentScan.Filter(
                type = FilterType.ASSIGNABLE_TYPE,
                classes = LegacyJwtMigrationFilter.class
        ),
        excludeAutoConfiguration = DataSourceAutoConfiguration.class
)
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("Auth Migration Controller Tests")
class AuthMigrationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthenticationService authenticationService;

    @Test
    @DisplayName("Login success returns access token in legacy array format")
    void loginSuccess() throws Exception {
        log.info("Testing login success");

        // Given
        String username = "testuser";
        String password = "password123";
        String testAccessToken = "test.access.token";
        String testRefreshToken = "test.refresh.token";

        LoginResponse mockLoginResponse = LoginResponse.builder()
                .username(username)
                .accessToken(testAccessToken)
                .refreshToken(testRefreshToken)
                .firstName("Test")
                .lastName("User")
                .roles(Set.of("SYSTEM_ADMIN", "PERSONNEL"))
                .build();

        when(authenticationService.authenticate(anyString(), anyString()))
                .thenReturn(mockLoginResponse);

        // When/Then
        LoginRequest request = new LoginRequest();
        request.setUsername(username);
        request.setPassword(password);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].authXBVO").exists())
                .andExpect(jsonPath("$[0].authXBVO.token").value(testAccessToken))
                .andExpect(jsonPath("$[0].authXBVO.refreshToken").value(testRefreshToken))
                .andExpect(jsonPath("$[0].authXBVO.login").value(username))
                .andExpect(jsonPath("$[0].authXBVO.firstName").value("Test"))
                .andExpect(jsonPath("$[0].authXBVO.lastName").value("User"))
                .andExpect(jsonPath("$[0].authXBVO.roles").isArray())
                .andExpect(jsonPath("$[0].lastUsed").exists());

        log.info("Login success test passed");
    }

    @Test
    @DisplayName("Refresh token returns new tokens in legacy format")
    void refreshToken() throws Exception {
        log.info("Testing refresh token");

        // Given
        String authHeader = "Bearer old.refresh.token";
        String newAccessToken = "new.access.token";
        String newRefreshToken = "new.refresh.token";

        LoginResponse mockLoginResponse = LoginResponse.builder()
                .username("testuser")
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .firstName("Test")
                .lastName("User")
                .roles(Set.of("PERSONNEL"))
                .build();

        when(authenticationService.refreshToken(anyString()))
                .thenReturn(mockLoginResponse);

        // When/Then
        mockMvc.perform(post("/auth/refresh")
                        .header("Authorization", authHeader))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].authXBVO.token").value(newAccessToken))
                .andExpect(jsonPath("$[0].authXBVO.refreshToken").value(newRefreshToken));

        log.info("Refresh token test passed");
    }
}
