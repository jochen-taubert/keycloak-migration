package de.usermigration.application.service;

import de.usermigration.UnitTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@UnitTest
@ExtendWith(MockitoExtension.class)
class PasswordServiceTest {

    @InjectMocks
    private PasswordService passwordService;

    @Test
    @DisplayName("Should generate a random password of correct length")
    void shouldGenerateRandomPassword() {
        String password = passwordService.createRandomPassword();
        assertThat(password).isNotNull().hasSize(15);
    }

    @Test
    @DisplayName("Should generate different passwords on subsequent calls")
    void shouldGenerateDifferentPasswords() {
        String p1 = passwordService.createRandomPassword();
        String p2 = passwordService.createRandomPassword();
        assertThat(p1).isNotEqualTo(p2);
    }

    @Test
    @DisplayName("Should encode password correctly to MD5 Base64")
    void shouldEncodePassword() {
        // MD5 of "password" is 5f4dcc3b5aa765d61d8327deb882cf99
        // Base64 of that hash: X03MO1qnZdYdgyfeuILPmQ==
        String encoded = passwordService.encodePassword("password");
        assertThat(encoded).isEqualTo("X03MO1qnZdYdgyfeuILPmQ==");
    }

    @Test
    @DisplayName("Should create random encoded password")
    void shouldCreateRandomEncodedPassword() {
        String encoded = passwordService.createRandomEncodedPassword();
        assertThat(encoded).isNotNull().isNotEmpty();
        // Base64 of MD5 should be 24 characters long (16 bytes -> 22 chars + 2 padding)
        assertThat(encoded).hasSize(24);
    }
}
