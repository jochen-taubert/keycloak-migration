package de.usermigration.application.service;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Service zum generieren von random Passwörtern.
 * TODO nach Umstieg auf Keycloak sollte diese Klasse entfernt werden
 */
@Slf4j
@Service
public class PasswordService {

    private static final String UPPER_CASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWER_CASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String NUMBERS = "0123456789";
    private static final String SYMBOLS = "!#%*()_+-=[]{};:,.<>?";
    private static final String ALL_CHARS = UPPER_CASE + LOWER_CASE + NUMBERS + SYMBOLS;
    private static final int PASSWORD_LENGTH = 15;

    public String createRandomEncodedPassword() {
        return encodePassword(createRandomPassword());
    }

    public String encodePassword(String aPlainPassword) {
        return encodeBase64(encodeMD5(aPlainPassword));
    }

    public String createRandomPassword() {
        SecureRandom random = new SecureRandom();

        return IntStream.range(0, PASSWORD_LENGTH)
                .map(i -> random.nextInt(ALL_CHARS.length()))
                .mapToObj(index -> String.valueOf(ALL_CHARS.charAt(index)))
                .collect(Collectors.joining());
    }

    private String encodeBase64(byte[] aInput) {
        return (new Base64()).encodeAsString(aInput);
    }

    private byte[] encodeMD5(String md5) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(md5.getBytes());
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }
}
