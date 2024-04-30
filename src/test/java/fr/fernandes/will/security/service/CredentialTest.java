package fr.fernandes.will.security.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class CredentialTest {
    private final CredentialService credentialService = CredentialService.getInstance();

    @Test
    @DisplayName("Hash password")
    void hashPassword() {
        String password = "password";
        String hash = credentialService.hash(password);

        Assertions.assertNotEquals(password, hash);
    }

    @Test
    @DisplayName("Password match")
    void checkPasswordMatch() {
        String password = "password";
        String hash = credentialService.hash(password);

        // Same password
        Assertions.assertTrue(credentialService.checkMatch(hash, password));

        // Different password
        Assertions.assertFalse(credentialService.checkMatch(hash, "wrong password"));
    }

    @Test
    @DisplayName("Email is valid")
    void email() {
        Assertions.assertTrue(credentialService.isValidEmail("email@email.com"));
        Assertions.assertFalse(credentialService.isValidEmail("not a valid email address"));
    }

    @Test
    void tokenGeneration() {
        String token = credentialService.generateToken("role=admin", "id=sd3c1s3d2c1s3c");
        Assertions.assertNotNull(token);
        Assertions.assertFalse(token.isEmpty());
    }
}
