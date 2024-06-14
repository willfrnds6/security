package fr.fernandes.will.security.service;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

public class CredentialTest {
    private final CredentialService credentialService;

    public CredentialTest() {
        credentialService = CredentialService.getInstance();
    }

    /** Test hash password */
    @Test
    @Order(1)
    @DisplayName("Hash password")
    void hashPassword() {
        // Hash password
        String password = "password";
        Argon2 encoder = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, 32, 64);
        String localHash = encoder.hash(2, 15 * 1024, 1, password.toCharArray());

        // Check encoder
        Assertions.assertTrue(encoder.verify(localHash, password.toCharArray()));

        // Check if hash match with service version
        String serviceHash = credentialService.hash(password);
        Assertions.assertTrue(encoder.verify(serviceHash, password.toCharArray()));
    }

    /** Check if a hashed password, match with clear password */
    @Test
    @Order(2)
    @DisplayName("Password match")
    void checkPasswordMatch() {
        String password = "password";
        String hash = credentialService.hash(password);

        // Same password
        Assertions.assertTrue(credentialService.checkMatch(hash, password));

        // Different password
        Assertions.assertFalse(credentialService.checkMatch(hash, "wrong password"));
    }

    /** Check if email is a real email */
    @Test
    @Order(3)
    @DisplayName("Email is valid")
    void email() {
        Assertions.assertTrue(credentialService.isValidEmail("email@email.com"));
        Assertions.assertFalse(credentialService.isValidEmail("not a valid email address"));
    }

    /** Check token generation */
    @Test
    @Order(4)
    @DisplayName("Token generation")
    void tokenGeneration() {
        String token = credentialService.generateToken("role=admin", "id=sd3c1s3d2c1s3c");
        Assertions.assertNotNull(token);
        Assertions.assertFalse(token.isEmpty());
    }

    /** Check strong password detection */
    @Test
    @Order(5)
    @DisplayName("Strong password detection")
    void strongPasswordDetection() {
        // Detect not strong password
        Assertions.assertFalse(credentialService.passwordIsSecured("password"));

        // Strong password
        Assertions.assertTrue(credentialService.passwordIsSecured("jkjh7834#@O0"));
    }

    /** Check if password min length update, works correctly */
    @Test
    @Order(6)
    @DisplayName("Update password length")
    void updatePasswordLength() {
        // Password length set by default is 12
        String password = "jkjh7834#@O0";
        Assertions.assertTrue(credentialService.passwordIsSecured(password));

        // Update password length
        credentialService.setPasswordLength(24);
        Assertions.assertFalse(credentialService.passwordIsSecured(password));

        // test secured password with 24 characters
        Assertions.assertTrue(credentialService.passwordIsSecured("jkjh7834#@O0jkjh7834#@O0"));
    }
}
