package fr.fernandes.will.security.service;

import java.sql.Date;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.UUID;

import com.password4j.Hash;
import com.password4j.Password;
import fr.fernandes.will.security.util.StringManager;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;

public class CredentialService {
    private static final String EMAIL_REGEX = "^\\w+([\\.-]?\\w+)*@\\w+([\\.-]?\\w+)*(\\.\\w{2,3})+$";
    private int passwordLength;

    private CredentialService() {
        passwordLength = 12;
    }

    /**
     * Getter for Credential instance
     *
     * @return Credential instance
     */
    public static CredentialService getInstance() {
        return InstanceHolder.INSTANCE;
    }

    /**
     * Update min length password
     *
     * @param passwordLength new password length
     */
    public void setPasswordLength(int passwordLength) {
        this.passwordLength = passwordLength;
    }

    /**
     * Hash value sends in argon 2 ID
     *
     * @param clearValue data we want to hash
     * @return data hashed
     */
    public String hash(String clearValue) {
        clearValue = StringManager.removeSpaces(clearValue);
        Hash hash = Password.hash(clearValue).addRandomSalt().withArgon2();
        return hash.getResult();
    }

    /**
     * Check clear value match with hashed
     *
     * @param clearValue value in clear
     * @param hashedValue hashed value
     * @return true if values are equals, false if not
     */
    public boolean checkMatch(String hashedValue, String clearValue) {
        return Password.check(clearValue, hashedValue).withArgon2();
    }

    /**
     * Check if an email is valid
     *
     * @param email to check
     * @return true if email is valid | false if not
     */
    public boolean isValidEmail(String email) {
        // Remove spaces
        email = StringManager.removeSpaces(email);

        // Check if email is valid
        return !email.isBlank() && email.matches(EMAIL_REGEX);
    }

    /**
     * Generate a JWT token
     *
     * @param properties Strings with all necessary value for generate a secured token. Example of string: "role=admin"
     * @return Generated token
     */
    public String generateToken(String... properties) {
        // Get jwt builder
        JwtBuilder builder = Jwts.builder();

        // Set properties into token
        String[] split;
        for (String claim : properties) {
            // Remove space
            claim = StringManager.removeSpaces(claim);

            split = claim.split("=", -1);
            builder.claim(split[0], split[1]);
        }

        // Return jwt token
        return builder.claim("createdAt", Date.valueOf(LocalDate.now(ZoneId.systemDefault())))
                .subject("Security Token")
                .id(UUID.randomUUID().toString())
                .compact();
    }

    /**
     * Check if password is secured
     *
     * @param password password to check
     * @return True if password is secured
     */
    public boolean passwordIsSecured(String password) {
        password = StringManager.removeSpaces(password);

        return !password.isBlank()
                && password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$_%^&+=]).{" + passwordLength + ",}$");
    }

    /** Instance holder */
    private static final class InstanceHolder {
        private static final CredentialService INSTANCE = new CredentialService();
    }
}
