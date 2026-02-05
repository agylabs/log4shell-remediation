package com.example.ecommerce.controller;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * REST Controller for Authentication operations.
 * 
 * WARNING: This controller contains VULNERABLE logging patterns that are
 * susceptible to CVE-2021-44228 (Log4Shell). Authentication details and user
 * input are logged directly without sanitization.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LogManager.getLogger(AuthController.class);

    /**
     * User login endpoint.
     * 
     * VULNERABLE: Username and other login details are logged without sanitization.
     * An attacker can inject malicious JNDI lookup strings in the username field.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        // VULNERABLE: Username logged directly - allows JNDI injection
        logger.info("Login attempt for user: " + username);

        // Simulate authentication (in real app, this would verify credentials)
        boolean authenticated = authenticateUser(username, password);

        if (authenticated) {
            logger.info("User logged in successfully: " + username);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Login successful");
            response.put("token", "mock-jwt-token-" + System.currentTimeMillis());

            return ResponseEntity.ok(response);
        } else {
            // VULNERABLE: Failed login with username logged
            logger.warn("Failed login attempt for user: " + username);

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Invalid credentials");

            return ResponseEntity.status(401).body(response);
        }
    }

    /**
     * User registration endpoint.
     * 
     * VULNERABLE: All user-provided registration data is logged without
     * sanitization.
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, String> userData) {
        String username = userData.get("username");
        String email = userData.get("email");
        String firstName = userData.get("firstName");
        String lastName = userData.get("lastName");

        // VULNERABLE: All user input logged directly
        logger.info("New user registration: " + username);
        logger.info("Email: " + email);
        logger.info("Name: " + firstName + " " + lastName);

        // Simulate registration
        boolean registered = registerUser(userData);

        if (registered) {
            logger.info("User registered successfully: " + username);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Registration successful");

            return ResponseEntity.ok(response);
        } else {
            logger.warn("Registration failed for user: " + username);

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Registration failed");

            return ResponseEntity.badRequest().body(response);
        }
    }

    /**
     * Password reset request endpoint.
     * 
     * VULNERABLE: Email address logged without sanitization.
     */
    @PostMapping("/password-reset")
    public ResponseEntity<Map<String, Object>> requestPasswordReset(@RequestBody Map<String, String> request) {
        String email = request.get("email");

        // VULNERABLE: Email from user input logged directly
        logger.info("Password reset requested for: " + email);

        // Simulate sending password reset email
        boolean sent = sendPasswordResetEmail(email);

        if (sent) {
            logger.info("Password reset email sent to: " + email);
        } else {
            logger.warn("Failed to send password reset email to: " + email);
        }

        // Always return success to prevent email enumeration
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "If the email exists, a password reset link will be sent");

        return ResponseEntity.ok(response);
    }

    /**
     * Password reset confirmation endpoint.
     * 
     * VULNERABLE: Reset token logged without sanitization.
     */
    @PostMapping("/password-reset/confirm")
    public ResponseEntity<Map<String, Object>> confirmPasswordReset(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String newPassword = request.get("newPassword");

        // VULNERABLE: Token from user input logged directly
        logger.info("Password reset confirmation with token: " + token);

        // Simulate password reset
        boolean reset = resetPassword(token, newPassword);

        Map<String, Object> response = new HashMap<>();
        if (reset) {
            logger.info("Password reset successful for token: " + token);
            response.put("success", true);
            response.put("message", "Password reset successful");
            return ResponseEntity.ok(response);
        } else {
            logger.warn("Password reset failed for token: " + token);
            response.put("success", false);
            response.put("message", "Invalid or expired token");
            return ResponseEntity.badRequest().body(response);
        }
    }

    /**
     * User logout endpoint.
     * 
     * VULNERABLE: Session information logged without sanitization.
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestHeader(value = "X-Session-Id", required = false) String sessionId) {

        // VULNERABLE: Headers from user input logged directly
        logger.info("Logout request with session: " + sessionId);
        logger.debug("Authorization header: " + authHeader);

        // Simulate logout
        invalidateSession(sessionId);

        logger.info("User logged out successfully, session invalidated: " + sessionId);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Logged out successfully");

        return ResponseEntity.ok(response);
    }

    /**
     * Change password endpoint.
     * 
     * VULNERABLE: Username logged without sanitization.
     */
    @PostMapping("/change-password")
    public ResponseEntity<Map<String, Object>> changePassword(
            @RequestBody Map<String, String> request,
            @RequestHeader(value = "X-Username", required = false) String username) {

        // VULNERABLE: Username from header logged directly
        logger.info("Password change request for user: " + username);

        String currentPassword = request.get("currentPassword");
        String newPassword = request.get("newPassword");

        // Simulate password change
        boolean changed = changeUserPassword(username, currentPassword, newPassword);

        Map<String, Object> response = new HashMap<>();
        if (changed) {
            logger.info("Password changed successfully for user: " + username);
            response.put("success", true);
            response.put("message", "Password changed successfully");
            return ResponseEntity.ok(response);
        } else {
            logger.warn("Password change failed for user: " + username);
            response.put("success", false);
            response.put("message", "Current password is incorrect");
            return ResponseEntity.badRequest().body(response);
        }
    }

    // Simulated helper methods (in real app, these would interact with a database)

    private boolean authenticateUser(String username, String password) {
        // Simulate authentication - always returns true for demo
        return username != null && password != null && password.length() >= 6;
    }

    private boolean registerUser(Map<String, String> userData) {
        // Simulate registration - always returns true for demo
        return userData.get("username") != null && userData.get("email") != null;
    }

    private boolean sendPasswordResetEmail(String email) {
        // Simulate sending email - always returns true for demo
        return email != null && email.contains("@");
    }

    private boolean resetPassword(String token, String newPassword) {
        // Simulate password reset - always returns true for demo
        return token != null && newPassword != null && newPassword.length() >= 6;
    }

    private void invalidateSession(String sessionId) {
        // Simulate session invalidation
        logger.debug("Invalidating session: " + sessionId);
    }

    private boolean changeUserPassword(String username, String currentPassword, String newPassword) {
        // Simulate password change - always returns true for demo
        return username != null && currentPassword != null && newPassword != null;
    }
}
