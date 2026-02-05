package com.example.ecommerce.controller;

import com.example.ecommerce.security.InputSanitizer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * REST Controller for Authentication operations (REMEDIATED).
 * 
 * Security improvements:
 * 1. All user input is sanitized before logging using InputSanitizer
 * 2. Parameterized logging is used instead of string concatenation
 * 3. Suspicious patterns trigger security alerts
 * 4. Sensitive data (passwords) are never logged
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LogManager.getLogger(AuthController.class);

    /**
     * User login endpoint.
     * 
     * SECURED: Username is sanitized before logging.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        // SECURED: Sanitize username before logging
        String sanitizedUsername = InputSanitizer.sanitizeWithAudit(username, "login username");

        // Check for injection attempts
        if (InputSanitizer.containsSuspiciousPatterns(username)) {
            logger.warn("SECURITY ALERT: Potential injection attack in login attempt");
        }

        logger.info("Login attempt for user: {}", sanitizedUsername);

        // Simulate authentication
        boolean authenticated = authenticateUser(username, password);

        if (authenticated) {
            logger.info("User logged in successfully: {}", sanitizedUsername);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Login successful");
            response.put("token", "mock-jwt-token-" + System.currentTimeMillis());

            return ResponseEntity.ok(response);
        } else {
            // SECURED: Using parameterized logging
            logger.warn("Failed login attempt for user: {}", sanitizedUsername);

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Invalid credentials");

            return ResponseEntity.status(401).body(response);
        }
    }

    /**
     * User registration endpoint.
     * 
     * SECURED: All user-provided data is sanitized before logging.
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, String> userData) {
        String username = userData.get("username");
        String email = userData.get("email");
        String firstName = userData.get("firstName");
        String lastName = userData.get("lastName");

        // SECURED: Sanitize all user input
        String sanitizedUsername = InputSanitizer.sanitize(username);
        String sanitizedEmail = InputSanitizer.sanitize(email);
        String sanitizedFirstName = InputSanitizer.sanitize(firstName);
        String sanitizedLastName = InputSanitizer.sanitize(lastName);

        // Check for injection attempts
        if (InputSanitizer.containsSuspiciousPatterns(username) ||
                InputSanitizer.containsSuspiciousPatterns(email)) {
            logger.warn("SECURITY ALERT: Potential injection attack in registration");
        }

        logger.info("New user registration: {}", sanitizedUsername);
        logger.info("Email: {}", sanitizedEmail);
        logger.info("Name: {} {}", sanitizedFirstName, sanitizedLastName);

        // Simulate registration
        boolean registered = registerUser(userData);

        if (registered) {
            logger.info("User registered successfully: {}", sanitizedUsername);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Registration successful");

            return ResponseEntity.ok(response);
        } else {
            logger.warn("Registration failed for user: {}", sanitizedUsername);

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Registration failed");

            return ResponseEntity.badRequest().body(response);
        }
    }

    /**
     * Password reset request endpoint.
     * 
     * SECURED: Email address is sanitized before logging.
     */
    @PostMapping("/password-reset")
    public ResponseEntity<Map<String, Object>> requestPasswordReset(@RequestBody Map<String, String> request) {
        String email = request.get("email");

        // SECURED: Sanitize email
        String sanitizedEmail = InputSanitizer.sanitizeWithAudit(email, "password reset email");
        logger.info("Password reset requested for: {}", sanitizedEmail);

        // Simulate sending password reset email
        boolean sent = sendPasswordResetEmail(email);

        if (sent) {
            logger.info("Password reset email sent to: {}", sanitizedEmail);
        } else {
            logger.warn("Failed to send password reset email to: {}", sanitizedEmail);
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
     * SECURED: Reset token is sanitized before logging (tokens may be sensitive).
     */
    @PostMapping("/password-reset/confirm")
    public ResponseEntity<Map<String, Object>> confirmPasswordReset(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String newPassword = request.get("newPassword");

        // SECURED: Sanitize token (partial logging for security)
        String sanitizedToken = InputSanitizer.sanitize(token);
        String maskedToken = sanitizedToken.length() > 8
                ? sanitizedToken.substring(0, 4) + "..." + sanitizedToken.substring(sanitizedToken.length() - 4)
                : "***";

        logger.info("Password reset confirmation with token: {}", maskedToken);

        // Simulate password reset
        boolean reset = resetPassword(token, newPassword);

        Map<String, Object> response = new HashMap<>();
        if (reset) {
            logger.info("Password reset successful for token: {}", maskedToken);
            response.put("success", true);
            response.put("message", "Password reset successful");
            return ResponseEntity.ok(response);
        } else {
            logger.warn("Password reset failed for token: {}", maskedToken);
            response.put("success", false);
            response.put("message", "Invalid or expired token");
            return ResponseEntity.badRequest().body(response);
        }
    }

    /**
     * User logout endpoint.
     * 
     * SECURED: Session information is sanitized before logging.
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestHeader(value = "X-Session-Id", required = false) String sessionId) {

        // SECURED: Sanitize headers
        String sanitizedSessionId = InputSanitizer.sanitize(sessionId);

        // Check for injection attempts in headers
        if (InputSanitizer.containsSuspiciousPatterns(sessionId) ||
                InputSanitizer.containsSuspiciousPatterns(authHeader)) {
            logger.warn("SECURITY ALERT: Suspicious patterns detected in logout headers");
        }

        logger.info("Logout request with session: {}", sanitizedSessionId);
        // Note: Authorization header is not logged as it contains sensitive data

        // Simulate logout
        invalidateSession(sessionId);

        logger.info("User logged out successfully, session invalidated: {}", sanitizedSessionId);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Logged out successfully");

        return ResponseEntity.ok(response);
    }

    /**
     * Change password endpoint.
     * 
     * SECURED: Username is sanitized before logging.
     */
    @PostMapping("/change-password")
    public ResponseEntity<Map<String, Object>> changePassword(
            @RequestBody Map<String, String> request,
            @RequestHeader(value = "X-Username", required = false) String username) {

        // SECURED: Sanitize username header
        String sanitizedUsername = InputSanitizer.sanitizeWithAudit(username, "change password username");
        logger.info("Password change request for user: {}", sanitizedUsername);

        String currentPassword = request.get("currentPassword");
        String newPassword = request.get("newPassword");

        // Simulate password change
        boolean changed = changeUserPassword(username, currentPassword, newPassword);

        Map<String, Object> response = new HashMap<>();
        if (changed) {
            logger.info("Password changed successfully for user: {}", sanitizedUsername);
            response.put("success", true);
            response.put("message", "Password changed successfully");
            return ResponseEntity.ok(response);
        } else {
            logger.warn("Password change failed for user: {}", sanitizedUsername);
            response.put("success", false);
            response.put("message", "Current password is incorrect");
            return ResponseEntity.badRequest().body(response);
        }
    }

    // Simulated helper methods

    private boolean authenticateUser(String username, String password) {
        return username != null && password != null && password.length() >= 6;
    }

    private boolean registerUser(Map<String, String> userData) {
        return userData.get("username") != null && userData.get("email") != null;
    }

    private boolean sendPasswordResetEmail(String email) {
        return email != null && email.contains("@");
    }

    private boolean resetPassword(String token, String newPassword) {
        return token != null && newPassword != null && newPassword.length() >= 6;
    }

    private void invalidateSession(String sessionId) {
        logger.debug("Invalidating session: {}", InputSanitizer.sanitize(sessionId));
    }

    private boolean changeUserPassword(String username, String currentPassword, String newPassword) {
        return username != null && currentPassword != null && newPassword != null;
    }
}
