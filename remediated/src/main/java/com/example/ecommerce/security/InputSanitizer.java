package com.example.ecommerce.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Input Sanitizer for preventing JNDI injection attacks.
 * 
 * This utility class provides methods to sanitize user input before logging
 * to prevent Log4Shell (CVE-2021-44228) and similar injection attacks.
 * 
 * Security measures implemented:
 * 1. Remove all JNDI lookup patterns (${jndi:...})
 * 2. Remove nested lookup patterns (${...${...}...})
 * 3. Remove environment variable lookups (${env:...})
 * 4. Remove system property lookups (${sys:...})
 * 5. Encode special characters that could be used for obfuscation
 */
@Component
public class InputSanitizer {

    private static final Logger logger = LogManager.getLogger(InputSanitizer.class);

    // Pattern to match JNDI lookup strings and variations
    private static final Pattern JNDI_PATTERN = Pattern.compile(
            "\\$\\{[^}]*(?:jndi|env|sys|lower|upper|date|java|main|ctx|log4j|marker|" +
                    "bundle|map|sd|mdc|ndc|web|docker|kubernetes|spring)[^}]*\\}",
            Pattern.CASE_INSENSITIVE);

    // Pattern to match any nested lookup pattern
    private static final Pattern NESTED_LOOKUP_PATTERN = Pattern.compile(
            "\\$\\{[^}]*\\$\\{[^}]*\\}[^}]*\\}",
            Pattern.CASE_INSENSITIVE);

    // Pattern to match any ${...} lookup pattern (most aggressive)
    private static final Pattern ANY_LOOKUP_PATTERN = Pattern.compile(
            "\\$\\{[^}]+\\}");

    // Pattern to match obfuscated patterns like ${::-j}
    private static final Pattern OBFUSCATED_PATTERN = Pattern.compile(
            "\\$\\{[^}]*::-[^}]*\\}",
            Pattern.CASE_INSENSITIVE);

    /**
     * Sanitize input by removing all potential JNDI injection patterns.
     * This is the recommended method for sanitizing user input before logging.
     *
     * @param input The user input to sanitize
     * @return Sanitized input safe for logging
     */
    public static String sanitize(String input) {
        if (input == null) {
            return null;
        }

        String result = input;

        // Remove obfuscated patterns first
        result = OBFUSCATED_PATTERN.matcher(result).replaceAll("[REMOVED]");

        // Remove nested lookup patterns (may need multiple passes)
        int iterations = 0;
        String previous;
        do {
            previous = result;
            result = NESTED_LOOKUP_PATTERN.matcher(result).replaceAll("[REMOVED]");
            iterations++;
        } while (!result.equals(previous) && iterations < 10);

        // Remove JNDI and other dangerous patterns
        result = JNDI_PATTERN.matcher(result).replaceAll("[REMOVED]");

        // Final pass: remove any remaining ${...} patterns
        result = ANY_LOOKUP_PATTERN.matcher(result).replaceAll("[REMOVED]");

        // Log if sanitization was applied
        if (!result.equals(input)) {
            logger.warn("Potentially malicious input sanitized. Original length: {}, Sanitized length: {}",
                    input.length(), result.length());
        }

        return result;
    }

    /**
     * Sanitize input with additional logging of the sanitization action.
     * Useful for audit trails and security monitoring.
     *
     * @param input   The user input to sanitize
     * @param context Description of where this input came from (e.g., "search
     *                query", "username")
     * @return Sanitized input safe for logging
     */
    public static String sanitizeWithAudit(String input, String context) {
        if (input == null) {
            return null;
        }

        String sanitized = sanitize(input);

        if (!sanitized.equals(input)) {
            logger.warn("SECURITY ALERT: Potential injection attempt detected in {}. " +
                    "Input contained suspicious patterns that were removed.", context);
        }

        return sanitized;
    }

    /**
     * Check if input contains potential injection patterns without modifying it.
     * Useful for validation and alerting without changing the input.
     *
     * @param input The input to check
     * @return true if the input contains suspicious patterns
     */
    public static boolean containsSuspiciousPatterns(String input) {
        if (input == null) {
            return false;
        }

        return JNDI_PATTERN.matcher(input).find() ||
                NESTED_LOOKUP_PATTERN.matcher(input).find() ||
                OBFUSCATED_PATTERN.matcher(input).find() ||
                ANY_LOOKUP_PATTERN.matcher(input).find();
    }

    /**
     * Escape special characters that could be used in Log4j lookups.
     * This is a more conservative approach that preserves the input
     * while making it safe for logging.
     *
     * @param input The input to escape
     * @return Escaped input ($ and { replaced with unicode escapes)
     */
    public static String escape(String input) {
        if (input == null) {
            return null;
        }

        // Replace $ and { with their unicode representations
        return input
                .replace("$", "\\u0024")
                .replace("{", "\\u007B")
                .replace("}", "\\u007D");
    }

    /**
     * Truncate input to a maximum length for safe logging.
     * This helps prevent log flooding and reduces potential attack surface.
     *
     * @param input     The input to truncate
     * @param maxLength Maximum length of the output
     * @return Truncated and sanitized input
     */
    public static String truncateAndSanitize(String input, int maxLength) {
        if (input == null) {
            return null;
        }

        String sanitized = sanitize(input);

        if (sanitized.length() > maxLength) {
            return sanitized.substring(0, maxLength) + "...[TRUNCATED]";
        }

        return sanitized;
    }
}
