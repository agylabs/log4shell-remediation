# Phase 3: Remediation

This guide provides step-by-step instructions for remediating the Log4Shell vulnerability.

## Overview

Remediation involves multiple layers of defense:
1. **Primary Fix**: Upgrade Log4j to a patched version
2. **Code Hardening**: Sanitize user input before logging
3. **Configuration Hardening**: Disable JNDI lookups
4. **Defense in Depth**: Additional security measures

## Remediation Priority

| Priority | Action | Time to Implement |
|----------|--------|-------------------|
| 1 | Upgrade Log4j to 2.17.1+ | 1-4 hours |
| 2 | Set formatMsgNoLookups=true | 5 minutes |
| 3 | Implement input sanitization | 2-8 hours |
| 4 | Add WAF rules | 1-2 hours |
| 5 | Network egress controls | 1-4 hours |

## Step 1: Upgrade Log4j Version

### Maven Projects

**Before (vulnerable):**
```xml
<properties>
    <log4j.version>2.14.1</log4j.version>
</properties>
```

**After (patched):**
```xml
<properties>
    <!-- PATCHED: Log4j 2.17.1 is not affected by Log4Shell -->
    <log4j.version>2.17.1</log4j.version>
</properties>
```

### Force Version Override

If transitive dependencies bring in vulnerable versions:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.17.1</version>
        </dependency>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-api</artifactId>
            <version>2.17.1</version>
        </dependency>
    </dependencies>
</dependencyManagement>
```

### Gradle Projects

```groovy
// Force Log4j version
ext['log4j2.version'] = '2.17.1'

// Or explicitly set constraints
constraints {
    implementation('org.apache.logging.log4j:log4j-core:2.17.1') {
        because 'CVE-2021-44228 - Log4Shell'
    }
    implementation('org.apache.logging.log4j:log4j-api:2.17.1') {
        because 'CVE-2021-44228 - Log4Shell'
    }
}
```

### Prevent Future Regressions

Add Maven Enforcer plugin to block vulnerable versions:

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-enforcer-plugin</artifactId>
    <version>3.1.0</version>
    <executions>
        <execution>
            <id>ban-vulnerable-log4j</id>
            <goals>
                <goal>enforce</goal>
            </goals>
            <configuration>
                <rules>
                    <bannedDependencies>
                        <excludes>
                            <exclude>org.apache.logging.log4j:log4j-core:[2.0,2.17.0)</exclude>
                            <exclude>org.apache.logging.log4j:log4j-api:[2.0,2.17.0)</exclude>
                        </excludes>
                    </bannedDependencies>
                </rules>
                <fail>true</fail>
            </configuration>
        </execution>
    </executions>
</plugin>
```

## Step 2: Configuration Hardening

### Application Properties

Add to `application.properties`:

```properties
# CRITICAL: Disable JNDI lookups in log messages
log4j2.formatMsgNoLookups=true
```

### JVM Arguments

Add to startup script or container configuration:

```bash
# Primary mitigation
-Dlog4j2.formatMsgNoLookups=true

# Additional protections
-Dcom.sun.jndi.ldap.object.trustURLCodebase=false
-Dcom.sun.jndi.rmi.object.trustURLCodebase=false
```

### Log4j2.xml Configuration

```xml
<Configuration status="WARN">
    <Properties>
        <Property name="log4j2.formatMsgNoLookups">true</Property>
    </Properties>
    <!-- Rest of configuration -->
</Configuration>
```

## Step 3: Code Hardening - Input Sanitization

### Create an Input Sanitizer

```java
package com.example.ecommerce.security;

import java.util.regex.Pattern;

public class InputSanitizer {

    // Pattern to match JNDI lookup strings
    private static final Pattern JNDI_PATTERN = Pattern.compile(
        "\\$\\{[^}]*(?:jndi|env|sys|lower|upper)[^}]*\\}",
        Pattern.CASE_INSENSITIVE
    );

    // Pattern to match any ${...} lookup
    private static final Pattern ANY_LOOKUP_PATTERN = Pattern.compile(
        "\\$\\{[^}]+\\}"
    );

    /**
     * Sanitize input by removing potential JNDI injection patterns.
     */
    public static String sanitize(String input) {
        if (input == null) {
            return null;
        }
        
        // Remove dangerous patterns
        String result = input;
        result = JNDI_PATTERN.matcher(result).replaceAll("[REMOVED]");
        result = ANY_LOOKUP_PATTERN.matcher(result).replaceAll("[REMOVED]");
        
        return result;
    }

    /**
     * Check if input contains suspicious patterns.
     */
    public static boolean containsSuspiciousPatterns(String input) {
        if (input == null) return false;
        return JNDI_PATTERN.matcher(input).find() || 
               ANY_LOOKUP_PATTERN.matcher(input).find();
    }
}
```

### Update Controllers

**Before (vulnerable):**
```java
@GetMapping("/search")
public ResponseEntity<?> searchProducts(@RequestParam String query) {
    // VULNERABLE: User input logged directly
    logger.info("Search query: " + query);
    return productService.search(query);
}
```

**After (secured):**
```java
@GetMapping("/search")
public ResponseEntity<?> searchProducts(@RequestParam String query) {
    // SECURED: Sanitize input before logging
    String sanitizedQuery = InputSanitizer.sanitize(query);
    
    // Check for attack attempts
    if (InputSanitizer.containsSuspiciousPatterns(query)) {
        logger.warn("SECURITY: Suspicious pattern detected in search query");
    }
    
    // Use parameterized logging
    logger.info("Search query: {}", sanitizedQuery);
    
    return productService.search(query);
}
```

### Use Parameterized Logging

**Before:**
```java
logger.info("User " + username + " logged in from " + ipAddress);
```

**After:**
```java
logger.info("User {} logged in from {}", 
    InputSanitizer.sanitize(username), 
    InputSanitizer.sanitize(ipAddress));
```

## Step 4: Emergency Workarounds

If you cannot immediately upgrade, apply these temporary mitigations:

### Option A: Remove JndiLookup Class

```bash
# Remove the vulnerable class from the JAR
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```

### Option B: Environment Variable (Log4j 2.10+)

```bash
export LOG4J_FORMAT_MSG_NO_LOOKUPS=true
```

### Option C: Set System Property at Startup

```bash
java -Dlog4j2.formatMsgNoLookups=true -jar application.jar
```

## Step 5: Build and Verify

### Rebuild the Application

```bash
# Clean build
mvn clean package

# Verify Log4j version
mvn dependency:tree | grep log4j
# Should show: log4j-core:jar:2.17.1
```

### Run Dependency Check

```bash
mvn org.owasp:dependency-check-maven:check

# Should report: No vulnerabilities found for Log4j
```

## Remediation Checklist

- [ ] Updated Log4j to version 2.17.1 or later
- [ ] Added `log4j2.formatMsgNoLookups=true` to configuration
- [ ] Added JVM arguments for JNDI restrictions
- [ ] Implemented InputSanitizer utility class
- [ ] Updated all controllers to sanitize input
- [ ] Added Maven Enforcer to prevent version regression
- [ ] Verified no vulnerable versions in dependency tree
- [ ] Ran OWASP Dependency-Check with passing results
- [ ] Tested application functionality after changes

## Common Issues and Solutions

### Issue: Transitive Dependency Still Vulnerable

**Solution:** Use `<dependencyManagement>` to force version:
```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.17.1</version>
        </dependency>
    </dependencies>
</dependencyManagement>
```

### Issue: Application Fails After Upgrade

**Solution:** Check for API changes between Log4j versions:
- Review [Log4j 2.17.1 Release Notes](https://logging.apache.org/log4j/2.x/changes-report.html)
- Update any deprecated API usage

### Issue: Cannot Upgrade Due to Compatibility

**Solution:** Apply temporary workarounds:
1. Set `log4j2.formatMsgNoLookups=true`
2. Remove JndiLookup class from JAR
3. Block JNDI protocols at network level

## Next Steps

After completing remediation:
1. Proceed to [04-validation.md](04-validation.md) to verify the fix
2. Document all changes made
3. Update incident response records

## Resources

- [Apache Log4j 2.17.1 Download](https://logging.apache.org/log4j/2.x/download.html)
- [Log4j Migration Guide](https://logging.apache.org/log4j/2.x/manual/migration.html)
