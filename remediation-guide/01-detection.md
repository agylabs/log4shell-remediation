# Phase 1: Detection

This guide covers how to detect the Log4Shell vulnerability (CVE-2021-44228) in your applications.

## Overview

The first step in remediation is identifying whether your application is vulnerable. Log4Shell affects Apache Log4j 2.x versions prior to 2.17.0.

## Quick Check: Are You Affected?

### Check Your Log4j Version

If your application uses **any** of these versions, you are vulnerable:
- Log4j 2.0-beta9 through 2.14.1 (most critical)
- Log4j 2.15.0 (partial fix, still vulnerable to CVE-2021-45046)
- Log4j 2.16.0 (vulnerable to CVE-2021-45105 DoS)

**Safe versions**: 2.17.0 and later (2.17.1+ recommended)

## Detection Methods

### Method 1: Maven Dependency Analysis

```bash
# Check for Log4j in your dependencies
cd /path/to/your/project
mvn dependency:tree | grep -i log4j

# Example output for VULNERABLE project:
# [INFO] +- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile
# [INFO] +- org.apache.logging.log4j:log4j-api:jar:2.14.1:compile
```

**Interpretation:**
- Version 2.14.1 or below = **VULNERABLE**
- Version 2.17.1+ = **SAFE**

### Method 2: Gradle Dependency Analysis

```bash
# For Gradle projects
./gradlew dependencies | grep -i log4j

# Or generate a full dependency report
./gradlew dependencyInsight --dependency log4j-core
```

### Method 3: OWASP Dependency-Check

OWASP Dependency-Check scans your dependencies for known vulnerabilities.

```bash
# Run with Maven
mvn org.owasp:dependency-check-maven:check

# The report will be generated in target/dependency-check-report.html
```

**Expected output for vulnerable project:**
```
[WARNING] One or more dependencies were identified with known vulnerabilities:

log4j-core-2.14.1.jar (pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1)
  CVE-2021-44228 - CRITICAL (CVSS: 10.0)
  CVE-2021-45046 - CRITICAL (CVSS: 9.0)
```

### Method 4: File System Scan

Search for Log4j JAR files directly:

```bash
# Linux/macOS
find / -name "log4j-core*.jar" 2>/dev/null

# Search in specific directory
find /opt/applications -name "log4j*.jar" -type f

# Check JAR version
unzip -p log4j-core-VERSION.jar META-INF/MANIFEST.MF | grep -i version
```

### Method 5: Using log4j-detector

The [log4j-detector](https://github.com/mergebase/log4j-detector) tool can scan for vulnerable versions:

```bash
# Download and run
java -jar log4j-detector.jar /path/to/scan

# Output example:
# /app/lib/log4j-core-2.14.1.jar contains Log4J-2.x   >= 2.10.0 _VULNERABLE_
```

### Method 6: Runtime Detection

Check if JNDI lookups are enabled at runtime:

```java
// Add this to your application startup for detection
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

Logger logger = LogManager.getLogger();
logger.info("Log4j version check: ${java:version}");
// If this logs the Java version, lookups are ENABLED (vulnerable)
// If this logs the literal string "${java:version}", lookups are DISABLED (safe)
```

## Automated Scanning Script

Use our provided script:

```bash
#!/bin/bash
# scripts/scan-vulnerabilities.sh

cd vulnerable/
mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7
```

## What to Look For

### Vulnerable Patterns in Code

Search for logging statements that include user input:

```bash
# Search for vulnerable logging patterns
grep -r "logger\.\(info\|warn\|error\|debug\)" --include="*.java" | grep -E "\+ |\" \+"
```

### Common Vulnerable Locations

1. **Authentication endpoints** - Logging usernames
2. **Search functionality** - Logging search queries
3. **API endpoints** - Logging request parameters
4. **Error handlers** - Logging exception messages
5. **HTTP headers** - Logging User-Agent, X-Forwarded-For, etc.

## Inventory Your Findings

Create a list of all affected components:

| Component | Log4j Version | Status | Priority |
|-----------|---------------|--------|----------|
| ecommerce-api | 2.14.1 | VULNERABLE | CRITICAL |
| payment-service | 2.14.1 | VULNERABLE | CRITICAL |
| notification-service | 2.17.1 | SAFE | - |

## Next Steps

After detecting vulnerable components:
1. Proceed to [02-analysis.md](02-analysis.md) for impact assessment
2. Prioritize critical systems for immediate remediation
3. Document all findings for tracking and reporting

## Resources

- [Apache Log4j Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html)
- [NIST CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [CISA Log4j Guidance](https://www.cisa.gov/uscert/apache-log4j-vulnerability-guidance)
