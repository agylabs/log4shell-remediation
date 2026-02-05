#!/bin/bash
#
# Log4Shell Remediation Validation Script
# Validates that the fix was properly applied
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS_COUNT=0
FAIL_COUNT=0

echo "=============================================="
echo "    Log4Shell Remediation Validation"
echo "=============================================="
echo ""

# Function to check a validation condition
check() {
    local name=$1
    local condition=$2
    
    printf "%-50s" "$name"
    
    if eval "$condition"; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((PASS_COUNT++))
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((FAIL_COUNT++))
    fi
}

cd "$PROJECT_ROOT/remediated"

echo "========================================="
echo "Dependency Validation"
echo "========================================="

# Check 1: pom.xml exists
check "pom.xml exists" "[ -f pom.xml ]"

# Check 2: Log4j version is 2.17.1+
check "Log4j version is 2.17.1 or later" \
    "grep -q '<log4j.version>2\\.17\\.[0-9]\\+</log4j.version>\\|<log4j.version>2\\.1[8-9]\\.[0-9]\\+</log4j.version>\\|<log4j.version>2\\.[2-9][0-9]\\.[0-9]\\+</log4j.version>' pom.xml"

# Check 3: Maven Enforcer plugin configured
check "Maven Enforcer plugin configured" \
    "grep -q 'maven-enforcer-plugin' pom.xml"

# Check 4: Banned dependencies rule exists
check "Banned vulnerable Log4j versions" \
    "grep -q 'log4j-core:\\[2.0,2.17.0)' pom.xml"

echo ""
echo "========================================="
echo "Configuration Validation"
echo "========================================="

# Check 5: application.properties has security setting
check "formatMsgNoLookups enabled" \
    "grep -q 'log4j2.formatMsgNoLookups=true' src/main/resources/application.properties"

# Check 6: Hardened log4j2.xml exists
check "Hardened log4j2.xml exists" \
    "[ -f src/main/resources/log4j2.xml ]"

# Check 7: Security config exists
check "Defense-in-depth config exists" \
    "[ -f security-configs/security-config.xml ]"

echo ""
echo "========================================="
echo "Code Validation"
echo "========================================="

# Check 8: InputSanitizer exists
check "InputSanitizer.java exists" \
    "[ -f src/main/java/com/example/ecommerce/security/InputSanitizer.java ]"

# Check 9: InputSanitizer is used in controllers
check "InputSanitizer used in ProductController" \
    "grep -q 'InputSanitizer' src/main/java/com/example/ecommerce/controller/ProductController.java"

check "InputSanitizer used in OrderController" \
    "grep -q 'InputSanitizer' src/main/java/com/example/ecommerce/controller/OrderController.java"

check "InputSanitizer used in AuthController" \
    "grep -q 'InputSanitizer' src/main/java/com/example/ecommerce/controller/AuthController.java"

# Check 10: No vulnerable patterns in remediated code
VULN_PATTERNS=$(grep -rn 'logger\.\(info\|warn\|error\|debug\).*+" *+' \
    --include="*.java" src/main/java/com/example/ecommerce/controller/ 2>/dev/null | wc -l || echo "0")
check "No string concatenation in controller logs" \
    "[ '$VULN_PATTERNS' -eq '0' ]"

echo ""
echo "========================================="
echo "Build Validation"
echo "========================================="

# Check 11: Project compiles successfully
printf "%-50s" "Project compiles successfully"
if mvn compile -q 2>/dev/null; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS_COUNT++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL_COUNT++))
fi

echo ""
echo "=============================================="
echo "    Validation Results"
echo "=============================================="
echo ""
echo -e "Passed: ${GREEN}$PASS_COUNT${NC}"
echo -e "Failed: ${RED}$FAIL_COUNT${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}  All validations passed!${NC}"
    echo -e "${GREEN}  The remediation is complete.${NC}"
    echo -e "${GREEN}=========================================${NC}"
    exit 0
else
    echo -e "${RED}=========================================${NC}"
    echo -e "${RED}  Some validations failed!${NC}"
    echo -e "${RED}  Please review and fix the issues above.${NC}"
    echo -e "${RED}=========================================${NC}"
    echo ""
    echo "For remediation steps, see:"
    echo "  remediation-guide/03-remediation.md"
    exit 1
fi
