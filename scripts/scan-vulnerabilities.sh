#!/bin/bash
#
# Log4Shell Vulnerability Scanner
# Scans the project for Log4j dependencies and known vulnerabilities
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=============================================="
echo "    Log4Shell Vulnerability Scanner"
echo "=============================================="
echo ""

# Function to check Log4j version in a directory
scan_directory() {
    local dir=$1
    local name=$2
    
    if [ ! -d "$dir" ]; then
        echo -e "${YELLOW}⚠ Directory $name not found, skipping...${NC}"
        return
    fi
    
    echo "Scanning $name..."
    cd "$dir"
    
    # Check if pom.xml exists
    if [ ! -f "pom.xml" ]; then
        echo -e "${YELLOW}  ⚠ No pom.xml found in $name${NC}"
        cd "$PROJECT_ROOT"
        return
    fi
    
    # Get Log4j version from dependency tree
    echo "  Checking dependency tree..."
    LOG4J_DEPS=$(mvn dependency:tree -DoutputType=dot 2>/dev/null | grep -i "log4j" || true)
    
    if [ -z "$LOG4J_DEPS" ]; then
        echo -e "  ${YELLOW}⚠ No Log4j dependencies found${NC}"
        cd "$PROJECT_ROOT"
        return
    fi
    
    # Check for vulnerable versions
    VULNERABLE=false
    while IFS= read -r line; do
        if echo "$line" | grep -qE "log4j-(core|api).*:(2\.([0-9]|1[0-6])\.[0-9]+|2\.14\.[0-1])"; then
            echo -e "  ${RED}✗ VULNERABLE: $line${NC}"
            VULNERABLE=true
        elif echo "$line" | grep -qE "log4j-(core|api).*(2\.17\.[0-9]+|2\.1[8-9]\.[0-9]+|2\.[2-9][0-9]\.[0-9]+)"; then
            echo -e "  ${GREEN}✓ SAFE: $line${NC}"
        fi
    done <<< "$LOG4J_DEPS"
    
    if [ "$VULNERABLE" = true ]; then
        echo -e "  ${RED}STATUS: VULNERABLE - Remediation required!${NC}"
    else
        echo -e "  ${GREEN}STATUS: SAFE${NC}"
    fi
    
    cd "$PROJECT_ROOT"
    echo ""
}

# Function to run OWASP Dependency-Check
run_owasp_check() {
    local dir=$1
    local name=$2
    
    if [ ! -d "$dir" ]; then
        return
    fi
    
    echo "Running OWASP Dependency-Check on $name..."
    cd "$dir"
    
    if [ ! -f "pom.xml" ]; then
        cd "$PROJECT_ROOT"
        return
    fi
    
    # Run dependency check
    mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7 2>/dev/null
    RESULT=$?
    
    if [ $RESULT -eq 0 ]; then
        echo -e "  ${GREEN}✓ OWASP Dependency-Check passed${NC}"
    else
        echo -e "  ${RED}✗ OWASP Dependency-Check found vulnerabilities${NC}"
        echo "  Check target/dependency-check-report.html for details"
    fi
    
    cd "$PROJECT_ROOT"
    echo ""
}

# Scan vulnerable application
echo "========================================="
echo "Phase 1: Scanning Vulnerable Application"
echo "========================================="
scan_directory "$PROJECT_ROOT/vulnerable" "vulnerable/"

# Scan remediated application
echo "=========================================="
echo "Phase 2: Scanning Remediated Application"
echo "=========================================="
scan_directory "$PROJECT_ROOT/remediated" "remediated/"

# Ask user if they want to run OWASP checks
echo ""
read -p "Run OWASP Dependency-Check? This may take several minutes. (y/N): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "========================================="
    echo "Phase 3: OWASP Dependency-Check"
    echo "========================================="
    run_owasp_check "$PROJECT_ROOT/vulnerable" "vulnerable/"
    run_owasp_check "$PROJECT_ROOT/remediated" "remediated/"
fi

# Search for vulnerable code patterns
echo ""
echo "========================================="
echo "Phase 4: Scanning for Vulnerable Patterns"
echo "========================================="

echo "Searching for vulnerable logging patterns in vulnerable/..."
VULN_PATTERNS=$(grep -rn 'logger\.\(info\|warn\|error\|debug\).*+' \
    --include="*.java" "$PROJECT_ROOT/vulnerable/src" 2>/dev/null | wc -l || echo "0")

if [ "$VULN_PATTERNS" -gt 0 ]; then
    echo -e "  ${RED}✗ Found $VULN_PATTERNS potentially vulnerable logging patterns${NC}"
    grep -rn 'logger\.\(info\|warn\|error\|debug\).*+' \
        --include="*.java" "$PROJECT_ROOT/vulnerable/src" 2>/dev/null | head -5
    echo "  ..."
else
    echo -e "  ${GREEN}✓ No vulnerable patterns found${NC}"
fi

echo ""
echo "Searching for sanitized logging patterns in remediated/..."
SANITIZED=$(grep -rn 'InputSanitizer' \
    --include="*.java" "$PROJECT_ROOT/remediated/src" 2>/dev/null | wc -l || echo "0")

if [ "$SANITIZED" -gt 0 ]; then
    echo -e "  ${GREEN}✓ Found $SANITIZED uses of InputSanitizer${NC}"
else
    echo -e "  ${YELLOW}⚠ No InputSanitizer usage found${NC}"
fi

echo ""
echo "=============================================="
echo "    Scan Complete"
echo "=============================================="
echo ""
echo "For detailed remediation steps, see:"
echo "  - remediation-guide/01-detection.md"
echo "  - remediation-guide/02-analysis.md"
echo "  - remediation-guide/03-remediation.md"
echo ""
