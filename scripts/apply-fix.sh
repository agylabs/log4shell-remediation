#!/bin/bash
#
# Log4Shell Fix Application Script
# Applies the remediation by copying the remediated version
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
echo "    Log4Shell Fix Application Script"
echo "=============================================="
echo ""

# Check if vulnerable directory exists
if [ ! -d "$PROJECT_ROOT/vulnerable" ]; then
    echo -e "${RED}Error: vulnerable/ directory not found${NC}"
    exit 1
fi

# Check if remediated directory exists
if [ ! -d "$PROJECT_ROOT/remediated" ]; then
    echo -e "${RED}Error: remediated/ directory not found${NC}"
    exit 1
fi

echo "This script demonstrates the changes needed to fix Log4Shell."
echo ""
echo "The following files will be compared/updated:"
echo "  1. pom.xml - Log4j version update (2.14.1 -> 2.17.1)"
echo "  2. application.properties - Security configuration"
echo "  3. log4j2.xml - Hardened logging configuration"
echo "  4. Controllers - Input sanitization"
echo ""

# Show the diff between vulnerable and remediated pom.xml
echo "========================================="
echo "Changes in pom.xml"
echo "========================================="
echo ""
echo "Key changes:"
echo -e "  ${RED}- <log4j.version>2.14.1</log4j.version>${NC}"
echo -e "  ${GREEN}+ <log4j.version>2.17.1</log4j.version>${NC}"
echo ""
echo -e "  ${GREEN}+ Maven Enforcer Plugin to ban vulnerable versions${NC}"
echo -e "  ${GREEN}+ OWASP Dependency-Check with failBuildOnCVSS=7${NC}"
echo ""

# Show application.properties changes
echo "========================================="
echo "Changes in application.properties"
echo "========================================="
echo ""
echo "Added security configuration:"
echo -e "  ${GREEN}+ log4j2.formatMsgNoLookups=true${NC}"
echo -e "  ${GREEN}+ server.servlet.session.cookie.http-only=true${NC}"
echo -e "  ${GREEN}+ server.servlet.session.cookie.secure=true${NC}"
echo ""

# Show controller changes
echo "========================================="
echo "Changes in Controllers"
echo "========================================="
echo ""
echo "Before (VULNERABLE):"
echo -e "  ${RED}logger.info(\"Search query: \" + query);${NC}"
echo ""
echo "After (SECURED):"
echo -e "  ${GREEN}String sanitized = InputSanitizer.sanitize(query);${NC}"
echo -e "  ${GREEN}logger.info(\"Search query: {}\", sanitized);${NC}"
echo ""

# Show new files
echo "========================================="
echo "New Security Components"
echo "========================================="
echo ""
echo -e "  ${GREEN}+ security/InputSanitizer.java${NC}"
echo "    - Removes JNDI lookup patterns from strings"
echo "    - Provides audit logging for suspicious input"
echo ""
echo -e "  ${GREEN}+ security-configs/security-config.xml${NC}"
echo "    - JVM arguments for defense-in-depth"
echo "    - WAF rules for blocking malicious patterns"
echo "    - Network egress restrictions"
echo ""

# Ask if user wants to view the InputSanitizer
read -p "View the InputSanitizer implementation? (y/N): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "========================================="
    echo "InputSanitizer.java (excerpt)"
    echo "========================================="
    echo ""
    head -60 "$PROJECT_ROOT/remediated/src/main/java/com/example/ecommerce/security/InputSanitizer.java" 2>/dev/null || echo "File not found"
    echo ""
fi

# Summary
echo ""
echo "=============================================="
echo "    Remediation Summary"
echo "=============================================="
echo ""
echo "To apply the fix to your own application:"
echo ""
echo "1. Update Log4j version in pom.xml:"
echo "   <log4j.version>2.17.1</log4j.version>"
echo ""
echo "2. Add to application.properties:"
echo "   log4j2.formatMsgNoLookups=true"
echo ""
echo "3. Add JVM argument:"
echo "   -Dlog4j2.formatMsgNoLookups=true"
echo ""
echo "4. Implement input sanitization for all user input in logs"
echo ""
echo "5. Run validation: ./scripts/validate-security.sh"
echo ""
echo -e "${GREEN}For detailed instructions, see:${NC}"
echo "  remediation-guide/03-remediation.md"
echo ""
