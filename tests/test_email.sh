#!/bin/bash
# test_email.sh - Comprehensive Email API Testing for Deadlight Proxy
# Tests HMAC authentication, MailChannels integration, and error handling

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROXY_URL="http://127.0.0.1:8080"
API_ENDPOINT="${PROXY_URL}/api/outbound/email"
YOUR_EMAIL="deadlight.boo@gmail.com"
AUTH_SECRET="gross-window-birthday-shit"        # ← CHANGE THIS TO MATCH deadlight.conf

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Deadlight Proxy - Email API Test Suite                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to generate HMAC signature
generate_hmac() {
    local payload="$1"
    local secret="$2"
    # printf ensures no extra newlines; awk ensures we only get the hex hash
    printf "%s" "$payload" | openssl dgst -sha256 -hmac "$secret" | awk '{print $2}'
}
# Function to run a test
run_test() {
    local test_name="$1"
    local payload="$2"
    local auth_header="$3"
    local expected_status="$4"
    local description="$5"
    
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}TEST:${NC} $test_name"
    echo -e "${BLUE}DESC:${NC} $description"
    echo ""
    
    # Make request
    if [ -n "$auth_header" ]; then
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_ENDPOINT" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $auth_header" \
            -d "$payload")
    else
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_ENDPOINT" \
            -H "Content-Type: application/json" \
            -d "$payload")
    fi
    
    # Extract status code and body
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    echo -e "${BLUE}Response Code:${NC} $http_code"
    echo -e "${BLUE}Response Body:${NC} $body"
    echo ""
    
    # Check result
    if [ "$http_code" = "$expected_status" ]; then
        echo -e "${GREEN}✓ PASS${NC} - Got expected status code $expected_status"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC} - Expected $expected_status, got $http_code"
        ((TESTS_FAILED++))
    fi
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════
# PRE-FLIGHT CHECKS
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[1/8]${NC} Pre-flight checks..."

# Check if proxy is running
if ! curl -s --max-time 2 "$PROXY_URL/api/health" > /dev/null 2>&1; then
    echo -e "${RED}✗ FAIL${NC} - Proxy not running at $PROXY_URL"
    echo "Please start the proxy with: sudo ./bin/deadlight -c deadlight.conf -v"
    exit 1
fi
echo -e "${GREEN}✓${NC} Proxy is running"

# Check if auth_secret is configured
if [ "$AUTH_SECRET" = "your-secret-here" ]; then
    echo -e "${RED}✗ FAIL${NC} - Please set AUTH_SECRET in this script to match your deadlight.conf"
    echo ""
    echo "Edit this script and set:"
    echo "  AUTH_SECRET=\"your-actual-secret\""
    echo ""
    echo "And make sure deadlight.conf has:"
    echo "  [security]"
    echo "  auth_secret = your-actual-secret"
    exit 1
fi
echo -e "${GREEN}✓${NC} AUTH_SECRET is configured"

# Check if email is configured
if [ "$YOUR_EMAIL" = "test@email.com" ]; then
    echo -e "${YELLOW}⚠${NC} Using placeholder email address"
    echo "  For real testing, edit this script and set YOUR_EMAIL"
fi

# Check for openssl
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}✗ FAIL${NC} - openssl not found (needed for HMAC generation)"
    echo "Install with: sudo apt-get install openssl"
    exit 1
fi
echo -e "${GREEN}✓${NC} openssl is available"

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# TEST 1: Valid Email with Correct HMAC
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[2/8]${NC} Testing valid email with correct HMAC..."

PAYLOAD_1='{"from":"test@deadlight.boo","to":"'"$YOUR_EMAIL"'","subject":"Test Email","body":"This is a test email via Deadlight API."}'

HMAC_1=$(generate_hmac "$PAYLOAD_1" "$AUTH_SECRET")

echo -e "${BLUE}Expected HMAC:${NC} $HMAC_1"
echo -e "${BLUE}Payload len:${NC} ${#PAYLOAD_1} bytes"

run_test \
    "Valid Email" \
    "$PAYLOAD_1" \
    "$HMAC_1" \
    "202" \
    "Should accept email with valid HMAC and return 202 Accepted"

# ═══════════════════════════════════════════════════════════════════════════
# TEST 2: Invalid HMAC
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[3/8]${NC} Testing invalid HMAC..."

PAYLOAD_2='{"from": "test@deadlight.boo","to": "'"$YOUR_EMAIL"'","subject": "This should be rejected","body": "If you receive this, HMAC validation is broken!"}'

WRONG_HMAC="0000000000000000000000000000000000000000000000000000000000000000"

echo -e "${BLUE}Expected HMAC:${NC} $HMAC_1"
echo -e "${BLUE}Payload len:${NC} ${#PAYLOAD_1} bytes"

run_test \
    "Invalid HMAC" \
    "$PAYLOAD_2" \
    "$WRONG_HMAC" \
    "401" \
    "Should reject email with invalid HMAC and return 401 Unauthorized"

# ═══════════════════════════════════════════════════════════════════════════
# TEST 3: Missing Authorization Header
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[4/8]${NC} Testing missing authorization header..."

PAYLOAD_3='{"from": "test@deadlight.boo","to": "'"$YOUR_EMAIL"'","subject": "No auth header","body": "This should fail"}'

echo -e "${BLUE}Expected HMAC:${NC} $HMAC_1"
echo -e "${BLUE}Payload len:${NC} ${#PAYLOAD_1} bytes"

run_test \
    "Missing Auth Header" \
    "$PAYLOAD_3" \
    "" \
    "401" \
    "Should reject email without Authorization header and return 401"

# ═══════════════════════════════════════════════════════════════════════════
# TEST 4: Missing Required Fields
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[5/8]${NC} Testing missing required fields..."

PAYLOAD_4='{"from": "test@deadlight.boo","subject": "Missing TO field"}'

HMAC_4=$(generate_hmac "$PAYLOAD_4" "$AUTH_SECRET")

echo -e "${BLUE}Expected HMAC:${NC} $HMAC_1"
echo -e "${BLUE}Payload len:${NC} ${#PAYLOAD_1} bytes"

run_test \
    "Missing Required Fields" \
    "$PAYLOAD_4" \
    "$HMAC_4" \
    "400" \
    "Should reject email with missing 'to' field and return 400 Bad Request"

# ═══════════════════════════════════════════════════════════════════════════
# TEST 5: Invalid JSON
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[6/8]${NC} Testing invalid JSON..."

PAYLOAD_5='{"not valid json'

HMAC_5=$(generate_hmac "$PAYLOAD_5" "$AUTH_SECRET")

echo -e "${BLUE}Expected HMAC:${NC} $HMAC_1"
echo -e "${BLUE}Payload len:${NC} ${#PAYLOAD_1} bytes"

run_test \
    "Invalid JSON" \
    "$PAYLOAD_5" \
    "$HMAC_5" \
    "400" \
    "Should reject malformed JSON and return 400 Bad Request"

# ═══════════════════════════════════════════════════════════════════════════
# TEST 6: Wrong HTTP Method
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[7/8]${NC} Testing wrong HTTP method..."

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}TEST:${NC} Wrong HTTP Method"
echo -e "${BLUE}DESC:${NC} Should reject GET request and return 405 Method Not Allowed"
echo ""

response=$(curl -s -w "\n%{http_code}" -X GET "$API_ENDPOINT" -H "Content-Type: application/json")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

echo -e "${BLUE}Response Code:${NC} $http_code"
echo -e "${BLUE}Response Body:${NC} $body"
echo ""

if [ "$http_code" = "405" ]; then
    echo -e "${GREEN}✓ PASS${NC} - Got expected status code 405"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAIL${NC} - Expected 405, got $http_code"
    ((TESTS_FAILED++))
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# TEST 7: Long Email with Special Characters
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[8/8]${NC} Testing email with special characters..."

PAYLOAD_7='{
  "from": "noreply@deadlight.boo",
  "to": "'"$YOUR_EMAIL"'",
  "subject": "Test: Special Characters & Unicode 🚀",
  "body": "Testing special chars:\n• Bullet points\n• Émojis 🎉\n• Line breaks\n• \"Quotes\" and '\''apostrophes'\''\n\nThis tests the full email pipeline including:\n- JSON parsing\n- HMAC validation\n- MailChannels API\n- Connection pooling"
}'

HMAC_7=$(generate_hmac "$PAYLOAD_7" "$AUTH_SECRET")

echo -e "${BLUE}Expected HMAC:${NC} $HMAC_1"
echo -e "${BLUE}Payload len:${NC} ${#PAYLOAD_1} bytes"

run_test \
    "Special Characters" \
    "$PAYLOAD_7" \
    "$HMAC_7" \
    "202" \
    "Should handle special characters and return 202 Accepted"

# ═══════════════════════════════════════════════════════════════════════════
# RESULTS SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Test Results Summary                                     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))

echo -e "${GREEN}Passed:${NC} $TESTS_PASSED / $TOTAL_TESTS"
echo -e "${RED}Failed:${NC} $TESTS_FAILED / $TOTAL_TESTS"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ ALL TESTS PASSED!                                      ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "🎉 Email API is fully functional!"
    echo ""
    echo "Next steps:"
    echo "  1. Check $YOUR_EMAIL inbox for test emails"
    echo "  2. Monitor proxy logs for MailChannels pool usage:"
    echo "     grep 'api.mailchannels.net' <log-file>"
    echo "  3. Test from your dashboard at https://deadlight.boo"
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ✗ SOME TESTS FAILED                                      ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Debug steps:"
    echo "  1. Check proxy logs for detailed errors"
    echo "  2. Verify auth_secret matches in both:"
    echo "     - This script (AUTH_SECRET variable)"
    echo "     - deadlight.conf [security] section"
    echo "  3. Ensure MailChannels API key is configured in deadlight.conf:"
    echo "     [smtp]"
    echo "     mailchannels_api_key = your-key-here"
    echo "  4. Re-run tests with: bash test_email.sh"
    exit 1
fi
