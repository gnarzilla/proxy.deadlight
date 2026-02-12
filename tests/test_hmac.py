#!/usr/bin/env python3
"""
HMAC-SHA256 Test Script for Deadlight Proxy
Generates proper signatures for /api/outbound/email endpoint
"""

import hmac
import hashlib
import json
import sys

def generate_hmac(secret, payload):
    """Generate HMAC-SHA256 for the given payload"""
    signature = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return signature

def test_outbound_email(secret, from_addr=None, to_addr=None, subject=None, body=None):
    """Test the outbound email endpoint with HMAC authentication"""
    
    # Use defaults if not provided
    from_addr = from_addr or "gnarzilla@deadlight.boo"
    to_addr = to_addr or "deadlight.boo@gmail.com"
    subject = subject or "Authenticated Test"
    body = body or "This email requires HMAC authentication"
    
    # Build payload - CRITICAL: No spaces after separators!
    payload_dict = {
        "from": from_addr,
        "to": to_addr,
        "subject": subject,
        "body": body
    }
    
    # Generate JSON with NO SPACES (this is critical for HMAC)
    payload = json.dumps(payload_dict, separators=(',', ':'))
    
    # Generate HMAC
    signature = generate_hmac(secret, payload)
    
    # Display results
    print("=" * 70)
    print("HMAC Test for /api/outbound/email")
    print("=" * 70)
    print(f"\nSecret: {secret}")
    print(f"Secret length: {len(secret)} bytes")
    print(f"\nPayload ({len(payload)} bytes):")
    print(payload)
    print(f"\nPayload (hex):")
    print(payload.encode('utf-8').hex())
    print(f"\nGenerated HMAC-SHA256:")
    print(signature)
    print(f"\nCurl command:")
    print("-" * 70)
    
    # Escape single quotes in payload for shell
    safe_payload = payload.replace("'", "'\\''")
    
    print(f"""curl -X POST http://localhost:8080/api/outbound/email \\
  -H "Authorization: Bearer {signature}" \\
  -H "Content-Type: application/json" \\
  -d '{safe_payload}'""")
    
    print("-" * 70)
    print("\nDEBUGGING TIPS:")
    print("1. Set DEADLIGHT_DEBUG_HMAC=1 environment variable")
    print("2. Compare payload bytes exactly (check for extra spaces/newlines)")
    print("3. Verify auth_secret in /etc/deadlight/deadlight.conf")
    print("4. Check logs for HMAC validation details")
    print("=" * 70)

def verify_hmac(secret, payload, expected_signature):
    """Verify an HMAC signature"""
    computed = generate_hmac(secret, payload)
    match = computed == expected_signature
    
    print("=" * 70)
    print("HMAC Verification")
    print("=" * 70)
    print(f"Expected:  {expected_signature}")
    print(f"Computed:  {computed}")
    print(f"Match:     {match}")
    print("=" * 70)
    
    return match

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Generate HMAC:")
        print("    ./test_hmac.py <auth_secret>")
        print("")
        print("  Custom email:")
        print("    ./test_hmac.py <auth_secret> <from> <to> <subject> <body>")
        print("")
        print("  Verify HMAC:")
        print("    ./test_hmac.py <auth_secret> --verify <payload> <signature>")
        print("")
        print("Example:")
        print("  ./test_hmac.py my_secret")
        print("  ./test_hmac.py my_secret alice@x.com bob@y.com 'Hello' 'World'")
        print("")
        print("Get your auth_secret from deadlight.conf:")
        print("  grep auth_secret /etc/deadlight/deadlight.conf")
        sys.exit(1)
    
    secret = sys.argv[1]
    
    # Verify mode
    if len(sys.argv) == 5 and sys.argv[2] == "--verify":
        payload = sys.argv[3]
        expected = sys.argv[4]
        verify_hmac(secret, payload, expected)
    # Custom email
    elif len(sys.argv) == 6:
        test_outbound_email(secret, sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    # Default test
    else:
        test_outbound_email(secret)
