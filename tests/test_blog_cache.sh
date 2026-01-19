#!/bin/bash
# Test script for blog cache integration

PROXY_URL="${PROXY_URL:-http://localhost:8080}"
CACHE_DIR="/var/lib/deadlight/blog"

echo "=== Deadlight Blog Cache Integration Test ==="
echo

# Test 1: Check blog status
echo "1. Checking blog status..."
curl -s "$PROXY_URL/api/blog/status" | jq
echo

# Test 2: Fetch posts (should cache)
echo "2. Fetching posts (first request - cache MISS)..."
time curl -s "$PROXY_URL/api/blog/posts" | jq -r '.posts | length'
echo

# Test 3: Check cache file
echo "3. Checking cache file..."
if [ -f "$CACHE_DIR/posts.json" ]; then
    echo "✓ Cache file exists"
    ls -lh "$CACHE_DIR/posts.json"
    echo "Cache age: $(( $(date +%s) - $(stat -c %Y "$CACHE_DIR/posts.json") )) seconds"
else
    echo "✗ Cache file not found"
fi
echo

# Test 4: Fetch again (should use cache)
echo "4. Fetching posts again (should be cache HIT)..."
time curl -s "$PROXY_URL/api/blog/posts" | jq -r '.posts | length'
echo

# Test 5: Check metrics
echo "5. Checking proxy metrics..."
curl -s "$PROXY_URL/api/metrics" | jq '.active_connections, .total_connections'
echo

# Test 6: Test offline mode (simulate Workers down)
echo "6. Testing offline mode..."
echo "   Manually edit deadlight.conf to set workers_url to invalid URL"
echo "   Then run: curl $PROXY_URL/api/blog/posts"
echo "   Should serve stale cache with warning"
echo

# Test 7: Federation integration
echo "7. Testing federation sync..."
curl -s "$PROXY_URL/api/federation/status" | jq
echo

echo "=== Test Complete ==="
echo
echo "Cache directory: $CACHE_DIR"
echo "View logs: journalctl -u deadlight -f | grep -i blog"
