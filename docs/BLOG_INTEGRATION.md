# Deadlight Blog Integration Guide

Complete guide for integrating proxy.deadlight with blog.deadlight using read-through caching.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                 Client Request Flow                      │
└─────────────────────────────────────────────────────────┘

Request → Proxy (localhost:8080)
            │
            ├─ Check local cache (/var/lib/deadlight/blog/)
            │  ├─ Fresh (< 5 min) → Return cached data
            │  └─ Stale or missing → Continue
            │
            ├─ Fetch from Workers (https://blog.deadlight.boo)
            │  ├─ Success → Update cache → Return data
            │  └─ Fail → Serve stale cache (offline mode)
            │
            └─ No cache available → 503 Service Unavailable
```

## Configuration

### 1. Proxy Config (`/etc/deadlight/deadlight.conf`)

Add this section:

```ini
[blog]
# URL of your Workers instance
workers_url = https://deadlight.boo

# Cache time-to-live (seconds)
# Posts older than this are considered stale
cache_ttl = 300

# Enable read-through caching
enable_cache = true

# Local cache directory
cache_dir = /var/lib/deadlight/blog
```

### 2. Workers Config (`wrangler.toml`)

```toml
[vars]
SITE_URL = "https://deadlight.boo"
ENABLE_QUEUE_PROCESSING = true
USE_PROXY_AUTH = false

# URL of your proxy's API
PROXY_API_URL = "http://98.53.133.209:8080/api"
PROXY_URL = "98.53.133.209:8080"
```

### 3. Directory Permissions

```bash
# Create cache directory
sudo mkdir -p /var/lib/deadlight/blog
sudo chown deadlight:deadlight /var/lib/deadlight/blog
sudo chmod 755 /var/lib/deadlight/blog
```

## Cache Behavior

### Cache States

| State | Condition | Behavior |
|-------|-----------|----------|
| **Fresh** | Age < `cache_ttl` | Serve immediately from cache |
| **Stale** | Age ≥ `cache_ttl` | Fetch from Workers, update cache |
| **Missing** | No cache file | Fetch from Workers, create cache |
| **Offline** | Workers unreachable + stale cache exists | Serve stale with warning |
| **Unavailable** | Workers unreachable + no cache | Return 503 error |

### Cache Invalidation

Caches are invalidated by:
1. **Time-based**: Automatically after `cache_ttl` seconds
2. **Manual**: Delete `/var/lib/deadlight/blog/posts.json`
3. **Restart**: Cache persists across restarts (filesystem-based)

```bash
# Manual cache clear
rm /var/lib/deadlight/blog/*.json

# View cache age
stat -c '%y' /var/lib/deadlight/blog/posts.json
```

## API Endpoints

### `/api/blog/posts`

Fetches posts with caching.

**Request:**
```bash
curl http://localhost:8080/api/blog/posts
```

**Response (Cache HIT):**
```json
{
  "posts": [...],
  "total": 5
}
```

**Response (Offline, stale cache):**
```json
{
  "posts": [...],
  "_warning": "Served from stale cache (Workers offline)"
}
```

**Logs:**
```
INFO: Blog: Cache HIT for /posts (age < 300 seconds)
INFO: Blog: Cache MISS for /posts, fetching from Workers
INFO: Blog: Updated cache for /posts
WARNING: Blog: Workers fetch failed, trying stale cache
INFO: Blog: Serving STALE cache (offline mode)
```

### `/api/blog/status`

Check blog integration status.

**Request:**
```bash
curl http://localhost:8080/api/blog/status
```

**Response:**
```json
{
  "status": "running",
  "version": "4.0.0",
  "backend": "connected",
  "cache_enabled": true,
  "cache_ttl": 300
}
```

**States:**
- `backend: "connected"` - Workers reachable
- `backend: "offline"` - Workers unreachable (serving from cache)

## Integration Testing

### Test 1: Basic Caching

```bash
# First request (cache MISS)
time curl http://localhost:8080/api/blog/posts
# → Should take ~300-500ms (network fetch)

# Second request (cache HIT)
time curl http://localhost:8080/api/blog/posts
# → Should take <10ms (local file read)

# Check cache file
ls -lh /var/lib/deadlight/blog/posts.json
cat /var/lib/deadlight/blog/posts.json | jq
```

### Test 2: Offline Mode

```bash
# 1. Warm cache
curl http://localhost:8080/api/blog/posts > /dev/null

# 2. Simulate Workers outage
# Edit deadlight.conf: workers_url = https://invalid.deadlight.boo

# 3. Restart proxy
sudo systemctl restart deadlight

# 4. Request should serve stale cache
curl http://localhost:8080/api/blog/posts | jq '._warning'
# → "Served from stale cache (Workers offline)"
```

### Test 3: Cache Expiry

```bash
# 1. Fetch posts (creates cache)
curl http://localhost:8080/api/blog/posts > /dev/null

# 2. Wait for cache to expire (cache_ttl + 1 second)
sleep 301

# 3. Next request should refresh cache
curl http://localhost:8080/api/blog/posts > /dev/null

# 4. Check logs for cache MISS
journalctl -u deadlight -n 20 | grep "Cache MISS"
```

## Workers Queue Integration

Your existing cron job works unchanged:

```javascript
// In your Workers scheduled handler
export default {
  async scheduled(event, env, ctx) {
    // Check if proxy is available
    const proxyHealth = await fetch(`${env.PROXY_API_URL}/health`);
    
    if (proxyHealth.ok) {
      // Flush email queue
      const pending = await env.DB.prepare(
        'SELECT * FROM email_queue WHERE status = "pending"'
      ).all();
      
      for (const email of pending.results) {
        await fetch(`${env.PROXY_API_URL}/email/send`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            to: email.to,
            subject: email.subject,
            body: email.body
          })
        });
        
        // Mark as sent
        await env.DB.prepare(
          'UPDATE email_queue SET status = "sent" WHERE id = ?'
        ).bind(email.id).run();
      }
    }
  }
};
```

## Monitoring

### Cache Performance Metrics

```bash
# Cache hit rate (from logs)
journalctl -u deadlight --since today | grep -c "Cache HIT"
journalctl -u deadlight --since today | grep -c "Cache MISS"

# Cache directory size
du -sh /var/lib/deadlight/blog/

# Cache file ages
find /var/lib/deadlight/blog -name "*.json" -printf "%p: %T+\n"
```

### Health Checks

```bash
# Proxy health
curl http://localhost:8080/api/health

# Blog backend connectivity
curl http://localhost:8080/api/blog/status | jq '.backend'

# Federation status
curl http://localhost:8080/api/federation/status
```

## Troubleshooting

### Cache Not Working

**Symptom:** Every request shows "Cache MISS"

**Check:**
```bash
# 1. Verify config
grep -A 5 "\[blog\]" /etc/deadlight/deadlight.conf

# 2. Check directory permissions
ls -ld /var/lib/deadlight/blog/

# 3. Check logs
journalctl -u deadlight -f | grep -i cache
```

**Fix:**
```bash
# Ensure cache is enabled
echo "enable_cache = true" >> /etc/deadlight/deadlight.conf

# Fix permissions
sudo chown -R deadlight:deadlight /var/lib/deadlight/blog/
sudo chmod 755 /var/lib/deadlight/blog/

# Restart
sudo systemctl restart deadlight
```

### Workers Unreachable

**Symptom:** `backend: "offline"` in status

**Check:**
```bash
# Test connectivity from proxy host
curl -I https://deadlight.boo/api/health

# Check proxy logs
journalctl -u deadlight -n 50 | grep -i workers
```

**Fix:**
```bash
# Verify Workers URL in config
grep workers_url /etc/deadlight/deadlight.conf

# Test DNS resolution
nslookup deadlight.boo

# Check firewall
sudo iptables -L OUTPUT
```

### Stale Cache Warning

**Symptom:** `_warning` field in responses

**This is expected behavior** when:
- Workers is temporarily offline
- Network connectivity is intermittent
- Proxy can't reach Workers but has cached data

**To resolve:**
1. Fix Workers connectivity
2. Wait for cache to refresh (happens automatically on next request)
3. Or manually clear cache to force error instead of stale data

## Advanced Configuration

### Different TTL per Endpoint

```ini
[blog]
workers_url = https://deadlight.boo
enable_cache = true
cache_dir = /var/lib/deadlight/blog

# Default TTL
cache_ttl = 300

# Override for specific endpoints (future enhancement)
cache_ttl_posts = 600      # Posts change less frequently
cache_ttl_comments = 60    # Comments change more frequently
```

### Disable Caching for Development

```ini
[blog]
workers_url = http://localhost:8787  # Local dev server
enable_cache = false                 # Always fetch fresh
```

### Cache Prewarming

```bash
#!/bin/bash
# Prewarm cache on startup
curl -s http://localhost:8080/api/blog/posts > /dev/null
curl -s http://localhost:8080/api/federation/posts > /dev/null
echo "Cache prewarmed"
```

Add to systemd service:
```ini
[Service]
ExecStartPost=/usr/local/bin/prewarm-cache.sh
```

## Security Considerations

### Cache Poisoning

**Risk:** Attacker modifies cache files

**Mitigation:**
- Cache directory owned by proxy user only
- No write access from web
- Cache validation (future: HMAC verification)

```bash
# Harden permissions
sudo chmod 700 /var/lib/deadlight/blog/
sudo chown deadlight:deadlight /var/lib/deadlight/blog/
```

### Stale Data Exposure

**Risk:** Serving outdated/deleted content

**Mitigation:**
- Short TTL (5 minutes default)
- Manual cache clearing on critical updates
- Cache invalidation webhooks (future)

```bash
# Emergency cache clear
sudo rm -rf /var/lib/deadlight/blog/*.json
sudo systemctl restart deadlight
```

## Performance Impact

### Cache Enabled

| Metric | Value |
|--------|-------|
| **Cache HIT latency** | <10ms |
| **Cache MISS latency** | 300-500ms (Workers fetch) |
| **Disk usage** | ~100KB per 100 posts |
| **Memory overhead** | Negligible (file-based) |

### Cache Disabled

| Metric | Value |
|--------|-------|
| **All requests** | 300-500ms (always fetch) |
| **Workers load** | Higher (no caching) |
| **Offline mode** | Not available |

## Summary

✅ **Implemented:**
- Read-through caching for `/api/blog/posts`
- Offline mode with stale cache serving
- Configurable TTL and cache directory
- Health checks and status reporting
- Integration with Workers queue system

🔄 **Works With:**
- Existing blog.deadlight cron jobs (unchanged)
- Tailscale private networking
- MailChannels email queue
- Federation system

📊 **Benefits:**
- 50-100x faster response time (cache HITs)
- Offline resilience (stale cache fallback)
- Reduced Workers load
- Better experience on intermittent networks

## Next Steps

1. Deploy updated proxy with cache support
2. Configure `workers_url` in `deadlight.conf`
3. Test with `test_blog_cache.sh` script
4. Monitor cache performance in logs
5. Adjust `cache_ttl` based on your usage pattern
