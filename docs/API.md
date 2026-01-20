# Deadlight Proxy API Documentation

Complete reference for the Deadlight Proxy REST API (v1.0.0)

## Base URL

```
http://your-proxy-host:8080/api
```

## Authentication

Some endpoints require HMAC-SHA256 authentication:

```http
Authorization: Bearer <hmac_signature>
```

Generate signature:
```python
import hmac, hashlib, json

secret = "your_auth_secret"  # From deadlight.conf
payload = json.dumps(body, separators=(',', ':'))  # No spaces
signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
```

---

## System Endpoints

### Health Check
```http
GET /api/health
```

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "timestamp": 1768712037,
  "proxy": "deadlight"
}
```

### System Information
```http
GET /api/system/ip
```

**Response:**
```json
{
  "external_ip": "98.53.133.209",
  "port": 8080
}
```

### Metrics
```http
GET /api/metrics
```

**Response:**
```json
{
  "active_connections": 3,
  "total_connections": 24,
  "bytes_transferred": 23100,
  "uptime": 182.42,
  "connection_pool": {
    "idle": 0,
    "active": 16,
    "total_requests": 16,
    "cache_hits": 0,
    "hit_rate": 0.00,
    "evicted": 0,
    "failed": 0
  },
  "protocols": {
    "HTTP": {"active": 0},
    "HTTPS": {"active": 0},
    "WebSocket": {"active": 0},
    "SOCKS": {"active": 0},
    "SMTP": {"active": 0},
    "IMAP": {"active": 0},
    "FTP": {"active": 0},
    "API": {"active": 1}
  },
  "server_info": {
    "version": "1.0.0",
    "port": 8080,
    "ssl_intercept": true,
    "max_connections": 500
  }
}
```

---

## Email Endpoints

### Send Email (Simple)
```http
POST /api/email/send
Content-Type: application/json
```

**Request:**
```json
{
  "to": "recipient@example.com",
  "from": "sender@deadlight.boo",  // Optional, defaults to noreply@deadlight.boo
  "subject": "Test Email",          // Optional, defaults to "Message from Deadlight"
  "body": "Email content here"
}
```

**Response:**
```json
{
  "status": "sent",
  "provider": "mailchannels"
}
```

### Send Email (Authenticated)
```http
POST /api/outbound/email
Content-Type: application/json
Authorization: Bearer <hmac_signature>
```

**Request:**
```json
{
  "from": "sender@deadlight.boo",
  "to": "recipient@example.com",
  "subject": "Authenticated Email",
  "body": "This requires HMAC authentication"
}
```

**Response:**
```json
{
  "status": "sent",
  "provider": "mailchannels"
}
```

**Error (401):**
```json
{
  "error": "Invalid credentials"
}
```

---

## Federation Endpoints

### Send Federated Post
```http
POST /api/federation/send
Content-Type: application/json
```

**Request:**
```json
{
  "target_domain": "other.deadlight.boo",
  "content": "Post content here",
  "author": "user@deadlight.boo"
}
```

**Response:**
```json
{
  "status": "sent",
  "transport": "email"
}
```

### Receive Federated Post
```http
POST /api/federation/receive
Content-Type: application/json
From: sender@remote.domain
```

**Request:**
```json
{
  "content": "Incoming federated post",
  "author": "remote-user"
}
```

**Response:**
```json
{
  "status": "received",
  "queued": true,
  "stored": "/var/lib/deadlight/federation/post_1768712037_alice.json",
  "from": "alice@other.deadlight.boo"
}
```

### List Federated Posts
```http
GET /api/federation/posts
```

**Response:**
```json
{
  "posts": [
    {
      "timestamp": 1768712037,
      "from": "alice@other.deadlight.boo",
      "author": "alice",
      "content": "Hello from Alice!"
    }
  ],
  "total": 1
}
```

### Federation Status
```http
GET /api/federation/status
```

**Response:**
```json
{
  "status": "online",
  "connected_domains": 0,
  "posts_sent": 0,
  "posts_received": 1,
  "comments_synced": 0
}
```

### Test Domain Connectivity
```http
GET /api/federation/test/{domain}
```

**Example:**
```http
GET /api/federation/test/example.com
```

**Response:**
```json
{
  "domain": "example.com",
  "status": "verified",          // or "unreachable", "dns_failed"
  "trust_level": "verified",     // or "unverified"
  "test_time": 1768712037,
  "active": true
}
```

---

## Blog Endpoints

### Blog Status
```http
GET /api/blog/status
```

**Response:**
```json
{
  "status": "running",
  "version": "4.0.0",
  "backend": "not_connected"
}
```

### List Posts
```http
GET /api/blog/posts
```

**Response:**
```json
{
  "posts": [],
  "total": 0
}
```

### Publish Post
```http
POST /api/blog/publish
Content-Type: application/json
```

**Request:**
```json
{
  "title": "Post Title",
  "content": "Post content here"
}
```

**Response (501):**
```json
{
  "status": "success",
  "message": "Post published successfully",
  "note": "Blog integration not yet implemented"
}
```

---

## Error Responses

### 404 Not Found
```json
{
  "error": "API endpoint not found"
}
```

### 400 Bad Request
```json
{
  "error": "Invalid JSON"
}
```

### 401 Unauthorized
```json
{
  "error": "Invalid credentials"
}
```

### 500 Internal Server Error
```json
{
  "error": "NULL context"
}
```

### 502 Bad Gateway
```json
{
  "error": "Email provider failed"
}
```

---

## CORS Headers

All responses include CORS headers:

```http
Access-Control-Allow-Origin: https://deadlight.boo
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, X-API-Key, Authorization
```

---

## Rate Limiting

Currently no rate limiting is implemented. All endpoints are unrestricted.

---

## Testing Examples

### cURL Examples

```bash
# Health check
curl http://localhost:8080/api/health

# Send simple email
curl -X POST http://localhost:8080/api/email/send \
  -H "Content-Type: application/json" \
  -d '{"to":"test@example.com","subject":"Test","body":"Hello"}'

# Send federated post
curl -X POST http://localhost:8080/api/federation/send \
  -H "Content-Type: application/json" \
  -d '{"target_domain":"other.deadlight.boo","content":"Hello","author":"alice"}'

# Receive federated post
curl -X POST http://localhost:8080/api/federation/receive \
  -H "Content-Type: application/json" \
  -H "From: bob@remote.boo" \
  -d '{"content":"Post from Bob","author":"bob"}'

# List federated posts
curl http://localhost:8080/api/federation/posts

# Get metrics
curl http://localhost:8080/api/metrics
```

## Storage Locations

### Federation Posts
```
/var/lib/deadlight/federation/post_{timestamp}_{author}.json
```

**Format:**
```json
{
  "timestamp": 1768712037,
  "from": "alice@other.deadlight.boo",
  "author": "alice",
  "content": "Post content"
}
```

---

## Configuration

Relevant config sections in `/etc/deadlight/deadlight.conf`:

```ini
[core]
auth_endpoint = /api/outbound/email
auth_secret = your_hmac_secret_here

[smtp]
mailchannels_api_key = your_api_key_here
```

---

## Future Enhancements

- [ ] Rate limiting per endpoint
- [ ] API key authentication (alternative to HMAC)
- [ ] Webhook notifications for federation events
- [ ] Blog backend integration with Cloudflare Workers
- [ ] WebSocket support for real-time updates
- [ ] Pagination for `/api/federation/posts`
- [ ] Post search and filtering
- [ ] Domain trust/blocklist management
- [ ] Metrics export (Prometheus format)

---

## Support

- GitHub: https://github.com/gnarzilla/proxy.deadlight
- Issues: https://github.com/gnarzilla/proxy.deadlight/issues
- Email: gnarzilla@deadlight.boo
