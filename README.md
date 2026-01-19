# Deadlight Proxy

A high-performance, multi-protocol proxy server built for **real-world conditions**: intermittent connectivity, resource constraints, and hostile networks. Written in C with GLib, featuring automatic protocol detection, TLS interception, VPN gateway mode, REST API, and lightweight web UI.

**Multi-protocol in one binary** · **17.6 MB Docker image** · **Works on ARM64** · **REST API** · **Edge-native design**

[![Docker Pulls](https://img.shields.io/docker/pulls/gnarzilla/proxy-deadlight)](https://hub.docker.com/r/gnarzilla/proxy-deadlight)
[![GitHub](https://img.shields.io/github/license/gnarzilla/proxy.deadlight)](LICENSE)

[Quick Start](#quick-start) · [Features](#features) · [API](#rest-api) · [Configuration](#configuration) · [Documentation](docs/) · [Usage Examples](#usage-examples) · [Architecture](#architecture) · [Roadmap](#roadmap)

![Deadlight Proxy Web UI](assets/proxy.deadlight_cli_ui_boot2shut.gif)

---

## Quick Start

### Docker (Recommended)

```bash
# Pull and run
docker run -d \
  --name deadlight-proxy \
  -p 8080:8080 \
  -p 8081:8081 \
  gnarzilla/proxy-deadlight:latest

# Access proxy at localhost:8080
# Web UI at http://localhost:8081
# REST API at http://localhost:8080/api
```

**Docker Compose:**
```yaml
version: '3.8'
services:
  proxy:
    image: gnarzilla/proxy-deadlight:latest
    ports:
      - "8080:8080"  # Proxy + API
      - "8081:8081"  # Web UI
    environment:
      - DEADLIGHT_AUTH_SECRET=your-secret-here
    volumes:
      - ./config:/etc/deadlight
      - ./federation:/var/lib/deadlight/federation
    restart: unless-stopped
```

**Platforms:** `linux/amd64`, `linux/arm64` (Raspberry Pi, ARM servers, Apple Silicon)

### Build from Source

```bash
git clone https://github.com/gnarzilla/proxy.deadlight.git
cd proxy.deadlight
make UI=1           # With web UI
./bin/deadlight -v  # Start with verbose logging
```

**Requirements:** GLib 2.0+, OpenSSL 1.1+, GCC/Clang  
**Optional:** libmicrohttpd for web UI (build with `make UI=1`)

---

## Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **Multi-Protocol** | HTTP/S, SOCKS4/5, WebSocket, SMTP, IMAP/S, FTP—auto-detected |
| **TLS Interception** | Man-in-the-middle HTTPS inspection with upstream cert mimicry |
| **Connection Pooling** | Reuses upstream connections with health checks (0-50% hit rate) |
| **VPN Gateway** | Kernel-integrated TUN device for Layer 3 routing |
| **REST API** | Full-featured API for email, federation, metrics, and management |
| **Plugins** | Ad blocking, rate limiting, custom filters |
| **Web UI** | Real-time monitoring at `:8081` |
| **Resource-Efficient** | 17.6 MB Docker image, minimal RAM usage |

### NEW: REST API

Deadlight now includes a comprehensive REST API for:

- **Email Sending** - Send emails via MailChannels API with optional HMAC authentication
- **Federation** - Inter-instance communication via email transport (experimental)
- **Metrics** - Real-time connection stats, protocol breakdown, pool performance
- **System Info** - External IP detection, health checks

**Quick API Examples:**

```bash
# Health check
curl http://localhost:8080/api/health

# Send email
curl -X POST http://localhost:8080/api/email/send \
  -H "Content-Type: application/json" \
  -d '{"to":"user@example.com","subject":"Test","body":"Hello"}'

# View metrics
curl http://localhost:8080/api/metrics | jq

# Federation: Send post to another Deadlight instance
curl -X POST http://localhost:8080/api/federation/send \
  -H "Content-Type: application/json" \
  -d '{"target_domain":"other.deadlight.boo","content":"Hello!","author":"alice"}'
```

📖 **Full API Documentation:** [docs/API.md](docs/API.md)

---

## REST API

### Available Endpoints

#### System
- `GET /api/health` - Health check with version info
- `GET /api/system/ip` - External IP detection
- `GET /api/metrics` - Real-time metrics (connections, protocols, pool stats)

#### Email
- `POST /api/email/send` - Send email (no auth)
- `POST /api/outbound/email` - Send email (HMAC auth required)

#### Federation (Experimental)
- `POST /api/federation/send` - Send post to another instance via email
- `POST /api/federation/receive` - Receive and store federated posts
- `GET /api/federation/posts` - List all stored posts
- `GET /api/federation/status` - Federation system status
- `GET /api/federation/test/{domain}` - Test domain connectivity

#### Blog (Stubs)
- `GET /api/blog/status` - Blog backend status
- `GET /api/blog/posts` - List blog posts
- `POST /api/blog/publish` - Publish new post (not yet implemented)

### API Configuration

```ini
# /etc/deadlight/deadlight.conf

[core]
auth_endpoint = /api/outbound/email
auth_secret = <random_64_char_hex>

[smtp]
mailchannels_api_key = <your_mailchannels_api_key>
```

**Generate secret:** `openssl rand -hex 32`

For complete API documentation, examples, and HMAC authentication guide, see **[docs/API.md](docs/API.md)**

---

## TLS Interception Setup

For HTTPS inspection without browser warnings, install the Deadlight CA certificate.

### Docker (Extract CA)
```bash
docker run --rm gnarzilla/proxy-deadlight:latest cat /etc/deadlight/ca.crt > deadlight-ca.crt
```

### Install CA (Linux)
```bash
# Debian/Ubuntu
sudo cp deadlight-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Fedora/RHEL
sudo cp deadlight-ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

### Install CA (Other Platforms)
- **macOS:** `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain deadlight-ca.crt`
- **Windows:** Double-click → Install → Trusted Root Certification Authorities
- **Firefox:** `about:preferences#privacy` → Certificates → Authorities → Import

**Security Note:** Only install on devices you control. Breaks certificate pinning on some sites (GitHub, Mozilla, banks). Use responsibly.

---

## Configuration

### Default Config Locations
- **Docker:** `/etc/deadlight/deadlight.conf` (auto-generated)
- **Native:** `/etc/deadlight/deadlight.conf`

### Key Sections
```ini
[core]
port = 8080
max_connections = 500
worker_threads = 4
auth_secret = <generate_with_openssl_rand>

[ssl]
enabled = true
ca_cert_file = /etc/deadlight/ca.crt
ca_key_file = /etc/deadlight/ca.key

[smtp]
mailchannels_api_key = <your_api_key>

[plugins]
enabled = true
autoload = adblocker,ratelimiter

[vpn]
enabled = false  # Requires root + --privileged
tun_device = tun0
```

**Hot-reload:** Config changes apply automatically (no restart needed).

Example configs: [`deadlight.conf.example`](deadlight.conf.example), [`deadlight.conf.docker`](deadlight.conf.docker)

---

## Usage Examples

### As HTTP/HTTPS Proxy
```bash
# Configure browser/system to use http://localhost:8080
curl -x http://localhost:8080 https://example.com
```

### As SOCKS Proxy
```bash
curl --socks5 localhost:8080 http://example.com
```

### As Email Gateway
```bash
# Send email via REST API
curl -X POST http://localhost:8080/api/email/send \
  -H "Content-Type: application/json" \
  -d '{
    "to": "recipient@example.com",
    "subject": "Test Email",
    "body": "Sent via Deadlight Proxy"
  }'
```

### With VPN Mode (Docker)
```bash
docker run -d \
  --name proxy-vpn \
  --privileged \
  --cap-add=NET_ADMIN \
  -p 8080:8080 \
  gnarzilla/proxy-deadlight
```

### As Federation Node
```bash
# Receive federated post
curl -X POST http://localhost:8080/api/federation/receive \
  -H "Content-Type: application/json" \
  -H "From: alice@other.deadlight.boo" \
  -d '{"content":"Hello from another instance!","author":"alice"}'

# List all federated posts
curl http://localhost:8080/api/federation/posts | jq
```

### Command-Line Options
```
-c, --config FILE   Config file (default: /etc/deadlight/deadlight.conf)
-p, --port PORT     Override listening port
-v, --verbose       Enable debug logging
-d, --daemon        Run as background daemon
-h, --help          Show usage
```

---

## Architecture

```
┌─────────────────┐
│  GSocketService │ ← Connection acceptance (port 8080)
└────────┬────────┘
         │
    ┌────▼─────┐
    │  Workers │ ← Thread pool
    └────┬─────┘
         │
    ┌────▼──────────┐
    │  Detection    │ ← Protocol auto-detection
    └────┬──────────┘
         │
    ┌────▼─────────────────────────┐
    │  Protocol Handlers           │
    │  ├─ HTTP/HTTPS               │
    │  ├─ SOCKS4/5                 │
    │  ├─ API (REST endpoints)     │ ← NEW
    │  ├─ SMTP/IMAP                │
    │  ├─ WebSocket                │
    │  ├─ TLS Interception         │
    │  ├─ Connection Pool          │
    │  └─ Plugin Hooks             │
    └──────────────────────────────┘
```

**Design Philosophy:**
- **Stateless core** (no local DB/queues, federation uses filesystem)
- **Edge-native** (optimized for intermittent connectivity)
- **Plugin-extensible** (modify behavior without core changes)
- **Performance-focused** (connection pooling, async I/O, worker threads)
- **API-first** (RESTful interface for programmatic control)

---

## Use Cases

| Scenario | How Deadlight Helps |
|----------|---------------------|
| **Home Gateway** | Secure all devices via VPN without exposing ports |
| **Development** | Inspect/modify API calls with TLS interception + plugins |
| **Email Bridge** | Send emails via REST API or tunnel legacy SMTP/IMAP |
| **Privacy Tool** | SOCKS proxy with built-in ad blocking |
| **Edge Networks** | Works on mesh/satellite/2G with intermittent connectivity |
| **Federation Node** | Inter-instance communication for distributed systems |
| **Monitoring Hub** | Real-time metrics via REST API for dashboards |

---

## Documentation

- **[API Reference](docs/API.md)** - Complete REST API documentation
- **[Quick Start Guide](docs/QUICK_START.md)** - Detailed setup instructions
- **[Architecture](docs/ARCHITECTURE.md)** - Technical deep dive
- **[Extending Deadlight](docs/EXTENDING.md)** - Plugin and protocol development
- **[Contributing](docs/CONTRIBUTING.md)** - How to contribute

---

## Extending Deadlight

### Add a Protocol Handler
1. Create `src/protocols/myprotocol.c`
2. Implement `detect`, `handle`, `cleanup` functions
3. Register in `src/core/protocols.c`
4. Rebuild: `make`

### Add a Plugin
1. Create `src/plugins/myplugin.c`
2. Define hooks (`on_request_headers`, `on_response`, etc.)
3. Export with `G_MODULE_EXPORT`
4. Enable in config: `[plugins] autoload = myplugin`

See [docs/EXTENDING.md](docs/EXTENDING.md) for details.

---

## Roadmap

### Near-term (2025)
- [x] REST API with email sending
- [x] Federation system (experimental)
- [x] Connection pool metrics
- [ ] HMAC authentication fixes
- [ ] Blog backend integration
- [ ] API rate limiting
- [ ] WebSocket support for real-time updates

### Medium-term (2026)
- [ ] Dynamic plugin loading (no rebuild required)
- [ ] Full IPv6 support
- [ ] Windows/macOS native builds
- [ ] Advanced plugins (ML-based anomaly detection)
- [ ] ActivityPub federation support
- [ ] Prometheus metrics export

### Long-term
- [ ] HF radio transport layer
  - Enables global IP-over-HF connectivity (5–30 kbit/s) for resilient, infrastructure-free networking using open modems like VARA and ARDOP—perfect for intermittent edge scenarios like remote ops or disaster response.
  - Start with RX-only testing via RTL-SDR + upconverter and GNU Radio demodulators, piping decoded streams (e.g., KISS/UDP) directly into Deadlight for protocol handling.
  - Adding TX (e.g., HackRF or Hermes-Lite) is a simple flowgraph swap, unlocking bidirectional transport without core changes.
  - Targets 2026 delivery for Tier 2 (robust digital modes); full wideband OFDM is future stretch.

---

## Part of the Deadlight Ecosystem

This proxy is designed for **resilient, edge-native infrastructure** where connectivity is intermittent and resources are constrained. Part of the broader [Deadlight project](https://github.com/gnarzilla/edge.deadlight).

**Related Projects:**
- [blog.deadlight](https://github.com/gnarzilla/blog.deadlight) - Cloudflare Workers blog (<10 KB pages)
- [meshtastic.deadlight](https://github.com/gnarzilla/meshtastic.deadlight) - Internet-over-LoRa gateway
- [edge.deadlight](https://github.com/gnarzilla/edge.deadlight) - Unified edge platform

**API Integration:** The Deadlight Proxy API is designed to integrate seamlessly with blog.deadlight for content publishing and federation.

---

## License

MIT License - see [LICENSE](docs/LICENSE)

## Support

- **Issues:** [GitHub Issues](https://github.com/gnarzilla/proxy.deadlight/issues)
- **API Support:** See [docs/API.md](docs/API.md) for troubleshooting
- **Donate:** [ko-fi.com/gnarzilla](https://ko-fi.com/gnarzilla)
- **Email:** gnarzilla@deadlight.boo

**Contributions welcome** See [CONTRIBUTING.md](docs/CONTRIBUTING.md)

---

*Now with REST API for programmatic control and federation.*
