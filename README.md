# Deadlight Proxy v5.0

![Deadlight Proxy](https://github.com/user-attachments/assets/7f3febdf-5621-4b7d-b834-c2f912a3fa3b)

**A modular, protocol-agnostic, and high-performance proxy server written in C using the GLib ecosystem, designed for deep inspection and extensibility.**

---

### Table of Contents
1.  [Overview](#overview)
2.  [Features](#features)
3.  [Architecture](#architecture)
4.  [Getting Started](#getting-started)
    *   [Prerequisites](#prerequisites)
    *   [Building](#building)
    *   [Configuration](#configuration)
    *   [Running](#running)
5.  [Usage](#usage)
    *   [Command Line Options](#command-line-options)
    *   [Proxying HTTP](#proxying-http)
    *   [Proxying & Intercepting HTTPS](#proxying--intercepting-httpshttps)
6.  [Extending Deadlight](#extending-deadlight)
    *   [Adding a New Protocol](#adding-a-new-protocol)
7.  [Project Structure](#project-structure)
8.  [Development Status](#development-status)
9.  [License](#license)
10. [Support](#support)

---

### Overview

`proxy.deadlight` is a high-performance, protocol-agnostic network proxy written in C that serves as the **Protocol Bridge** for the Deadlight Ecosystem. It seamlessly connects modern HTTP-only serverless platforms (like Cloudflare Workers) to foundational TCP protocols (SMTP, IMAP, SOCKS), enabling **true self-sovereign infrastructure**.

**NEW in v5.0:** Complete integration with `deadlight.boo` via REST API endpoints, enabling real-time proxy management through a beautiful web interface deployable anywhere.

### Features (Current Status)

After a comprehensive refactoring and development cycle, `proxy.deadlight` has evolved from a simple proxy into a robust, extensible framework.

- 📦 **Modular, Protocol-Agnostic Architecture:** Built around a `DeadlightProtocolHandler` interface that allows new protocols to be added easily as self-contained modules.
- 🚀 **High-Performance C Foundation:** Utilizes the robust and efficient GNU/GLib ecosystem for high-throughput, low-latency network I/O and multi-threaded connection handling.
- 🔒 **Secure Tunneling & Interception:**
   - **HTTP/HTTPS Proxy:** Functions as a standard forward proxy for web traffic.
   - **SSL (TLS) Interception:** Capable of generating certificates on-the-fly for traffic inspection (MitM), a powerful tool for development and security analysis.
   - **IMAPS Tunneling:** Securely tunnels IMAP traffic over TLS, with robust certificate validation against the system's trust store.
- 🌐 **SOCKS4 Proxy Support:** Provides basic IP masking and privacy by serving as a SOCKS4 proxy for compatible applications.
- 🎛️ **REST API Server:** Complete HTTP API for external integration and management
- 🛜 **Multi-Protocol Support**: HTTP/HTTPS/SOCKS/SMTP/IMAP/IMAPS/API protocols
- 📱 **Web Dashboard Integration:** Real-time proxy control via modern web interface
- 📧 **Email-based Federation:** Revolutionary approach to decentralized social media using proven email protocols
- 🔧 **File-Based Configuration:** All core settings, listeners, and protocol behaviors are controlled via a simple .ini-style configuration file.

### Integration Features (NEW in v5.0)

- 🌐 **REST API Interface:** Complete HTTP API for integration with web applications
- 📊 **Real-time Status Monitoring:** Live connection tracking and system health reporting  
- 📧 **Email Federation Bridge:** SMTP protocol translation for decentralized social media
- 🎛️ **Web-based Management:** Full proxy control via `blog.deadlight` admin dashboard
- ⚡ **Instant Deployment:** One command deployment to global CDN with local proxy backend

**API Endpoints:**
- `GET /api/blog/status` - Blog service health and version info
- `GET /api/email/status` - Email queue status and processing metrics
- `POST /api/email/send` - Send emails through proxy SMTP bridge
- `POST /api/federation/send` - Federated blog post distribution via email

![Integrated Terminal Side-by_-Side](https://github.com/gnarzilla/proxy.deadlight/blob/main/src/assets/Proxy%20%26%20Blog%20Terminal%20Side-by-Side.png)

### Architecture

#### System Architecture

                    🌐 DEADLIGHT ECOSYSTEM ARCHITECTURE 🌐

    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                            GLOBAL WEB LAYER                                │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │  📱 Any Browser/Device → 🌐 Cloudflare CDN → ⚡ blog.deadlight Worker      │
    │                                               (REST API Client)            │
    └─────────────────────────┬───────────────────────────────────────────────────┘
                              │
                              │ HTTP/JSON API Calls
                              ▼
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                         LOCAL PROTOCOL BRIDGE                              │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │                    📡 proxy.deadlight v5.0                                │
    │                                                                             │
    │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
    │  │   🌐 API        │    │   📧 SMTP       │    │   🔒 SOCKS5     │        │
    │  │   Handler       │    │   Bridge        │    │   Proxy         │        │
    │  └─────────────────┘    └─────────────────┘    └─────────────────┘        │
    │                                                                             │
    │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
    │  │   🌍 HTTP/S     │    │   📬 IMAP       │    │   🔧 Protocol   │        │
    │  │   Proxy         │    │   Tunnel        │    │   Detection     │        │
    │  └─────────────────┘    └─────────────────┘    └─────────────────┘        │
    └─────────────────────────┬───────────────────────────────────────────────────┘
                              │
                              │ Native TCP/SSL Protocols
                              ▼
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                          INTERNET SERVICES                                 │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │  📧 SMTP Servers  │  📬 IMAP Servers  │  🌐 Web Sites  │  🏠 Other Proxies │
    └─────────────────────────────────────────────────────────────────────────────┘

    🎯 DEPLOYMENT MODEL:
    ┌────────────────────┐                    ┌────────────────────┐
    │   🌐 GLOBAL        │                    │   🏠 LOCAL         │
    │   deadlight.boo    │ ←─── API BRIDGE ──→│   proxy.deadlight  │
    │   Cloudflare       │                    │   VPS/Pi/Desktop   │
    │   Workers/Pages    │                    │   localhost:8080   │
    └────────────────────┘                    └────────────────────┘

Deadlight is built on a modular design managed by a central `DeadlightContext`. A connection flows through the system as follows:
1.  The **Main Thread** runs a `GSocketService`, accepting new connections.
2.  Incoming connections are passed to a **Worker Thread** from a `GThreadPool`.
3.  The worker thread performs **Protocol Detection** by peeking at the initial bytes of the connection.
4.  The appropriate registered `DeadlightProtocolHandler` is invoked to handle the connection.
5.  The handler processes the request. It can either complete the request synchronously or, for long-lived tunnels, hand off control to **asynchronous I/O watchers** on its own thread's event loop. This prevents the worker thread from blocking.

This is all managed by a set of distinct managers:
-   **Network Manager**: Handles listener sockets, the worker pool, and connection state.
-   **SSL Manager**: Manages OpenSSL contexts, CA certificates, and performs SSL interception.
-   **Protocol System**: Manages the registration and detection of protocol handlers.
-   **Configuration Manager**: Parses INI-style configuration files.
-   **Connection Pool**: Manages and reuses upstream server connections.

### Getting Started

#### Prerequisites

-   A C99 compliant compiler (GCC or Clang)
-   `make`
-   `pkg-config`
-   GLib 2.0+ & GIO development libraries (`libglib2.0-dev`)
-   OpenSSL 1.1.1+ development libraries (`libssl-dev`)

On Debian/Ubuntu, install all prerequisites with:
```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config libglib2.0-dev libssl-dev glib-networking
```
- `build-essential`: Provides gcc, make, etc.
- `libglib2.0-dev`: The GLib core libraries and development headers.
- `libopenssl-dev`: For all cryptographic and TLS functions.
- `glib-networking`: The essential backend for GIO's TLS functionality.

#### Building

Clone the repository and use the provided Makefile:
```bash
git clone https://your-repo-url/deadlight.git
cd deadlight
make
```
The executable will be located at `bin/deadlight`.

#### Configuration

The proxy uses an INI-style configuration file. A sample is provided at `deadlight.conf.example`.

```ini
[core]
port = 8080
bind_address = 0.0.0.0
max_connections = 500
log_level = info
worker_threads = 4

[ssl]
enabled = true
ca_cert_file = /home/thatch/.deadlight/ca.crt
ca_key_file = /home/thatch/.deadlight/ca.key
cert_cache_dir = /tmp/deadlight_certs

[protocols]
http_enabled = true
https_enabled = true
connect_enabled = true

[plugins]
enabled = false

[imap]
# The upstream IMAP server to proxy connections to.
upstream_host = imap.gmail.com
upstream_port = 143

[imaps]
# The upstream IMAPS server to proxy connections to.
# This uses SSL/TLS on port 993.
upstream_host = imap.gmail.com
upstream_port = 993

```

#### Running
```bash
./bin/deadlight -c deadlight.conf.example
```

### Usage

#### Example 1: HTTP/HTTPS Web Proxy

Configure your browser or system to use `http:/localhost:8080` as its proxy. Or, use `curl`:

```bash
# Proxy a standard HTTP request
curl -x http://localhost:8080 http://example.com

# Proxy an HTTPS request (using the CONNECT method)
curl -x http://localhost:8080 https://example.com
```
#### Example 2: SOCKS4 Privacy Proxy

Use `curl` to route a request through the SOCKS4 handler:
```bash
curl --socks4 localhost:8080 http://example.com
```

#### Example 3: IMAPS Secure Tunnel

Test the secure IMAP tunnel using `telnet` (this proves the TLS handshake and tunneling):
```bash
telnet localhost 8080
```
Once connected, type the following and press Enter:
```text
a001 NOOP
```
The proxy will establish a secure TLS connection to the upstream IMAP server and tunnel the data.

#### Example 4. Web Dashboard Management

Deploy the integrated blog.deadlight dashboard
```bash
# Terminal 1: Start the proxy server
./bin/deadlight -c deadlight.conf.example

# Terminal 2: Start the blog with proxy integration
cd ../deadlight
wrangler dev

# Or to deploy to your live site
wrangler dev
```
Access `http://localhost:8787/admin/proxy` for real-time proxy management including:
- Live connection monitoring
- API endpoint testing
- Federation testing
- Email system management

#### Command Line Options

-   `-c, --config FILE`: Path to configuration file.
-   `-p, --port PORT`: Port to listen on (overrides config).
-   `-d, --daemon`: Run as a background daemon.
-   `-v, --verbose`: Enable verbose (debug) logging.
-   `-h, --help`: Show help message.

#### Proxying HTTP
```bash
curl -x http://localhost:8080 http://example.com
```

#### Proxying & Intercepting HTTPS
For TLS interception to work, you must instruct your client to trust the proxy's Certificate Authority. The CA certificate is generated automatically (e.g., in `ssl/ca.crt`).

```bash
# The --cacert flag tells curl to trust our custom CA for this one request.
curl --cacert ssl/ca.crt -x http://localhost:8080 https://example.com
```

### Extending Deadlight

#### Adding a New Protocol
The core strength of Deadlight is its extensible protocol system. To add support for a new protocol:
1.  Create `my_protocol.c` and `my_protocol.h` in the `src/protocols/` directory.
2.  Implement the `DeadlightProtocolHandler` interface:
    *   `detect`: A function that inspects a buffer and returns a non-zero value if it matches the protocol.
    *   `handle`: The main function to process the connection. It **must** return a `DeadlightHandlerResult` to correctly manage the connection's lifecycle (`HANDLER_SUCCESS_CLEANUP_NOW` for synchronous tasks, `HANDLER_SUCCESS_ASYNC` for asynchronous tasks).
    *   `cleanup`: An optional function for any protocol-specific cleanup.
3.  Create a public registration function, e.g., `deadlight_register_my_protocol_handler()`.
4.  Call your registration function from `deadlight_protocols_init()` in `src/core/protocols.c`.
5.  Add `src/protocols/my_protocol.c` to the `PROTOCOL_SOURCES` list in the `Makefile`.
6.  Recompile. Your protocol is now live.

### Project Structure
```
deadlight/
├── bin/                    # Compiled binaries
├── obj/                    # Compiled object files
├── ssl/                    # Directory for SSL certificates
├── src/
│   ├── core/               # Core modules (main, context, config, network, etc.)
│   ├── plugins/            # Built-in plugin implementations
│   └── protocols/          # Protocol handler implementations
├── deadlight.conf.example  # Example configuration file
├── Makefile                # Build configuration
└── README.md               # This file
```

### Development Status

### 6. Update Development Status:

**v5.0 BREAKTHROUGH:** Complete integration achieved with blog.deadlight!

- ✅ **REST API Server**: Full HTTP API implementation for external integration
- ✅ **Real-time Dashboard**: Minimalist web interface for proxy management  
- ✅ **Email Federation**: Working email-based social media federation
- ✅ **Multi-Protocol Support**: HTTP/HTTPS/SOCKS/SMTP/IMAP/IMAPS/API protocols
- ➡️ **SOCKS5 Enhancement**: Full authentication support (next milestone)
- 🚀 **Production Deployment**: VPS deployment with global CDN integration

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


### Support

☕  [Support is greatly appreciated! Buy me a coffee](coff.ee/gnarzillah)
