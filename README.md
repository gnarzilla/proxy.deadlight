# Deadlight Proxy

**A modular, protocol-agnostic, and high-performance proxy server written in C using the GLib ecosystem, designed for deep inspection and extensibility.**

![Proxy in terminal reacting to API calls from deadlight.boo](assets/interactive_proxy_dash.gif)

---

### Table of Contents
1.  [Overview](#overview)
2.  [Architecture](#architecture)
3.  [Features](#features)
4.  [Roadmap](#roadmap)
5.  [Getting Started](#getting-started)
6.  [Usage](#usage)
7.  [Extending Deadlight](#extending-deadlight)
9.  [Project Structure](#project-structure)
10.  [License](#license)
11. [Support](#support) 

---

![Deadlight Proxy Side-by-Side](assets/proxy_live_dual.png)

### Overview

`proxy.deadlight` is a high-performance network proxy that serves as a stateless protocol bridge. It connects mature, stateful TCP protocols (SMTP, IMAP, SOCKS) to the modern, stateless, and globally distributed serverless ecosystem.

By bridging these two worlds, the Deadlight Proxy enables a powerful new form of self-sovereign infrastructure. It eliminates the need for an "always-on" home server by delegating state management to a serverless database (Cloudflare D1), all while preserving the privacy and control of a self-hosted solution.

This release represents a major breakthrough, with a complete REST API that integrates with `blog.deadlight`. This allows for real-time proxy management, status monitoring, and email-based federation, all controlled from a web interface you can deploy anywhere in the world.

### Architecture

Deadlight’s core innovation is its decoupling of the protocol from the service.

**Stateless by Design:** Instead of maintaining a local database or a mail queue, the proxy translates TCP traffic into clean HTTP API calls. This offloads all state management to a globally available database, allowing the proxy to remain lightweight and stateless. It can be turned off without losing any data.

**Protocol Agnostic:** The proxy is not an "email server" or a "SOCKS proxy"—it’s a platform for handling any TCP-based protocol. Its modular architecture means you can add new protocol handlers (e.g., for XMPP or Matrix) as simple, self-contained C files without changing the core application.

**Eliminating the "Always-On" Server:** The proxy's design leverages **Cloudflare Tunnel** for secure, outbound-only connectivity. This means your home IP address is never exposed, your firewall can remain closed, and you don’t need to worry about dynamic IPs or complex NAT configurations. Your home machine becomes a trusted network gateway, not a public server.



                    🌐 DEADLIGHT ECOSYSTEM ARCHITECTURE 🌐

    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                            GLOBAL WEB LAYER                                 │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │  📱 Any Browser/Device → 🌐 Cloudflare CDN → ⚡ blog.deadlight Worker     │
    │                                               (REST API Client)             │
    └─────────────────────────┬───────────────────────────────────────────────────┘
                              │
                              │ HTTP/JSON API Calls
                              ▼
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                         LOCAL PROTOCOL BRIDGE                               │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │                        proxy.deadlight v5.0                                 │
    │                                                                             │
    │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐          │
    │  │    API          │    │   SMTP          │    │   SOCKS4/5      │          │
    │  │   Handler       │    │   Bridge        │    │   Proxy         │          │
    │  └─────────────────┘    └─────────────────┘    └─────────────────┘          │
    │                                                                             │
    │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐          │
    │  │   🌍 HTTP/S    │    │   📬 IMAP/S     │    │    Protocol     │          │
    │  │   Proxy         │    │   Tunnel        │    │   Detection     │          │
    │  └─────────────────┘    └─────────────────┘    └─────────────────┘          │
    └─────────────────────────┬───────────────────────────────────────────────────┘
                              │
                              │ Native TCP/SSL Protocols
                              ▼
    ┌──────────────────────────────────────────────────────────────────────────────┐
    │                          INTERNET SERVICES                                   │
    ├──────────────────────────────────────────────────────────────────────────────┤
    │  📧 SMTP Servers  │  📬 IMAP Servers  │  🌐 Web Sites  │  🏠 Other Proxies │
    └──────────────────────────────────────────────────────────────────────────────┘

    🎯 DEPLOYMENT MODEL:
    ┌────────────────────┐                    ┌────────────────────┐
    │   🌐 GLOBAL        │                    │   🏠 LOCAL        │
    │   deadlight.boo    │ ←─── API BRIDGE ──→│   proxy.deadlight  │
    │   Cloudflare       │                    │   VPS/Pi/Desktop   │
    │   Workers/Pages    │                    │   localhost:8080   │
    └────────────────────┘                    └────────────────────┘

![Deadlight Proxy/Blog Integration](assets/thatch-dt_proxy_browser_dual.png)

Deadlight is built on a modular design managed by a central `DeadlightContext`. A connection flows through the system as follows:
1.  The **Main Thread** runs a `GSocketService`, accepting new connections.
2.  Incoming connections are passed to a **Worker Thread** from a `GThreadPool`.
3.  The worker thread performs **Protocol Detection** by peeking at the initial bytes of the connection.
4.  The appropriate registered `DeadlightProtocolHandler` is invoked to handle the connection.
5.  The handler processes the request. It can either complete the request synchronously or, for long-lived tunnels, hand off control to **asynchronous I/O watchers** on its own thread's event loop. This prevents the worker thread from blocking.

This is all managed by a set of distinct managers:
-   **Network Manager**: Handles listener sockets, the worker pool, and connection state.
-   **SSL Manager**: Manages GIO/gnutls contexts, CA certificates, and performs SSL interception.
-   **Protocol System**: Manages the registration and detection of protocol handlers.
-   **Configuration Manager**: Parses INI-style configuration files.
-   **Connection Pool**: Manages and reuses upstream server connections.

### Features

- **High-Performance C Foundation:** Built with the robust and efficient GLib ecosystem for high-throughput, low-latency network I/O and multi-threaded connection handling.

- **Multi-Protocol Support:** A single binary can act as a bridge for HTTP/HTTPS, SOCKS, SMTP, IMAP/S, and a custom API.

- **API-First Design:** Complete REST API for external integration, enabling real-time status monitoring, email sending, and federation from any web application.

- **Email-based Federation:** A simplified, or revolutionary, approach to decentralized social media that uses proven email protocols for instance-to-instance communication, eliminating the need to invent a new protocol.

- **Advanced Security:** Features include on-the-fly TLS interception (for development/analysis), robust certificate validation, and a secure deployment model that leverages outbound-only connections.

**API Endpoints:**
- `GET /api/blog/status` - Blog service health and version info
- `GET /api/email/status` - Email queue status and processing metrics
- `POST /api/email/send` - Send emails through proxy SMTP bridge
- `POST /api/federation/send` - Federated blog post distribution via email

### Roadmap
#### v5.0 (Current):

+ **Stateless Protocol Bridge:** Complete integration with blog.deadlight via HTTP API endpoints.

+ **API-First:** Full REST API for real-time status and management.

+ **Email Federation:** Working email-based social media federation.

+ **Cloudflare Tunnel Integration:** Production-ready deployment using Cloudflare Tunnel.

+ **Plugin Ecosystem:** API for creating and sharing ad-blocking, analytics, and other plugins.

#### Future Considerations:

➡ **Local Web Interface:** A minimalist web server within the proxy for easy, direct configuration and debugging.

➡ **Mobile & Desktop Clients:** Publish an API specification to enable the development of native clients.

![Deadlight Proxy](assets/proxy.deadlight_test_commands.png)

### Getting Started

#### Prerequisites

-   A C99 compliant compiler (GCC or Clang)
-   `make`
-   `pkg-config`
-   GLib 2.0+ & GIO development libraries (`libglib2.0-dev`)
-   gnutls development libraries (`gnutls`)

On Debian/Ubuntu, install all prerequisites with:
```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config libglib2.0-dev libssl-dev glib-networking
```
- `build-essential`: Provides gcc, make, etc.
- `libglib2.0-dev`: The GLib core libraries and development headers.
- `gnutls`: GNU TLS functions.
- `glib-networking`: The essential backend for GIO's TLS functionality.

#### Building

Clone the repository and use the provided Makefile:
```bash
git clone https://github.com/gnarzilla/proxy.deadlight
cd proxy.deadlight
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
ca_cert_file = /home/thatch/.deadlight/ca/ca.crt
ca_key_file = /home/thatch/.deadlight/ca/ca.key
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
Add deadlight certificate to the trust store. If using Firefox you will also need to add via firefox's settings.
```bash
sudo cp ~/.deadlight/ca/ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```


### Usage

#### Example 1: HTTP/HTTPS Web Proxy

Configure your browser or system to use `http://localhost:8080` as its proxy. Or, use `curl`:

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

![Deadlight Proxy - thatch-dt](assets/thatch-dt_proxy.png)

Deploy the integrated blog.deadlight dashboard
```bash
# Terminal 1: Start the proxy server
./bin/deadlight -c deadlight.conf.example

# Terminal 2: Start the blog with proxy integration
cd ../deadlight
wrangler dev

# Or to deploy to your live site
wrangler deploy
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
The `DeadlightProtocolHandler` interface and modular design make extending the proxy simple and powerful. To add a new protocol, you simply implement a few functions, and the core handles everything else.
## Extending Deadlight

The DeadlightProtocolHandler interface and table-driven detection system make extending the proxy simple and powerful. To add a new protocol, you implement a few functions and add detection rules - the core handles everything else.

### Adding a New Protocol

To add support for a new protocol:

1. **Create protocol files** in `src/protocols/`: `my_protocol.c` and `my_protocol.h`

2. **Implement the DeadlightProtocolHandler interface:**
   - `detect`: Inspects initial bytes and returns a priority (0 = no match, higher = better match)
   - `handle`: Main function to process the connection. Returns:
     - `HANDLER_SUCCESS_CLEANUP_NOW` for synchronous completion
     - `HANDLER_SUCCESS_ASYNC` for async operations
     - `HANDLER_ERROR` on failure
   - `cleanup`: Optional protocol-specific cleanup

3. **Add detection rules** in `src/core/protocol_detection.c`:
   ```c
   // Add to protocol_table array
   {
       .name = "MyProtocol",
       .protocol_id = DEADLIGHT_PROTOCOL_MYPROTOCOL,
       .priority = 30,
       .rules = my_protocol_rules,
       .rule_count = 1
   }
   ```

4. **Update core files:**
   - Add enum value to `DeadlightProtocol` in `deadlight.h`
   - Add case to `deadlight_protocol_to_string()` in `protocols.c`
   - Register handler in `deadlight_protocols_init()` in `protocols.c`

5. **Add to Makefile:** Add `src/protocols/my_protocol.c` to `PROTOCOL_SOURCES`

6. **Recompile:** Your protocol is now live!

The table-driven detection system supports multiple matching types (exact, prefix, contains, custom) and compound rules (AND/OR), making it easy to handle complex protocol signatures.

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

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


### Support

☕  [Support is greatly appreciated! Buy me a coffee](coff.ee/gnarzillah)
