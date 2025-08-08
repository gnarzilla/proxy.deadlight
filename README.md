# Deadlight Proxy v4.0

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

---

### Overview

Deadlight Proxy is a feature-rich proxy server built with a modern C architecture. It provides a robust foundation for tunneling, modifying, and inspecting network traffic. While its initial focus is on HTTP/HTTPS with SSL interception, its core design allows for the seamless integration of additional protocols like IMAP, SOCKS, and WebSockets through a clean protocol handler system.

### Features

-   **Multi-Protocol Support**: Core engine designed to handle different protocols.
    -   ✅ **HTTP/1.1**: Full support for proxying HTTP traffic.
    -   ✅ **HTTPS (CONNECT Tunneling)**: Standard handling for HTTPS connections.
    -   ✅ **HTTPS (SSL Interception)**: Man-in-the-Middle (MITM) capability for inspecting and modifying TLS traffic via on-the-fly certificate generation.
-   **High Performance**:
    -   **Multi-Threaded Worker Pool**: Handles concurrent connections efficiently across multiple CPU cores.
    -   **Asynchronous I/O**: Uses GLib's event loop for scalable, non-blocking operations on long-lived connections (like SSL tunnels).
    -   **Upstream Connection Pooling**: Reuses upstream connections to reduce latency and resource usage.
-   **Robust Operation**:
    -   **Daemon Mode**: Run as a background service.
    -   **Configuration**: INI-style configuration file (`deadlight.conf`) with hot-reloading support.
    -   **Comprehensive Logging**: Configurable logging subsystem with multiple levels and color-coded output.
    -   **Graceful Shutdown**: Signal handling for clean exit and resource cleanup.
-   **Extensible Architecture**:
    -   Add new features or modify traffic on the fly with custom plugins (hooks for connection lifecycle, headers, etc.).
    -   Easily add new protocol handlers to the core engine.

### Architecture

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
sudo apt-get install build-essential pkg-config libglib2.0-dev libssl-dev
```

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
# Address to bind to. 0.0.0.0 for all interfaces.
address = 0.0.0.0
port = 8080
worker_threads = 4
max_connections = 500
# Log level: error, warning, info, debug
log_level = info

[ssl]
# Enable SSL interception (MITM)
intercept_enabled = true
# Path to your CA certificate and key. They will be generated if they don't exist.
ca_cert = ./ssl/ca.crt
ca_key = ./ssl/ca.key
```

#### Running
```bash
./bin/deadlight -c deadlight.conf.example
```

### Usage

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

The proxy core is stable and the protocol-handling framework is complete.

**Known Limitations / Next Steps:**
-   Plain TCP tunnels (non-intercepted `CONNECT`) currently use a blocking loop. This should be refactored to use the asynchronous `GIOChannel` model.
-   HTTP/2 support is not yet implemented.
-   No proxy authentication mechanisms are implemented.
-   The plugin system is foundational and can be expanded with more hooks.

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.