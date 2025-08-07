# Deadlight Proxy v4.0

A modular, high-performance, and extensible proxy server written in C using the GLib ecosystem. Designed for protocol-agnostic handling and deep inspection capabilities.

## Overview

Deadlight Proxy is a feature-rich proxy server built with a modern C plugin architecture. It provides a robust foundation for tunneling, modifying, and inspecting network traffic. While its initial focus is on HTTP/HTTPS with SSL interception, its core design allows for the integration of additional protocols like IMAP, SOCKS, and WebSockets through a clean plugin and protocol handler system.

## Features

- **Multi-Protocol Support**: Core engine designed to handle different protocols.
    - ✅ **HTTP/1.1**: Full support for proxying HTTP traffic.
    - ✅ **HTTPS (CONNECT Tunneling)**: Standard handling for HTTPS connections.
    - ✅ **HTTPS (SSL Interception)**: Man-in-the-Middle (MITM) capability for inspecting and modifying TLS traffic.
- **Extensible Plugin Architecture**: Add new features or modify traffic on the fly with custom plugins. Hooks are available for connection lifecycle, headers, and body content.
- **High Performance**:
    - Non-blocking I/O using GLib's event loop (`GMainLoop`).
    - Upstream connection pooling to reduce latency.
    - Worker thread pool for offloading intensive tasks.
- **Robust Operation**:
    - **Daemon Mode**: Run as a background service.
    - **Configuration**: INI-style configuration file (`deadlight.conf`) with hot-reloading.
    - **Logging**: Comprehensive and configurable logging subsystem.
    - **Graceful Shutdown**: Signal handling for clean exit and resource cleanup.
- **Developer Focused**:
    - **Built-in Test Framework**: Easily run unit tests for individual modules (`-t all`).
    - **Clean, Modular Codebase**: Logic is clearly separated into managers for network, SSL, plugins, etc.

## Architecture

The proxy is built on a modular design managed by a central `DeadlightContext`:

- **Main Context**: Holds the state of the application and pointers to all subsystems.
- **Network Manager**: Handles non-blocking I/O, listener sockets, and connection management using GIO.
- **SSL Manager**: Manages the OpenSSL context, CA certificates, and performs SSL interception.
- **Plugin Manager**: Loads, registers, and invokes plugins at various hooks in the connection lifecycle.
- **Protocol System**: Detects the protocol of an incoming connection and dispatches to the appropriate handler.
- **Configuration Manager**: Parses INI-style configuration files and monitors them for changes.
- **Connection Pool**: Manages and reuses upstream server connections for improved performance.

## Building

### Prerequisites

- GCC or Clang compiler
- GLib 2.0+ & GIO development libraries (`libglib2.0-dev`)
- OpenSSL development libraries (`libssl-dev`)
- pkg-config
- Make

### Compilation

```bash
make clean
make
```

The build process will create the `deadlight-proxy` executable in the project root.

## Configuration

The proxy uses an INI-style configuration file (e.g. `deadlight.conf`)

[core]
# Address to bind to. 0.0.0.0 for all interfaces.
address = 0.0.0.0
port = 8080
max_connections = 500
# Log level: error, warning, info, debug
log_level = info
pid_file = /var/run/deadlight.pid

[ssl]
# Enable SSL interception (MITM)
intercept_enabled = true
# Directory for CA certificate and generated certs
ca_cert_path = ./certs/deadlight-ca.crt
ca_key_path = ./certs/deadlight-ca.key

[plugins]
# List of plugins to load
enabled = adblocker, logger, stats

## Usage

### Starting the Proxy

```bash
# Run in foreground on port 8080
./deadlight -p 8080

# Run using a config file
./deadlight -c deadlight.conf

# Run as a daemon
sudo ./deadlight -d -c /etc/deadlight/deadlight.conf
```

<img width="949" height="878" alt="image" src="https://github.com/user-attachments/assets/7f3febdf-5621-4b7d-b834-c2f912a3fa3b" />


### Command Line Options

-c, --config FILE: Path to configuration file.
-p, --port PORT: Port to listen on (overrides config).
-d, --daemon: Run as a background daemon.
-v, --verbose: Enable verbose (debug) logging.
--pid-file FILE: Path to write PID file in daemon mode.
-t, --test MODULE: Run tests for a specific module (all, network, ssl, etc.).
-h, --help: Show help message.

### Testing the Proxy

Configure your HTTP client to use `localhost:8888` as the proxy:

```bash
# Using curl
curl -x http://localhost:8888 http://example.com

# For HTTPS
curl -x http://localhost:8888 https://example.com
```

## Project Structure

```
deadlight-proxy/
├── src/
│   ├── core/               # Core modules (main, context, config, logging, etc.)
│   │   ├── main.c
│   │   ├── context.c
│   │   ├── config.c
│   │   ├── network.c
│   │   ├── ssl.c
│   │   └── plugins.c
│   ├── plugins/            # Built-in plugin implementations
│   │   ├── adblocker.c
│   │   └── ...
│   ├── protocols/          # Protocol handler implementations
│   │   └── http.c
│   └── deadlight.h         # Main header with all public structures and APIs
├── certs/                  # Directory for SSL certificates
├── deadlight.conf.example  # Example configuration file
├── Makefile                # Build configuration
└── README.md               # This file
```

## Development Status

### Completed Features

- ✅ Core proxy functionality for HTTP/HTTPS
- ✅ Non-blocking network I/O
- ✅ Configuration file support with hot-reload
- ✅ Comprehensive logging system
- ✅ SSL/TLS support for secure connections
- ✅ HTTP CONNECT method for HTTPS tunneling
- ✅ Error handling and recovery
- ✅ Memory-efficient data forwarding

### Known Limitations

- Single-threaded architecture (uses event-driven model)
- Basic HTTP/1.1 support (no HTTP/2 yet)
- No authentication mechanisms implemented
- Limited to TCP-based protocols

## Performance

The proxy is designed for efficiency with:
- Non-blocking I/O to handle multiple connections
- Minimal memory copying during data forwarding
- Efficient buffer management
- Event-driven architecture avoiding thread overhead

## Contributing

This project is under active development. Key areas for contribution include:
- Performance optimizations
- Additional protocol support
- Enhanced security features
- Documentation improvements

## License

[License information to be added]

## Acknowledgments

Built using the excellent GLib framework and OpenSSL library. Special thanks to the open-source community for providing robust, well-documented libraries that make projects like this possible.
___
