# Deadlight Proxy v4.0

A lightweight, modular HTTP/HTTPS proxy server written in C using the GLib ecosystem.

## Overview

Deadlight Proxy is a high-performance proxy server designed with modularity and extensibility in mind. Built using modern C programming practices and the GLib framework, it provides a solid foundation for HTTP/HTTPS proxying with clean separation of concerns across different modules.

## Features

### Current Implementation (v4.0)

- **HTTP/HTTPS Support**: Full support for HTTP and HTTPS traffic proxying
- **CONNECT Method**: Handles HTTPS tunneling through CONNECT requests
- **Protocol Detection**: Automatic detection of HTTP vs HTTPS traffic
- **Non-blocking I/O**: Efficient handling of multiple concurrent connections
- **Modular Architecture**: Clean separation between networking, protocol handling, and configuration
- **Configuration Management**: YAML-based configuration with runtime file monitoring
- **Comprehensive Logging**: Multi-level logging system for debugging and monitoring
- **SSL/TLS Support**: OpenSSL integration for secure connections
- **Bidirectional Tunneling**: Efficient data forwarding between clients and upstream servers

## Architecture

The proxy is built with a modular design consisting of:

- **Core Engine**: Main event loop and connection management
- **Network Module**: Socket handling and non-blocking I/O operations
- **Protocol Module**: HTTP/HTTPS protocol parsing and handling
- **Configuration Module**: YAML configuration parsing and hot-reload support
- **Logging Module**: Structured logging with multiple verbosity levels
- **SSL Module**: TLS/SSL connection handling and certificate management

## Building

### Prerequisites

- GCC or Clang compiler
- GLib 2.0+ development libraries
- OpenSSL development libraries
- libyaml development libraries
- pkg-config
- Make

### Compilation

```bash
make clean
make
```

The build process will create the `deadlight-proxy` executable in the project root.

## Configuration

The proxy uses a YAML configuration file (`config.yaml`) with the following structure:

```yaml
proxy:
  host: "0.0.0.0"
  port: 8888
  max_connections: 1000
  timeout: 30

logging:
  level: "info"  # debug, info, warning, error
  file: "/var/log/deadlight-proxy.log"
  max_size: 10485760  # 10MB
  max_files: 5

ssl:
  cert_dir: "./certs"
  verify_upstream: true
```

## Usage

### Starting the Proxy

```bash
./deadlight-proxy -c config.yaml
```

### Command Line Options

- `-c, --config`: Path to configuration file (default: ./config.yaml)
- `-d, --debug`: Enable debug logging
- `-h, --help`: Show help message
- `-v, --version`: Show version information

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
│   ├── main.c              # Entry point and main loop
│   ├── network.c           # Network I/O operations
│   ├── protocol.c          # HTTP/HTTPS protocol handling
│   ├── config.c            # Configuration management
│   ├── logging.c           # Logging subsystem
│   └── ssl.c               # SSL/TLS handling
├── include/
│   └── deadlight-proxy.h   # Main header file
├── config.yaml             # Default configuration
├── Makefile               # Build configuration
└── README.md              # This file
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
