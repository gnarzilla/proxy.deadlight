/**
 * Deadlight Proxy v4.0 - Protocol Handler
 *
 * Protocol detection and handling for HTTP, HTTPS, SOCKS, etc.
 */

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <ctype.h>

#include "deadlight.h"

// HTTP methods
static const gchar *http_methods[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", 
    "PATCH", NULL
};

// Forward declarations
static gboolean handle_http_request(DeadlightConnection *conn, GError **error);
static gboolean handle_connect_request(DeadlightConnection *conn, GError **error);
static gboolean handle_socks4_request(DeadlightConnection *conn, GError **error);
static gboolean handle_socks5_request(DeadlightConnection *conn, GError **error);
static gboolean parse_http_request_line(const gchar *line, gchar **method, 
                                       gchar **uri, gchar **version);
static gboolean parse_host_port(const gchar *host_port, gchar **host, guint16 *port);

/**
 * Detect protocol from initial bytes
 */
DeadlightProtocol deadlight_protocol_detect(const guint8 *data, gsize length) {
    g_return_val_if_fail(data != NULL, DEADLIGHT_PROTOCOL_UNKNOWN);
    g_return_val_if_fail(length > 0, DEADLIGHT_PROTOCOL_UNKNOWN);
    
    // Check for HTTP methods
    for (int i = 0; http_methods[i]; i++) {
        gsize method_len = strlen(http_methods[i]);
        if (length >= method_len + 1 && 
            memcmp(data, http_methods[i], method_len) == 0 &&
            data[method_len] == ' ') {
            
            // Special case for CONNECT method (HTTPS proxy)
            if (strcmp(http_methods[i], "CONNECT") == 0) {
                return DEADLIGHT_PROTOCOL_CONNECT;
            }
            return DEADLIGHT_PROTOCOL_HTTP;
        }
    }
    
    // Check for SOCKS4
    if (length >= 2 && data[0] == 0x04) {
        return DEADLIGHT_PROTOCOL_SOCKS4;
    }
    
    // Check for SOCKS5
    if (length >= 2 && data[0] == 0x05) {
        return DEADLIGHT_PROTOCOL_SOCKS5;
    }
    
    // Check for TLS/SSL handshake (client hello)
    if (length >= 6 && 
        data[0] == 0x16 &&  // Handshake
        data[1] == 0x03 &&  // SSL 3.0 or TLS
        (data[2] >= 0x00 && data[2] <= 0x04)) {  // TLS version
        return DEADLIGHT_PROTOCOL_HTTPS;
    }
    
    return DEADLIGHT_PROTOCOL_UNKNOWN;
}

/**
 * Convert protocol enum to string
 */
const gchar *deadlight_protocol_to_string(DeadlightProtocol protocol) {
    switch (protocol) {
        case DEADLIGHT_PROTOCOL_HTTP: return "HTTP";
        case DEADLIGHT_PROTOCOL_HTTPS: return "HTTPS";
        case DEADLIGHT_PROTOCOL_SOCKS4: return "SOCKS4";
        case DEADLIGHT_PROTOCOL_SOCKS5: return "SOCKS5";
        case DEADLIGHT_PROTOCOL_CONNECT: return "CONNECT";
        case DEADLIGHT_PROTOCOL_WEBSOCKET: return "WebSocket";
        default: return "Unknown";
    }
}

/**
 * Handle protocol request
 */
gboolean deadlight_protocol_handle_request(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    
    switch (conn->protocol) {
        case DEADLIGHT_PROTOCOL_HTTP:
            return handle_http_request(conn, error);
            
        case DEADLIGHT_PROTOCOL_CONNECT:
            return handle_connect_request(conn, error);
            
        case DEADLIGHT_PROTOCOL_SOCKS4:
            return handle_socks4_request(conn, error);
            
        case DEADLIGHT_PROTOCOL_SOCKS5:
            return handle_socks5_request(conn, error);
            
        case DEADLIGHT_PROTOCOL_HTTPS:
            // Direct HTTPS not supported without CONNECT
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                       "Direct HTTPS connections not supported");
            return FALSE;
            
        default:
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                       "Protocol %s not supported", 
                       deadlight_protocol_to_string(conn->protocol));
            return FALSE;
    }
}

/**
 * Handle HTTP request
 */
static gboolean handle_http_request(DeadlightConnection *conn, GError **error) {
    DeadlightContext *context = conn->context;
    
    // Parse request
    conn->current_request = deadlight_request_new(conn);
    
    // Find the end of headers
    gchar *headers_end = NULL;
    for (gsize i = 0; i < conn->client_buffer->len - 3; i++) {
        if (conn->client_buffer->data[i] == '\r' &&
            conn->client_buffer->data[i+1] == '\n' &&
            conn->client_buffer->data[i+2] == '\r' &&
            conn->client_buffer->data[i+3] == '\n') {
            headers_end = (gchar *)&conn->client_buffer->data[i+4];
            break;
        }
    }
    
    if (!headers_end) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                   "Incomplete HTTP headers");
        return FALSE;
    }
    
    // Parse headers
    gchar *headers_str = g_strndup((gchar *)conn->client_buffer->data, 
                                  headers_end - (gchar *)conn->client_buffer->data);
    
    gchar **lines = g_strsplit(headers_str, "\r\n", -1);
    g_free(headers_str);
    
    if (!lines || !lines[0]) {
        g_strfreev(lines);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid HTTP request");
        return FALSE;
    }
    
    // Parse request line
    if (!parse_http_request_line(lines[0], &conn->current_request->method,
                                &conn->current_request->uri,
                                &conn->current_request->version)) {
        g_strfreev(lines);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid HTTP request line");
        return FALSE;
    }
    
    // Parse headers
    for (int i = 1; lines[i] && strlen(lines[i]) > 0; i++) {
        gchar *colon = strchr(lines[i], ':');
        if (colon) {
            *colon = '\0';
            gchar *name = g_strstrip(lines[i]);
            gchar *value = g_strstrip(colon + 1);
            g_hash_table_insert(conn->current_request->headers,
                              g_ascii_strdown(name, -1),
                              g_strdup(value));
        }
    }
    g_strfreev(lines);
    
    // Get host header
    const gchar *host_header = g_hash_table_lookup(conn->current_request->headers, "host");
    if (!host_header) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Missing Host header");
        return FALSE;
    }
    
    // Parse host and port
    gchar *host = NULL;
    guint16 port = 80;
    if (!parse_host_port(host_header, &host, &port)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid Host header");
        return FALSE;
    }
    
        conn->current_request->host = host;
    conn->current_request->port = port;
    
    g_info("Connection %lu: HTTP %s request to %s:%d", 
           conn->id, conn->current_request->method, host, port);
    
    // Connect to upstream
    if (!deadlight_network_connect_upstream(conn, host, port, error)) {
        return FALSE;
    }
    
    // Send request to upstream
    GOutputStream *upstream_output = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->upstream_connection));
    
    gssize bytes_written = g_output_stream_write(upstream_output,
                                                conn->client_buffer->data,
                                                conn->client_buffer->len,
                                                NULL, error);
    
    if (bytes_written < 0) {
        return FALSE;
    }
    
    conn->bytes_client_to_upstream += bytes_written;
    
    // Now tunnel the connection
    return deadlight_network_tunnel_data(conn, error);
}

/**
 * Handle CONNECT request (HTTPS proxy)
 */
static gboolean handle_connect_request(DeadlightConnection *conn, GError **error) {
    // Parse CONNECT request
    gchar *request_line = NULL;
    for (gsize i = 0; i < conn->client_buffer->len - 1; i++) {
        if (conn->client_buffer->data[i] == '\r' &&
            conn->client_buffer->data[i+1] == '\n') {
            request_line = g_strndup((gchar *)conn->client_buffer->data, i);
            break;
        }
    }
    
    if (!request_line) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                   "Incomplete CONNECT request");
        return FALSE;
    }
    
    // Parse CONNECT line
    gchar **parts = g_strsplit(request_line, " ", 3);
    g_free(request_line);
    
    if (!parts || !parts[0] || !parts[1] || 
        strcmp(parts[0], "CONNECT") != 0) {
        g_strfreev(parts);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid CONNECT request");
        return FALSE;
    }
    
    // Parse host:port
    gchar *host = NULL;
    guint16 port = 443;  // Default HTTPS port
    if (!parse_host_port(parts[1], &host, &port)) {
        g_strfreev(parts);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid host:port in CONNECT request");
        return FALSE;
    }
    g_strfreev(parts);
    
    g_info("Connection %lu: CONNECT request to %s:%d", conn->id, host, port);
    
    // Connect to upstream
    if (!deadlight_network_connect_upstream(conn, host, port, error)) {
        g_free(host);
        return FALSE;
    }
    g_free(host);
    
    // Send 200 Connection Established response
    const gchar *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    GOutputStream *client_output = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->client_connection));
    
    if (g_output_stream_write(client_output, response, strlen(response), 
                             NULL, error) < 0) {
        return FALSE;
    }
    
    // Check if SSL interception is enabled
    if (conn->context->ssl_intercept_enabled) {
        // TODO: Implement SSL interception
        g_debug("SSL interception would happen here");
    }
    
    // Tunnel the connection
    return deadlight_network_tunnel_data(conn, error);
}

/**
 * Handle SOCKS4 request
 */
static gboolean handle_socks4_request(DeadlightConnection *conn, GError **error) {
    // SOCKS4 requires at least 9 bytes
    if (conn->client_buffer->len < 9) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                   "Incomplete SOCKS4 request");
        return FALSE;
    }
    
    guint8 *data = conn->client_buffer->data;
    
    // Check version
    if (data[0] != 0x04) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid SOCKS4 version");
        return FALSE;
    }
    
    // Get command (1 = connect)
    if (data[1] != 0x01) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                   "SOCKS4 command %d not supported", data[1]);
        return FALSE;
    }
    
    // Get port
    guint16 port = (data[2] << 8) | data[3];
    
    // Get IP address
    gchar ip_str[16];
    g_snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
               data[4], data[5], data[6], data[7]);
    
    g_info("Connection %lu: SOCKS4 request to %s:%d", conn->id, ip_str, port);
    
    // Connect to upstream
    if (!deadlight_network_connect_upstream(conn, ip_str, port, error)) {
        // Send SOCKS4 error response
        guint8 response[8] = {0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        GOutputStream *output = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write(output, response, 8, NULL, NULL);
        return FALSE;
    }
    
    // Send SOCKS4 success response
    guint8 response[8] = {0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    GOutputStream *output = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->client_connection));
    
    if (g_output_stream_write(output, response, 8, NULL, error) < 0) {
        return FALSE;
    }
    
    // Tunnel the connection
    return deadlight_network_tunnel_data(conn, error);
}

/**
 * Handle SOCKS5 request
 */
static gboolean handle_socks5_request(DeadlightConnection *conn, GError **error) {
    // This is a simplified SOCKS5 implementation
    // Full implementation would include authentication methods
    
    if (conn->client_buffer->len < 3) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                   "Incomplete SOCKS5 handshake");
        return FALSE;
    }
    
    guint8 *data = conn->client_buffer->data;
    
    // Check version
    if (data[0] != 0x05) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid SOCKS5 version");
        return FALSE;
    }
    
    // For simplicity, we'll just send "no authentication required"
    guint8 auth_response[2] = {0x05, 0x00};
    GOutputStream *output = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->client_connection));
    
    if (g_output_stream_write(output, auth_response, 2, NULL, error) < 0) {
        return FALSE;
    }
    
    // TODO: Implement full SOCKS5 protocol
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
               "SOCKS5 not fully implemented yet");
    return FALSE;
}

/**
 * Parse HTTP request line
 */
static gboolean parse_http_request_line(const gchar *line, gchar **method,
                                       gchar **uri, gchar **version) {
    gchar **parts = g_strsplit(line, " ", 3);
    
    if (!parts || !parts[0] || !parts[1] || !parts[2]) {
        g_strfreev(parts);
        return FALSE;
    }
    
    *method = g_strdup(parts[0]);
    *uri = g_strdup(parts[1]);
    *version = g_strdup(parts[2]);
    
    g_strfreev(parts);
    return TRUE;
}

/**
 * Parse host:port string
 */
static gboolean parse_host_port(const gchar *host_port, gchar **host, guint16 *port) {
    if (!host_port || !host || !port) {
        return FALSE;
    }
    
    // Check for IPv6 address [host]:port
    if (host_port[0] == '[') {
        const gchar *close_bracket = strchr(host_port, ']');
        if (!close_bracket) {
            return FALSE;
        }
        
        *host = g_strndup(host_port + 1, close_bracket - host_port - 1);
        
        if (*(close_bracket + 1) == ':') {
            *port = (guint16)g_ascii_strtoull(close_bracket + 2, NULL, 10);
        }
    } else {
        // IPv4 or hostname
        const gchar *colon = strrchr(host_port, ':');
        if (colon) {
            *host = g_strndup(host_port, colon - host_port);
            *port = (guint16)g_ascii_strtoull(colon + 1, NULL, 10);
        } else {
            *host = g_strdup(host_port);
            // *port already has default value
        }
    }
    
    return TRUE;
}

/**
 * Handle protocol response (stub for now)
 */
gboolean deadlight_protocol_handle_response(DeadlightConnection *connection, GError **error) {
    // TODO: Implement response handling for plugins
    (void)connection;
    (void)error;
    return TRUE;
}