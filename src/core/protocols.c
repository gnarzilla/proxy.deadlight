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
    
    // Now read the response from upstream and forward to client
    GInputStream *upstream_input = g_io_stream_get_input_stream(
        G_IO_STREAM(conn->upstream_connection));
    GOutputStream *client_output = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->client_connection));
    
    // Read and forward response
    guint8 buffer[8192];
    gssize bytes_read;
    
    while ((bytes_read = g_input_stream_read(upstream_input, buffer, 
                                            sizeof(buffer), NULL, error)) > 0) {
        gssize sent = g_output_stream_write(client_output, buffer, 
                                          bytes_read, NULL, error);
        if (sent > 0) {
            conn->bytes_upstream_to_client += sent;
        } else if (sent < 0) {
            return FALSE;
        }
    }
    
    // Check if we stopped due to error
    if (bytes_read < 0) {
        return FALSE;
    }
    
    g_info("Connection %lu: HTTP request completed (sent: %s, received: %s)", 
           conn->id,
           deadlight_format_bytes(conn->bytes_client_to_upstream),
           deadlight_format_bytes(conn->bytes_upstream_to_client));
    
    return TRUE;
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

    // Set target host BEFORE connecting (important for SSL interception)
    conn->target_host = g_strdup(host); 
    conn->target_port = port;


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
        // Intercept the SSL connection
        if (!deadlight_ssl_intercept_connection(conn, error)) {
            g_warning("Failed to intercept SSL for %s: %s", 
                     conn->target_host,  // Use conn->target_host instead of host
                     error && *error ? (*error)->message : "Unknown error");
            // Fall back to tunneling
            return deadlight_network_tunnel_data(conn, error);
        }
        
        // Now we can inspect/modify SSL traffic
        return deadlight_ssl_tunnel_data(conn, error);
    }
    // Regular tunneling without interception
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
    GSocket *socket = g_socket_connection_get_socket(conn->client_connection);
    GOutputStream *output = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->client_connection));
    
    // Get or create SOCKS5 state data
    Socks5Data *socks_data = g_hash_table_lookup(conn->plugin_data, "socks5");
    if (!socks_data) {
        socks_data = g_new0(Socks5Data, 1);
        socks_data->state = SOCKS5_STATE_INIT;
        g_hash_table_insert(conn->plugin_data, g_strdup("socks5"), socks_data);
    }
    
    guint8 buffer[512];
    gssize bytes_read;
    
    // State machine for SOCKS5 protocol
    while (socks_data->state != SOCKS5_STATE_CONNECTED) {
        switch (socks_data->state) {
            case SOCKS5_STATE_INIT: {
                // Phase 1: Client greeting
                // We should have initial data in conn->client_buffer
                if (conn->client_buffer->len < 3) {
                    g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                               "Incomplete SOCKS5 greeting");
                    return FALSE;
                }
                
                guint8 *data = conn->client_buffer->data;
                if (data[0] != SOCKS5_VERSION) {
                    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                               "Invalid SOCKS5 version: %02x", data[0]);
                    return FALSE;
                }
                
                guint8 nmethods = data[1];
                if (conn->client_buffer->len < 2 + nmethods) {
                    g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                               "Incomplete method list");
                    return FALSE;
                }
                
                // Check supported auth methods
                gboolean has_no_auth = FALSE;
                gboolean has_password = FALSE;
                
                for (int i = 0; i < nmethods; i++) {
                    if (data[2 + i] == SOCKS5_AUTH_NONE) has_no_auth = TRUE;
                    if (data[2 + i] == SOCKS5_AUTH_PASSWORD) has_password = TRUE;
                }
                
                // Select authentication method
                guint8 selected_method = SOCKS5_AUTH_NO_ACCEPTABLE;
                
                if (conn->context->auth_endpoint && has_password) {
                    selected_method = SOCKS5_AUTH_PASSWORD;
                    socks_data->auth_method = SOCKS5_AUTH_PASSWORD;
                    socks_data->state = SOCKS5_STATE_AUTH;
                } else if (has_no_auth) {
                    selected_method = SOCKS5_AUTH_NONE;
                    socks_data->auth_method = SOCKS5_AUTH_NONE;
                    socks_data->state = SOCKS5_STATE_REQUEST;
                }
                
                // Send method selection response
                guint8 response[2] = {SOCKS5_VERSION, selected_method};
                if (g_output_stream_write(output, response, 2, NULL, error) < 0) {
                    return FALSE;
                }
                
                if (selected_method == SOCKS5_AUTH_NO_ACCEPTABLE) {
                    g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                               "No acceptable authentication methods");
                    return FALSE;
                }
                
                // Clear processed data from buffer
                g_byte_array_remove_range(conn->client_buffer, 0, 2 + nmethods);
                
                // If no auth required, continue to request phase
                if (socks_data->state == SOCKS5_STATE_REQUEST) {
                    continue;
                }
                break;
            }
            
            case SOCKS5_STATE_AUTH: {
                // Phase 2: Username/password authentication
                bytes_read = g_socket_receive(socket, (gchar *)buffer, 
                                            sizeof(buffer), NULL, error);
                if (bytes_read <= 0) {
                    return FALSE;
                }
                
                // Auth request format: [version=1][ulen][username][plen][password]
                if (buffer[0] != 0x01) {
                    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                               "Invalid auth version");
                    return FALSE;
                }
                
                if (bytes_read < 2) {
                    g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                               "Incomplete auth header");
                    return FALSE;
                }
                
                guint8 ulen = buffer[1];
                if (bytes_read < 2 + ulen + 1) {
                    g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                               "Incomplete username");
                    return FALSE;
                }
                
                gchar *username = g_strndup((gchar *)&buffer[2], ulen);
                guint8 plen = buffer[2 + ulen];
                
                if (bytes_read < 2 + ulen + 1 + plen) {
                    g_free(username);
                    g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                               "Incomplete password");
                    return FALSE;
                }
                
                gchar *password = g_strndup((gchar *)&buffer[3 + ulen], plen);
                
                // Perform authentication
                gboolean authenticated = FALSE;
                if (conn->context->auth_endpoint) {
                    // TODO: Call your auth endpoint
                    // authenticated = deadlight_auth_check(conn->context, username, password);
                    authenticated = TRUE; // Placeholder
                }
                
                // Send auth response: [version=1][status]
                guint8 auth_response[2] = {0x01, authenticated ? 0x00 : 0xFF};
                if (g_output_stream_write(output, auth_response, 2, NULL, error) < 0) {
                    g_free(username);
                    g_free(password);
                    return FALSE;
                }
                
                if (!authenticated) {
                    g_free(username);
                    g_free(password);
                    g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                               "Authentication failed");
                    return FALSE;
                }
                
                conn->username = username; // Store authenticated user
                g_free(password);
                
                socks_data->state = SOCKS5_STATE_REQUEST;
                break;
            }
            
            case SOCKS5_STATE_REQUEST: {
                // Phase 3: Connection request
                // Check if we have buffered data first
                if (conn->client_buffer->len > 0) {
                    bytes_read = MIN(conn->client_buffer->len, sizeof(buffer));
                    memcpy(buffer, conn->client_buffer->data, bytes_read);
                    g_byte_array_remove_range(conn->client_buffer, 0, bytes_read);
                } else {
                    bytes_read = g_socket_receive(socket, (gchar *)buffer, 
                                                sizeof(buffer), NULL, error);
                    if (bytes_read <= 0) {
                        return FALSE;
                    }
                }
                
                // Request format: [ver][cmd][rsv][atyp][addr][port]
                if (bytes_read < 10) {
                    g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                               "Incomplete SOCKS5 request");
                    return FALSE;
                }
                
                if (buffer[0] != SOCKS5_VERSION) {
                    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                               "Invalid request version");
                    return FALSE;
                }
                
                guint8 cmd = buffer[1];
                if (cmd != SOCKS5_CMD_CONNECT) {
                    // Send error reply
                    guint8 reply[10] = {SOCKS5_VERSION, SOCKS5_REP_COMMAND_NOT_SUPPORTED,
                                       0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0};
                    g_output_stream_write(output, reply, 10, NULL, NULL);
                    g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                               "Command %d not supported", cmd);
                    return FALSE;
                }
                
                // Parse destination address
                gchar *target_host = NULL;
                guint16 target_port = 0;
                guint8 atyp = buffer[3];
                gint addr_offset = 4;
                gint port_offset;
                
                switch (atyp) {
                    case SOCKS5_ATYP_IPV4:
                        if (bytes_read < 10) {
                            g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                                       "Incomplete IPv4 address");
                            return FALSE;
                        }
                        target_host = g_strdup_printf("%d.%d.%d.%d",
                                                     buffer[4], buffer[5], 
                                                     buffer[6], buffer[7]);
                        port_offset = 8;
                        break;
                        
                    case SOCKS5_ATYP_DOMAIN: {
                        guint8 domain_len = buffer[4];
                        if (bytes_read < 7 + domain_len) {
                            g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                                       "Incomplete domain name");
                            return FALSE;
                        }
                        target_host = g_strndup((gchar *)&buffer[5], domain_len);
                        port_offset = 5 + domain_len;
                        break;
                    }
                    
                    case SOCKS5_ATYP_IPV6:
                        if (bytes_read < 22) {
                            g_set_error(error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                                       "Incomplete IPv6 address");
                            return FALSE;
                        }
                        target_host = g_strdup_printf(
                            "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                            "%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
                            buffer[4], buffer[5], buffer[6], buffer[7],
                            buffer[8], buffer[9], buffer[10], buffer[11],
                            buffer[12], buffer[13], buffer[14], buffer[15],
                            buffer[16], buffer[17], buffer[18], buffer[19]);
                        port_offset = 20;
                        break;
                        
                    default:
                        // Send error reply
                        guint8 reply[10] = {SOCKS5_VERSION, SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED,
                                           0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0};
                        g_output_stream_write(output, reply, 10, NULL, NULL);
                        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                                   "Address type %d not supported", atyp);
                        return FALSE;
                }
                
                // Get port
                target_port = (buffer[port_offset] << 8) | buffer[port_offset + 1];
                
                g_info("Connection %lu: SOCKS5 CONNECT to %s:%d", 
                       conn->id, target_host, target_port);
                
                // Try to connect to target
                if (!deadlight_network_connect_upstream(conn, target_host, 
                                                       target_port, error)) {
                    // Send error reply
                    guint8 reply[10] = {SOCKS5_VERSION, SOCKS5_REP_HOST_UNREACHABLE,
                                       0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0};
                    g_output_stream_write(output, reply, 10, NULL, NULL);
                    g_free(target_host);
                    return FALSE;
                }
                
                // Build success reply (echo back the address info)
                gint reply_len = port_offset + 2;
                guint8 *reply = g_malloc(reply_len);
                memcpy(reply, buffer, reply_len);
                reply[0] = SOCKS5_VERSION;
                reply[1] = SOCKS5_REP_SUCCESS;
                reply[2] = 0x00; // Reserved
                
                if (g_output_stream_write(output, reply, reply_len, NULL, error) < 0) {
                    g_free(reply);
                    g_free(target_host);
                    return FALSE;
                }
                
                g_free(reply);
                g_free(target_host);
                
                socks_data->state = SOCKS5_STATE_CONNECTED;
                break;
            }
            
            default:
                g_assert_not_reached();
        }
    }
    
    // Start tunneling data
    return deadlight_network_tunnel_data(conn, error);
}
    
    //
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