#include "websocket.h"
#include <string.h>
#include <glib.h>
#include <gio/gio.h>

// SHA-1 for WebSocket handshake
#include <glib/gchecksum.h>

// WebSocket magic string for handshake
#define WS_MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Forward declarations
static gsize websocket_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult websocket_handle(DeadlightConnection *conn, GError **error);
static void websocket_cleanup(DeadlightConnection *conn);
static gchar* websocket_calculate_accept_key(const gchar *client_key);
static gboolean websocket_tunnel_data(DeadlightConnection *conn, GError **error);
static gboolean parse_host_port(const gchar *host_port, gchar **host, guint16 *port);

// Protocol handler definition
static const DeadlightProtocolHandler websocket_protocol_handler = {
    .name = "WebSocket",
    .protocol_id = DEADLIGHT_PROTOCOL_WEBSOCKET,
    .detect = websocket_detect,
    .handle = websocket_handle,
    .cleanup = websocket_cleanup
};

void deadlight_register_websocket_handler(void) {
    deadlight_protocol_register(&websocket_protocol_handler);
}

static gsize websocket_detect(const guint8 *data, gsize len) {
    // WebSocket starts as HTTP GET request
    if (len < 4 || memcmp(data, "GET ", 4) != 0) {
        return 0;
    }
    
    // Convert to string for header searching
    gchar *request = g_strndup((const gchar*)data, len);
    gchar *request_lower = g_ascii_strdown(request, -1);
    
    // Check for required WebSocket headers
    gboolean has_upgrade = strstr(request_lower, "upgrade: websocket") != NULL;
    gboolean has_connection = strstr(request_lower, "connection:") && 
                             (strstr(request_lower, "upgrade") != NULL);
    gboolean has_ws_key = strstr(request_lower, "sec-websocket-key:") != NULL;
    gboolean has_ws_version = strstr(request_lower, "sec-websocket-version:") != NULL;
    
    g_free(request);
    g_free(request_lower);
    
    // All headers required for valid WebSocket request
    if (has_upgrade && has_connection && has_ws_key && has_ws_version) {
        return 20; // Higher priority than plain HTTP
    }
    
    return 0;
}

static gchar* websocket_calculate_accept_key(const gchar *client_key) {
    // Concatenate client key with magic string
    gchar *concat = g_strconcat(client_key, WS_MAGIC_STRING, NULL);
    
    // Calculate SHA-1 hash
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA1);
    g_checksum_update(checksum, (guchar*)concat, strlen(concat));
    
    // Get digest
    guint8 digest[20];
    gsize digest_len = 20;
    g_checksum_get_digest(checksum, digest, &digest_len);
    
    // Base64 encode
    gchar *accept_key = g_base64_encode(digest, digest_len);
    
    // Cleanup
    g_checksum_free(checksum);
    g_free(concat);
    
    return accept_key;
}

static gboolean parse_host_port(const gchar *host_port, gchar **host, guint16 *port) {
    if (!host_port || !host || !port) return FALSE;

    if (host_port[0] == '[') { // IPv6
        const gchar *end = strchr(host_port, ']');
        if (!end) return FALSE;
        *host = g_strndup(host_port + 1, end - (host_port + 1));
        if (*(end + 1) == ':') {
            *port = (guint16)strtoul(end + 2, NULL, 10);
        }
    } else { // IPv4 or hostname
        const gchar *colon = strrchr(host_port, ':');
        if (colon) {
            *host = g_strndup(host_port, colon - host_port);
            *port = (guint16)strtoul(colon + 1, NULL, 10);
        } else {
            *host = g_strdup(host_port);
        }
    }
    return (*host != NULL);
}

static DeadlightHandlerResult websocket_handle(DeadlightConnection *conn, GError **error) {
    // Parse the HTTP request
    conn->current_request = deadlight_request_new(conn);
    if (!deadlight_request_parse_headers(conn->current_request, 
                                        (const gchar *)conn->client_buffer->data, 
                                        conn->client_buffer->len)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, 
                    "Failed to parse WebSocket upgrade request");
        return HANDLER_ERROR;
    }
    
    // Validate WebSocket headers
    const gchar *upgrade = deadlight_request_get_header(conn->current_request, "Upgrade");
    const gchar *connection = deadlight_request_get_header(conn->current_request, "Connection");
    const gchar *ws_key = deadlight_request_get_header(conn->current_request, "Sec-WebSocket-Key");
    const gchar *ws_version = deadlight_request_get_header(conn->current_request, "Sec-WebSocket-Version");
    const gchar *ws_protocol = deadlight_request_get_header(conn->current_request, "Sec-WebSocket-Protocol");
    
    if (!upgrade || g_ascii_strcasecmp(upgrade, "websocket") != 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, 
                    "Invalid Upgrade header for WebSocket");
        return HANDLER_ERROR;
    }
    
    if (!connection || !strstr(g_ascii_strdown(connection, -1), "upgrade")) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, 
                    "Invalid Connection header for WebSocket");
        return HANDLER_ERROR;
    }
    
    if (!ws_key || strlen(ws_key) == 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, 
                    "Missing Sec-WebSocket-Key header");
        return HANDLER_ERROR;
    }
    
    if (!ws_version || strcmp(ws_version, "13") != 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, 
                    "Unsupported WebSocket version: %s", ws_version ? ws_version : "none");
        return HANDLER_ERROR;
    }
    
    // Extract target from Host header
    const gchar *host_header = deadlight_request_get_header(conn->current_request, "Host");
    if (!host_header) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Missing Host header");
        return HANDLER_ERROR;
    }
    
    gchar *host = NULL;
    guint16 port = 80; // Default for ws://
    
    // If this came through CONNECT (wss://), default port is 443
    if (conn->ssl_established || conn->client_tls) {
        port = 443;
    }
    
    if (!parse_host_port(host_header, &host, &port)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid Host header");
        return HANDLER_ERROR;
    }
    
    // Plugin hooks
    g_debug("Connection %lu: WebSocket upgrade request to %s:%d%s", 
        conn->id, host, port, conn->current_request->path ? conn->current_request->path : "/");
    
    if (!deadlight_plugins_call_on_request_headers(conn->context, conn->current_request)) {
        g_info("Connection %lu: WebSocket request blocked by plugin", conn->id);
        
        // Send HTTP 403 Forbidden response
        const gchar *response = "HTTP/1.1 403 Forbidden\r\n"
                               "Content-Length: 0\r\n"
                               "Connection: close\r\n\r\n";
        GOutputStream *client_output = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output, response, strlen(response), 
                                 NULL, NULL, NULL);
        g_free(host);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }
    
    // Check for proxy loops
    if ((g_strcmp0(host, conn->context->listen_address) == 0 || 
         g_strcmp0(host, "localhost") == 0 || 
         g_strcmp0(host, "127.0.0.1") == 0) && 
         port == conn->context->listen_port) {
        g_warning("Connection %lu: Detected WebSocket proxy loop to %s:%d", 
                  conn->id, host, port);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "Proxy loop detected");
        g_free(host);
        return HANDLER_ERROR;
    }
    
    // Connect to upstream
    g_info("Connection %lu: Connecting to WebSocket upstream %s:%d", conn->id, host, port);
    if (!deadlight_network_connect_upstream(conn, host, port, error)) {
        g_warning("Connection %lu: Failed to connect to WebSocket upstream %s:%d", 
                  conn->id, host, port);
        
        // Send HTTP 502 Bad Gateway response
        const gchar *response = "HTTP/1.1 502 Bad Gateway\r\n"
                               "Content-Length: 0\r\n"
                               "Connection: close\r\n\r\n";
        GOutputStream *client_output = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output, response, strlen(response), 
                                 NULL, NULL, NULL);
        g_free(host);
        return HANDLER_ERROR;
    }
    
    // If wss://, establish TLS with upstream
    if (conn->ssl_established || conn->client_tls) {
        g_info("Connection %lu: Establishing TLS for WSS connection", conn->id);
        if (!deadlight_network_establish_upstream_ssl(conn, error)) {
            g_free(host);
            return HANDLER_ERROR;
        }
    }
    
    // Forward the original upgrade request to upstream
    GOutputStream *upstream_output = g_io_stream_get_output_stream(
        conn->upstream_tls ? G_IO_STREAM(conn->upstream_tls) : 
                            G_IO_STREAM(conn->upstream_connection));
    
    if (!g_output_stream_write_all(upstream_output, 
                                   conn->client_buffer->data, 
                                   conn->client_buffer->len, 
                                   NULL, NULL, error)) {
        g_free(host);
        return HANDLER_ERROR;
    }
    
    // Read upstream response
    GInputStream *upstream_input = g_io_stream_get_input_stream(
        conn->upstream_tls ? G_IO_STREAM(conn->upstream_tls) : 
                            G_IO_STREAM(conn->upstream_connection));
    
    guint8 response_buffer[4096];
    gssize bytes_read = g_input_stream_read(upstream_input, response_buffer, 
                                            sizeof(response_buffer), NULL, error);
    
    if (bytes_read <= 0) {
        g_free(host);
        return HANDLER_ERROR;
    }
    
    // Forward response to client
    GOutputStream *client_output = g_io_stream_get_output_stream(
        conn->client_tls ? G_IO_STREAM(conn->client_tls) : 
                          G_IO_STREAM(conn->client_connection));
    
    if (!g_output_stream_write_all(client_output, response_buffer, bytes_read, 
                                   NULL, NULL, error)) {
        g_free(host);
        return HANDLER_ERROR;
    }
    
    // Check if upgrade was successful (101 Switching Protocols)
    gchar *response_str = g_strndup((const gchar*)response_buffer, bytes_read);
    gboolean upgrade_success = g_str_has_prefix(response_str, "HTTP/1.1 101") || 
                              g_str_has_prefix(response_str, "HTTP/1.0 101");
    g_free(response_str);
    
    if (!upgrade_success) {
        g_warning("Connection %lu: WebSocket upgrade failed - upstream rejected", conn->id);
        g_free(host);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }
    
    g_info("Connection %lu: WebSocket upgrade successful, starting frame relay", conn->id);
    g_free(host);
    
    // Start WebSocket tunneling
    if (websocket_tunnel_data(conn, error)) {
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        return HANDLER_ERROR;
    }
}

static gboolean websocket_tunnel_data(DeadlightConnection *conn, GError **error) {
    g_info("Connection %lu: Starting WebSocket tunnel", conn->id);
    
    // Get appropriate streams based on TLS status
    GInputStream *client_is = conn->client_tls ? 
        g_io_stream_get_input_stream(G_IO_STREAM(conn->client_tls)) :
        g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
    
    GOutputStream *client_os = conn->client_tls ?
        g_io_stream_get_output_stream(G_IO_STREAM(conn->client_tls)) :
        g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    
    GInputStream *upstream_is = conn->upstream_tls ?
        g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_tls)) :
        g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_connection));
    
    GOutputStream *upstream_os = conn->upstream_tls ?
        g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_tls)) :
        g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
    
    // Use larger buffer for WebSocket frames (max frame is typically 64KB)
    guint8 buffer[65536];
    gboolean running = TRUE;
    conn->state = DEADLIGHT_STATE_TUNNELING;
    
    // Get sockets for polling
    GSocket *client_socket = g_socket_connection_get_socket(conn->client_connection);
    GSocket *upstream_socket = g_socket_connection_get_socket(conn->upstream_connection);
    
    GPollFD fds[2];
    fds[0].fd = g_socket_get_fd(client_socket);
    fds[1].fd = g_socket_get_fd(upstream_socket);
    fds[0].events = G_IO_IN | G_IO_HUP | G_IO_ERR;
    fds[1].events = G_IO_IN | G_IO_HUP | G_IO_ERR;
    
    while (running && conn->state == DEADLIGHT_STATE_TUNNELING) {
        gint ready = g_poll(fds, 2, 1000); // 1 second timeout for periodic checks
        
        if (ready < 0) {
            if (errno != EINTR) {
                g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno),
                           "Poll failed: %s", g_strerror(errno));
                running = FALSE;
            }
            continue;
        }
        
        if (ready == 0) {
            // Timeout - could implement ping/pong here if needed
            continue;
        }
        
        // Client to upstream
        if (fds[0].revents & G_IO_IN) {
            gssize bytes_read = g_input_stream_read(client_is, buffer, sizeof(buffer), 
                                                   NULL, error);
            if (bytes_read > 0) {
                if (!g_output_stream_write_all(upstream_os, buffer, bytes_read, 
                                             NULL, NULL, error)) {
                    g_warning("Connection %lu: Failed to write to upstream: %s", 
                             conn->id, (*error)->message);
                    running = FALSE;
                } else {
                    conn->bytes_client_to_upstream += bytes_read;
                }
            } else if (bytes_read == 0) {
                g_debug("Connection %lu: Client closed WebSocket connection", conn->id);
                running = FALSE;
            } else {
                running = FALSE;
            }
        }
        
        if (fds[0].revents & (G_IO_HUP | G_IO_ERR)) {
            g_debug("Connection %lu: Client socket closed", conn->id);
            running = FALSE;
        }
        
        // Upstream to client
        if (fds[1].revents & G_IO_IN) {
            gssize bytes_read = g_input_stream_read(upstream_is, buffer, sizeof(buffer), 
                                                   NULL, error);
            if (bytes_read > 0) {
                if (!g_output_stream_write_all(client_os, buffer, bytes_read, 
                                             NULL, NULL, error)) {
                    g_warning("Connection %lu: Failed to write to client: %s", 
                             conn->id, (*error)->message);
                    running = FALSE;
                } else {
                    conn->bytes_upstream_to_client += bytes_read;
                }
            } else if (bytes_read == 0) {
                g_debug("Connection %lu: Upstream closed WebSocket connection", conn->id);
                running = FALSE;
            } else {
                running = FALSE;
            }
        }
        
        if (fds[1].revents & (G_IO_HUP | G_IO_ERR)) {
            g_debug("Connection %lu: Upstream socket closed", conn->id);
            running = FALSE;
        }
    }
    
    conn->state = DEADLIGHT_STATE_CLOSING;
    g_info("Connection %lu: WebSocket tunnel closed (client->upstream: %s, upstream->client: %s)",
           conn->id,
           deadlight_format_bytes(conn->bytes_client_to_upstream),
           deadlight_format_bytes(conn->bytes_upstream_to_client));
    
    return TRUE;
}

static void websocket_cleanup(DeadlightConnection *conn) {
    g_debug("WebSocket cleanup called for conn %lu", conn->id);
    // Any WebSocket-specific cleanup would go here
    // Currently, generic connection cleanup handles everything
}