#include "websocket.h"
#include <string.h>
#include <glib.h>
#include <gio/gio.h>
#include <glib/gchecksum.h>

#define WS_MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WebSocket protocol data
typedef struct {
    gboolean compression_enabled;
    GTimer *last_ping_timer;
    gboolean close_received;
    guint16 close_code;
    gchar *close_reason;
    guint64 messages_sent;
    guint64 messages_received;
} WebSocketData;

// Forward declarations
static gsize websocket_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult websocket_handle(DeadlightConnection *conn, GError **error);
static void websocket_cleanup(DeadlightConnection *conn);
static gchar* websocket_calculate_accept_key(const gchar *client_key);
static gboolean websocket_tunnel_with_inspection(DeadlightConnection *conn, GError **error);
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

static gboolean websocket_tunnel_with_inspection(DeadlightConnection *conn, GError **error) {
    WebSocketData *ws_data = (WebSocketData*)conn->protocol_data;
    
    g_info("Connection %lu: Starting WebSocket tunnel with frame inspection", conn->id);
    
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
    
    // For now, use simple tunneling
    // Full implementation would parse WebSocket frames here
    gboolean result = deadlight_network_tunnel_data(conn, error);
    
    g_info("Connection %lu: WebSocket session ended (messages sent: %lu, received: %lu)",
           conn->id, ws_data->messages_sent, ws_data->messages_received);
    
    return result;
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
    const gchar *ws_extensions = deadlight_request_get_header(conn->current_request, "Sec-WebSocket-Extensions");
    
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
    
    // Allocate WebSocket protocol data
    WebSocketData *ws_data = g_new0(WebSocketData, 1);
    ws_data->last_ping_timer = g_timer_new();
    conn->protocol_data = ws_data;
    
    // Check for compression extension
    if (ws_extensions && strstr(ws_extensions, "permessage-deflate")) {
        ws_data->compression_enabled = TRUE;
        g_info("Connection %lu: WebSocket compression requested", conn->id);
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
    g_info("Connection %lu: WebSocket upgrade request to %s:%d%s", 
           conn->id, host, port, 
           conn->current_request->path ? conn->current_request->path : "/");
    
    if (ws_protocol) {
        g_info("Connection %lu: WebSocket subprotocol requested: %s", conn->id, ws_protocol);
    }
    

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
    
    // Check for accepted extensions
    if (upgrade_success && ws_data->compression_enabled) {
        gchar *response_lower = g_ascii_strdown(response_str, -1);
        if (!strstr(response_lower, "sec-websocket-extensions:") ||
            !strstr(response_lower, "permessage-deflate")) {
            ws_data->compression_enabled = FALSE;
            g_info("Connection %lu: WebSocket compression not accepted by server", conn->id);
        } else {
            g_info("Connection %lu: WebSocket compression enabled", conn->id);
        }
        g_free(response_lower);
    }
    
    g_free(response_str);
    
    if (!upgrade_success) {
        g_warning("Connection %lu: WebSocket upgrade failed - upstream rejected", conn->id);
        g_free(host);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }
    
    g_info("Connection %lu: WebSocket upgrade successful, starting enhanced frame relay", conn->id);
    g_free(host);
    
    // Start WebSocket tunneling with inspection
    if (websocket_tunnel_with_inspection(conn, error)) {
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        return HANDLER_ERROR;
    }
}

static void websocket_cleanup(DeadlightConnection *conn) {
    if (conn->protocol_data) {
        WebSocketData *ws_data = (WebSocketData*)conn->protocol_data;
        
        if (ws_data->last_ping_timer) {
            g_timer_destroy(ws_data->last_ping_timer);
        }
        
        g_free(ws_data->close_reason);
        g_free(ws_data);
        conn->protocol_data = NULL;
    }
    
    g_debug("WebSocket cleanup called for conn %lu", conn->id);
}