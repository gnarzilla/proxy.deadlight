#include "websocket.h"
#include <string.h>
#include <glib.h>
#include <gio/gio.h>
#include <glib/gchecksum.h>
#include "core/utils.h"

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
static gboolean websocket_frame_relay_loop(DeadlightConnection *conn, GError **error);

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

// The corrected read_ws_frame function
static gboolean read_ws_frame(GInputStream *is, WebSocketFrame *frame, GError **error) {
    guint8 header[2];
    // [FIX] Correct arguments for g_input_stream_read_all
    if (!g_input_stream_read_all(is, header, 2, NULL, NULL, error)) return FALSE;

    frame->fin = (header[0] & 0x80) != 0;
    frame->opcode = header[0] & 0x0F;
    gboolean masked = (header[1] & 0x80) != 0;
    guint64 len = header[1] & 0x7F;

    if (len == 126) {
        guint16 len16;
        if (!g_input_stream_read_all(is, &len16, 2, NULL, NULL, error)) return FALSE;
        len = g_ntohs(len16);
    } else if (len == 127) {
        guint64 len64;
        if (!g_input_stream_read_all(is, &len64, 8, NULL, NULL, error)) return FALSE;
        if (G_BYTE_ORDER == G_LITTLE_ENDIAN) {
            len = GUINT64_SWAP_LE_BE(len64);
        } else {
            len = len64;
        }
    }
    frame->payload_len = len;

    guint8 mask_key[4];
    if (masked) {
        if (!g_input_stream_read_all(is, mask_key, 4, NULL, NULL, error)) return FALSE;
    }

    frame->payload = g_malloc(frame->payload_len);
    if (!g_input_stream_read_all(is, frame->payload, frame->payload_len, NULL, NULL, error)) {
        g_free(frame->payload);
        return FALSE;
    }
    if (masked) {
        for (guint64 i = 0; i < frame->payload_len; i++) {
            frame->payload[i] ^= mask_key[i % 4];
        }
    }
    return TRUE; 
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

static gboolean websocket_frame_relay_loop(DeadlightConnection *conn, GError **error) {
    (void)error; // Mark as unused for now.
    WebSocketData *ws_data = (WebSocketData*)conn->protocol_data;

    GInputStream *client_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
    // GInputStream *upstream_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_connection));

    while (!ws_data->close_received && !conn->context->shutdown_requested) {
        WebSocketFrame frame = {0};
        
        if (read_ws_frame(client_is, &frame, NULL)) {
            if (frame.opcode == WS_OPCODE_TEXT) {
                g_info("C->S [%lu]: %.*s", conn->id, (int)frame.payload_len, (char*)frame.payload);
            } else if (frame.opcode == WS_OPCODE_CLOSE) {
                ws_data->close_received = TRUE;
            }
            // TODO: Write frame to upstream
            g_free(frame.payload);
        } else {
            break; // Connection closed or error
        }
        
        // TODO: Read from upstream
    }
    return TRUE;
}

static DeadlightHandlerResult websocket_handle(DeadlightConnection *conn, GError **error) {
    conn->current_request = deadlight_request_new(conn);
    if (!deadlight_request_parse_headers(conn->current_request, (const gchar *)conn->client_buffer->data, conn->client_buffer->len)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Failed to parse WebSocket upgrade request");
        return HANDLER_ERROR;
    }
    
    const gchar *ws_key = deadlight_request_get_header(conn->current_request, "Sec-WebSocket-Key");
    if (!ws_key) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Missing Sec-WebSocket-Key header");
        return HANDLER_ERROR;
    }
    
    gchar *accept_key = websocket_calculate_accept_key(ws_key);

    GString *response = g_string_new("HTTP/1.1 101 Switching Protocols\r\n");
    g_string_append(response, "Upgrade: websocket\r\n");
    g_string_append(response, "Connection: Upgrade\r\n");
    g_string_append_printf(response, "Sec-WebSocket-Accept: %s\r\n\r\n", accept_key);
    g_free(accept_key);
    
    const gchar *host_header = deadlight_request_get_header(conn->current_request, "Host");
    gchar *host = NULL;
    guint16 port = 80;
    if (!deadlight_parse_host_port(host_header, &host, &port)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid Host header");
        g_string_free(response, TRUE);
        return HANDLER_ERROR;
    }

    if (!deadlight_network_connect_upstream(conn, host, port, error)) {
        g_free(host);
        g_string_free(response, TRUE);
        return HANDLER_ERROR;
    }
    
    GString *upstream_request = g_string_new("");
    g_string_append_printf(upstream_request, "GET %s HTTP/1.1\r\n", conn->current_request->path);
    g_string_append_printf(upstream_request, "Host: %s\r\n", host_header);
    g_string_append(upstream_request, "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n");

    guchar client_key_buf[16];
    for (int i = 0; i < 16; i++) { client_key_buf[i] = g_random_int_range(0, 256); }
    gchar *new_client_key = g_base64_encode(client_key_buf, sizeof(client_key_buf));
    g_string_append_printf(upstream_request, "Sec-WebSocket-Key: %s\r\n\r\n", new_client_key);
    g_free(new_client_key);

    GOutputStream *upstream_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
    g_output_stream_write_all(upstream_output, upstream_request->str, upstream_request->len, NULL, NULL, error);
    g_string_free(upstream_request, TRUE);

    GInputStream *upstream_input = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_connection));
    guint8 response_buffer[4096];
    gssize bytes_read = g_input_stream_read(upstream_input, response_buffer, sizeof(response_buffer) - 1, NULL, error);
    
    if (bytes_read <= 0) {
        g_free(host);
        g_string_free(response, TRUE);
        return HANDLER_ERROR;
    }
    
    response_buffer[bytes_read] = '\0';
    if (!g_str_has_prefix((char*)response_buffer, "HTTP/1.1 101")) {
        GOutputStream *client_output_err = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output_err, response_buffer, bytes_read, NULL, NULL, NULL);
        g_free(host);
        g_string_free(response, TRUE);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    GOutputStream *client_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    g_output_stream_write_all(client_output, response->str, response->len, NULL, NULL, error);
    g_string_free(response, TRUE);

    g_info("Connection %lu: WebSocket MITM established. Relaying frames.", conn->id);
    g_free(host);
    
    // Allocate WebSocket protocol data
    WebSocketData *ws_data = g_new0(WebSocketData, 1);
    conn->protocol_data = ws_data;

    if (websocket_frame_relay_loop(conn, error)) {
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        return HANDLER_ERROR;
    }
}

// In websocket_cleanup()
static void websocket_cleanup(DeadlightConnection *conn) {
    if (conn->protocol_data) {
        WebSocketData *ws_data = (WebSocketData*)conn->protocol_data;
        // [FIX] Add this line to prevent a memory leak
        if (ws_data->last_ping_timer) {
            g_timer_destroy(ws_data->last_ping_timer);
        }
        g_free(ws_data);
        conn->protocol_data = NULL;
    }
}