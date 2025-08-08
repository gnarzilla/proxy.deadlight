// in src/protocols/socks.c

#include "socks.h"
#include <arpa/inet.h> // For inet_ntoa, part of POSIX

// Forward declarations for our handler functions
static gsize socks_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult socks_handle(DeadlightConnection *conn, GError **error);
static void socks_cleanup(DeadlightConnection *conn);
static DeadlightHandlerResult handle_socks4(DeadlightConnection *conn, GError **error);

// The handler object
static const DeadlightProtocolHandler socks_protocol_handler = {
    .name = "SOCKS", // Generic name for both v4 and v5
    .protocol_id = DEADLIGHT_PROTOCOL_SOCKS4, // We'll use SOCKS4 as the base ID for now
    .detect = socks_detect,
    .handle = socks_handle,
    .cleanup = socks_cleanup
};

void deadlight_register_socks_handler(void) {
    deadlight_protocol_register(&socks_protocol_handler);
}


// --- IMPLEMENTATION ---

static gsize socks_detect(const guint8 *data, gsize len) {
    // The first byte of any SOCKS4 or SOCKS5 connection is the version number.
    if (len > 0 && (data[0] == 0x04 || data[0] == 0x05)) {
        return 1; // It looks like SOCKS.
    }
    return 0;
}

static void socks_cleanup(DeadlightConnection *conn) {
    // For this simple handler, we don't allocate any extra data.
    (void)conn; // Suppress unused parameter warning
    g_debug("SOCKS cleanup called for conn %lu", conn->id);
}

static DeadlightHandlerResult socks_handle(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn->client_buffer && conn->client_buffer->len > 0, HANDLER_ERROR);

    guint8 version = conn->client_buffer->data[0];

    if (version == 0x04) {
        g_info("Connection %lu: Detected SOCKSv4 protocol.", conn->id);
        return handle_socks4(conn, error);
    } else if (version == 0x05) {
        g_warning("Connection %lu: SOCKSv5 detected but not yet supported.", conn->id);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "SOCKSv5 is not yet implemented.");
        return HANDLER_ERROR;
    }

    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Unknown SOCKS version: %d", version);
    return HANDLER_ERROR;
}

/**
 * Handle a SOCKS4 request (adapted from your original code)
 */
static DeadlightHandlerResult handle_socks4(DeadlightConnection *conn, GError **error) {
    // The initial data is already in the connection's client buffer.
    GByteArray *buffer = conn->client_buffer;

    // SOCKS4 request format: [ver=4][cmd=1][port_be][ip_be][userid]\0
    // Minimum length is 9 bytes (1+1+2+4+1 for null terminator)
    if (buffer->len < 9) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Incomplete SOCKS4 request header.");
        return HANDLER_ERROR;
    }
    
    guint8 *data = buffer->data;
    
    // Command code must be 1 for CONNECT
    if (data[1] != 0x01) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "SOCKS4 command %d not supported, only CONNECT (1).", data[1]);
        // We can't send a SOCKS reply here because we don't know the state, so we just fail.
        return HANDLER_ERROR;
    }
    
    // Extract port and IP address (they are in network byte order)
    guint16 target_port = ntohs(*(guint16*)&data[2]); // Read 2 bytes for port
    struct in_addr target_ip_addr = { .s_addr = *(in_addr_t*)&data[4] }; // Read 4 bytes for IP
    gchar *target_ip_str = g_strdup(inet_ntoa(target_ip_addr));
    
    g_info("Connection %lu: SOCKS4 CONNECT request to %s:%u", conn->id, target_ip_str, target_port);
    
    // Connect to the requested upstream target
    if (!deadlight_network_connect_upstream(conn, target_ip_str, target_port, error)) {
        g_warning("Connection %lu: SOCKS4 failed to connect upstream to %s:%u", conn->id, target_ip_str, target_port);
        // We could try to send a SOCKS4 error reply here, but for simplicity, we'll just drop.
        g_free(target_ip_str);
        return HANDLER_ERROR;
    }
    g_free(target_ip_str);

    // If successful, we MUST send a SOCKS4 success reply.
    // Reply format: [ver=0][status=90][port][ip]
    guint8 reply[8] = {0x00, 0x5A, data[2], data[3], data[4], data[5], data[6], data[7]};
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    
    if (!g_output_stream_write_all(client_os, reply, sizeof(reply), NULL, NULL, error)) {
        g_warning("Connection %lu: Failed to send SOCKS4 success reply: %s", conn->id, (*error)->message);
        return HANDLER_ERROR;
    }
    g_info("Connection %lu: SOCKS4 success reply sent.", conn->id);

    // The handshake is complete. The rest of the connection is a blind tunnel.
    // Call our universal tunnel function. When it returns, the connection is finished.
    if (deadlight_network_tunnel_data(conn, error)) {
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        return HANDLER_ERROR;
    }
}