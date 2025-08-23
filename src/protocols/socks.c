#include "socks.h"
#include <arpa/inet.h> // For inet_ntoa, ntohs, etc.

// SOCKS5 Constants (ADD THESE BACK)
#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04
#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_HOST_UNREACHABLE 0x04

// Add the missing error codes we referenced in error handling:
#define SOCKS5_REP_GENERAL_FAILURE 0x01
#define SOCKS5_REP_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REP_CONNECTION_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED 0x06
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 0x08

// Also add IPv6 support
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

static gsize socks_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult socks_handle(DeadlightConnection *conn, GError **error);
static void socks_cleanup(DeadlightConnection *conn);
static DeadlightHandlerResult handle_socks4(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult handle_socks5(DeadlightConnection *conn, GError **error);

// Add this helper function before handle_socks5
static gboolean send_socks5_error_reply(GOutputStream *client_os, guint8 error_code, GError **error) {
    guint8 error_reply[10] = {
        SOCKS5_VERSION,     // Version
        error_code,         // Error code  
        0x00,               // Reserved
        SOCKS5_ATYP_IPV4,   // Address type
        0, 0, 0, 0,         // IP address (0.0.0.0)
        0, 0                // Port (0)
    };
    
    return g_output_stream_write_all(client_os, error_reply, 10, NULL, NULL, error);
}

// Updated handle_socks5 function with proper error handling:
static DeadlightHandlerResult handle_socks5(DeadlightConnection *conn, GError **error) {
    GInputStream *client_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    DeadlightContext *ctx = conn->context;

    // Load config
    gboolean auth_required = deadlight_config_get_bool(ctx, "socks5", "auth_required", FALSE);
    gchar *config_username = deadlight_config_get_string(ctx, "socks5", "username", NULL);
    gchar *config_password = deadlight_config_get_string(ctx, "socks5", "password", NULL);

    // --- Phase 1: Greeting & Method Selection ---
    g_debug("SOCKS5 conn %lu: Starting phase 1 (Greeting).", conn->id);
    guint8 *greeting_data = conn->client_buffer->data;
    guint nmethods = greeting_data[1];

    if (conn->client_buffer->len < 2 + nmethods) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Incomplete SOCKS5 greeting.");
        return HANDLER_ERROR;
    }

    gboolean no_auth_offered = FALSE;
    gboolean user_pass_offered = FALSE;
    for (guint i = 0; i < nmethods; i++) {
        guint8 method = greeting_data[2 + i];
        if (method == SOCKS5_AUTH_NONE) no_auth_offered = TRUE;
        if (method == 0x02) user_pass_offered = TRUE;  // Username/pass
    }

    guint8 selected_method = SOCKS5_AUTH_NO_ACCEPTABLE;
    if (!auth_required && no_auth_offered) {
        selected_method = SOCKS5_AUTH_NONE;
    } else if (user_pass_offered && config_username && config_password) {
        selected_method = 0x02;
    }

    guint8 reply_method[2] = {SOCKS5_VERSION, selected_method};
    if (!g_output_stream_write_all(client_os, reply_method, 2, NULL, NULL, error)) {
        g_warning("SOCKS5 conn %lu: Failed to send method reply: %s", conn->id, (*error)->message);
        return HANDLER_ERROR;
    }

    if (selected_method == SOCKS5_AUTH_NO_ACCEPTABLE) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "No acceptable authentication methods.");
        return HANDLER_ERROR;
    }
    g_info("SOCKS5 conn %lu: Method %02x selected.", conn->id, selected_method);

    // --- Auth Sub-Negotiation (if user/pass) ---
    if (selected_method == 0x02) {
        guint8 auth_buffer[512];  // Max username/pass len 255 each + headers
        gsize bytes_read;
        if (!g_input_stream_read_all(client_is, auth_buffer, 2, &bytes_read, NULL, error)) {  // VER + ULEN
            send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
            return HANDLER_ERROR;
        }
        if (auth_buffer[0] != 0x01) {  // Subnegotiation version
            guint8 auth_reply[2] = {0x01, 0x01};  // Failure
            g_output_stream_write_all(client_os, auth_reply, 2, NULL, NULL, NULL);
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid auth subnegotiation version.");
            return HANDLER_ERROR;
        }
        guint8 ulen = auth_buffer[1];
        if (!g_input_stream_read_all(client_is, auth_buffer + 2, ulen + 1, &bytes_read, NULL, error)) {  // Username + PLEN
            return HANDLER_ERROR;
        }
        guint8 plen = auth_buffer[2 + ulen];
        if (!g_input_stream_read_all(client_is, auth_buffer + 2 + ulen + 1, plen, &bytes_read, NULL, error)) {  // Password
            return HANDLER_ERROR;
        }

        gchar *client_username = g_strndup((gchar*)(auth_buffer + 2), ulen);
        gchar *client_password = g_strndup((gchar*)(auth_buffer + 2 + ulen + 1), plen);

        gboolean auth_ok = g_strcmp0(client_username, config_username) == 0 &&
                           g_strcmp0(client_password, config_password) == 0;

        guint8 auth_reply[2] = {0x01, auth_ok ? 0x00 : 0x01};
        g_output_stream_write_all(client_os, auth_reply, 2, NULL, NULL, error);

        g_free(client_username);
        g_free(client_password);

        if (!auth_ok) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "SOCKS5 authentication failed.");
            return HANDLER_ERROR;
        }
        g_info("SOCKS5 conn %lu: User/pass auth succeeded.", conn->id);
    }

    g_info("SOCKS5 conn %lu: Method 'NO AUTHENTICATION' selected.", conn->id);
    
    // --- Phase 2: Connection Request ---
    g_debug("SOCKS5 conn %lu: Starting phase 2 (Request).", conn->id);
    guint8 req_buffer[262]; // Max SOCKS5 request size
    gsize bytes_read;

    // Read request header (VER + CMD + RSV + ATYP)
    if (!g_input_stream_read_all(client_is, req_buffer, 4, &bytes_read, NULL, error)) {
        g_warning("SOCKS5 conn %lu: Failed to read request header: %s", conn->id, (*error)->message);
        send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
        return HANDLER_ERROR;
    }

    if (req_buffer[1] != SOCKS5_CMD_CONNECT) {
        g_warning("SOCKS5 conn %lu: Command %d not supported", conn->id, req_buffer[1]);
        send_socks5_error_reply(client_os, SOCKS5_REP_COMMAND_NOT_SUPPORTED, NULL);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "SOCKS5 command %d not supported.", req_buffer[1]);
        return HANDLER_ERROR;
    }

    guint8 atyp = req_buffer[3];
    gchar *target_host = NULL;
    guint16 target_port = 0;

    switch (atyp) {
        case SOCKS5_ATYP_IPV4:
            if (!g_input_stream_read_all(client_is, &req_buffer[4], 4 + 2, &bytes_read, NULL, error)) {
                send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
                return HANDLER_ERROR;
            }
            target_host = g_strdup_printf("%d.%d.%d.%d", req_buffer[4], req_buffer[5], req_buffer[6], req_buffer[7]);
            target_port = ntohs(*(guint16*)&req_buffer[8]);
            break;
            
        case SOCKS5_ATYP_DOMAIN:
            if (!g_input_stream_read_all(client_is, &req_buffer[4], 1, &bytes_read, NULL, error)) {
                send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
                return HANDLER_ERROR;
            }
            guint8 domain_len = req_buffer[4];
            if (!g_input_stream_read_all(client_is, &req_buffer[5], domain_len + 2, &bytes_read, NULL, error)) {
                send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
                return HANDLER_ERROR;
            }
            target_host = g_strndup((gchar*)&req_buffer[5], domain_len);
            target_port = ntohs(*(guint16*)&req_buffer[5 + domain_len]);
            break;
            
        case SOCKS5_ATYP_IPV6: {
            if (!g_input_stream_read_all(client_is, &req_buffer[4], 16 + 2, &bytes_read, NULL, error)) {
                send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
                return HANDLER_ERROR;
            }
            
            // Format IPv6 address properly
            char ipv6_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &req_buffer[4], ipv6_str, INET6_ADDRSTRLEN)) {
                target_host = g_strdup(ipv6_str);
            } else {
                target_host = g_strdup("IPv6 Address"); // fallback
            }
            target_port = ntohs(*(guint16*)&req_buffer[20]);
            break;
        }
        
        default:
            g_warning("SOCKS5 conn %lu: Address type %d not supported", conn->id, atyp);
            send_socks5_error_reply(client_os, SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED, NULL);
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Unsupported address type %d.", atyp);
            return HANDLER_ERROR;
    }
    
    g_info("SOCKS5 conn %lu: CONNECT request to %s:%u", conn->id, target_host, target_port);

    // --- Phase 3: Upstream Connection & Reply ---
    g_debug("SOCKS5 conn %lu: Starting phase 3 (Upstream Connect).", conn->id);
    if (!deadlight_network_connect_upstream(conn, target_host, target_port, error)) {
        g_warning("SOCKS5 conn %lu: Failed to connect upstream to %s:%u: %s", 
                 conn->id, target_host, target_port, (*error)->message);
        
        // Send appropriate error based on the failure reason
        guint8 socks_error = SOCKS5_REP_GENERAL_FAILURE;
        if (g_error_matches(*error, G_RESOLVER_ERROR, G_RESOLVER_ERROR_NOT_FOUND)) {
            socks_error = SOCKS5_REP_HOST_UNREACHABLE;
        } else if (g_error_matches(*error, G_IO_ERROR, G_IO_ERROR_CONNECTION_REFUSED)) {
            socks_error = SOCKS5_REP_CONNECTION_REFUSED;
        } else if (g_error_matches(*error, G_IO_ERROR, G_IO_ERROR_NETWORK_UNREACHABLE)) {
            socks_error = SOCKS5_REP_NETWORK_UNREACHABLE;
        }
        
        send_socks5_error_reply(client_os, socks_error, NULL);
        g_free(target_host);
        return HANDLER_ERROR;
    }
    g_free(target_host);

    // Send success reply
    guint8 success_reply[10] = {SOCKS5_VERSION, SOCKS5_REP_SUCCESS, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0};
    if (!g_output_stream_write_all(client_os, success_reply, 10, NULL, NULL, error)) {
        g_warning("SOCKS5 conn %lu: Failed to send success reply: %s", conn->id, (*error)->message);
        return HANDLER_ERROR;
    }
    g_info("SOCKS5 conn %lu: Success reply sent. Handshake complete.", conn->id);

    // --- Phase 4: Tunneling ---
    return deadlight_network_tunnel_data(conn, error) ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
}

static DeadlightHandlerResult socks_handle(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn->client_buffer && conn->client_buffer->len > 0, HANDLER_ERROR);

    guint8 version = conn->client_buffer->data[0];

    if (version == 0x04) {
        g_info("Connection %lu: Detected SOCKSv4 protocol.", conn->id);
        return handle_socks4(conn, error);
    } else if (version == 0x05) {
        g_info("Connection %lu: Detected SOCKSv5 protocol.", conn->id);
        return handle_socks5(conn, error);  // <-- THIS IS THE MISSING CALL
    }

    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Unknown SOCKS version: %d", version);
    return deadlight_network_tunnel_data(conn, error) ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
}

/**
 * Handle a SOCKS4 request
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
        
        // Send SOCKS4 error reply: [ver=0][status=91][port][ip] (91 = request rejected)
        guint8 error_reply[8] = {0x00, 0x5B, data[2], data[3], data[4], data[5], data[6], data[7]};
        GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_os, error_reply, sizeof(error_reply), NULL, NULL, NULL);
        
        g_free(target_ip_str);
        return HANDLER_ERROR;
    }
    g_free(target_ip_str);

    // Send SOCKS4 success reply: [ver=0][status=90][port][ip] (90 = request granted)
    guint8 success_reply[8] = {0x00, 0x5A, data[2], data[3], data[4], data[5], data[6], data[7]};
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    
    if (!g_output_stream_write_all(client_os, success_reply, sizeof(success_reply), NULL, NULL, error)) {
        g_warning("Connection %lu: Failed to send SOCKS4 success reply: %s", conn->id, (*error)->message);
        return HANDLER_ERROR;
    }
    g_info("Connection %lu: SOCKS4 success reply sent.", conn->id);

    // The handshake is complete. Start tunneling data.
    return deadlight_network_tunnel_data(conn, error) ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
}

// Add these at the end (you need the detection, cleanup, and protocol registration):
static gsize socks_detect(const guint8 *data, gsize len) {
    if (len > 0 && (data[0] == 0x04 || data[0] == 0x05)) {
        return 1;
    }
    return 0;
}

static void socks_cleanup(DeadlightConnection *conn) {
    (void)conn;
    g_debug("SOCKS cleanup called for conn %lu", conn->id);
}

// The handler object
static const DeadlightProtocolHandler socks_protocol_handler = {
    .name = "SOCKS",
    .protocol_id = DEADLIGHT_PROTOCOL_SOCKS5,
    .detect = socks_detect,
    .handle = socks_handle,  // <-- This calls your dispatcher
    .cleanup = socks_cleanup
};

void deadlight_register_socks_handler(void) {
    deadlight_protocol_register(&socks_protocol_handler);
}