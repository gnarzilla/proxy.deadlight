// Add this near the top with other constants
#define SOCKS5_REP_GENERAL_FAILURE 0x01
#define SOCKS5_REP_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REP_CONNECTION_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED 0x06
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 0x08

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
    
    // --- Phase 1: Greeting & Method Selection ---
    g_debug("SOCKS5 conn %lu: Starting phase 1 (Greeting).", conn->id);
    guint8 *greeting_data = conn->client_buffer->data;
    guint nmethods = greeting_data[1];
    
    if (conn->client_buffer->len < 2 + nmethods) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Incomplete SOCKS5 greeting.");
        return HANDLER_ERROR;
    }

    gboolean no_auth_supported = FALSE;
    for (guint i = 0; i < nmethods; i++) {
        if (greeting_data[2 + i] == SOCKS5_AUTH_NONE) {
            no_auth_supported = TRUE;
            break;
        }
    }
    
    guint8 reply_method[2] = {SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPTABLE};
    if (no_auth_supported) {
        reply_method[1] = SOCKS5_AUTH_NONE;
    }
    
    if (!g_output_stream_write_all(client_os, reply_method, 2, NULL, NULL, error)) {
        g_warning("SOCKS5 conn %lu: Failed to send method reply: %s", conn->id, (*error)->message);
        return HANDLER_ERROR;
    }
    
    if (!no_auth_supported) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "No acceptable authentication methods offered.");
        return HANDLER_ERROR;
    }
    g_info("SOCKS5 conn %lu: Method 'NO AUTHENTICATION' selected.", conn->id);
    
    // --- Phase 2: Connection Request ---
    g_debug("SOCKS5 conn %lu: Starting phase 2 (Request).", conn->id);
    guint8 req_buffer[262]; // Max SOCKS5 request size
    gssize bytes_read;

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