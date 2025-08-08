#include "smtp.h"
#include <string.h>

// Forward declarations (ADD ALL OF THESE AT THE TOP)
static gsize smtp_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult smtp_handle(DeadlightConnection *conn, GError **error);
static void smtp_cleanup(DeadlightConnection *conn);

// Add these missing forward declarations:
static DeadlightHandlerResult smtp_handle_bridge_mode(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult smtp_handle_proxy_mode(DeadlightConnection *conn, const gchar *upstream_host, gint upstream_port, GError **error);
static DeadlightHandlerResult smtp_handle_local_mode(DeadlightConnection *conn, GError **error);
static gboolean smtp_send_to_api(DeadlightConnection *conn, DeadlightSMTPData *smtp_data, const gchar *api_endpoint, GError **error);

// SMTP command constants
#define SMTP_GREETING "220 deadlight.proxy ESMTP Ready\r\n"
#define SMTP_OK "250 OK\r\n"
#define SMTP_DATA_START "354 Start mail input; end with <CRLF>.<CRLF>\r\n"
#define SMTP_BYE "221 Bye\r\n"

// The handler object
static const DeadlightProtocolHandler smtp_protocol_handler = {
    .name = "SMTP",
    .protocol_id = DEADLIGHT_PROTOCOL_UNKNOWN, // Add DEADLIGHT_PROTOCOL_SMTP to enum
    .detect = smtp_detect,
    .handle = smtp_handle,
    .cleanup = smtp_cleanup
};

void deadlight_register_smtp_handler(void) {
    deadlight_protocol_register(&smtp_protocol_handler);
}

// --- IMPLEMENTATION ---

static gsize smtp_detect(const guint8 *data, gsize len) {
    if (len < 4) return 0;
    
    const char *str = (const char*)data;
    
    // SMTP client commands
    if (g_str_has_prefix(str, "EHLO") ||
        g_str_has_prefix(str, "HELO") ||
        g_str_has_prefix(str, "MAIL FROM:") ||
        g_str_has_prefix(str, "RCPT TO:") ||
        g_str_has_prefix(str, "DATA") ||
        g_str_has_prefix(str, "QUIT") ||
        g_str_has_prefix(str, "RSET") ||
        g_str_has_prefix(str, "NOOP")) {
        return 1;
    }
    
    return 0;
}

static DeadlightHandlerResult smtp_handle(DeadlightConnection *conn, GError **error) {
    DeadlightContext *ctx = conn->context;
    g_info("SMTP handler assigned to connection %lu", conn->id);

    // Get configuration
    gboolean bridge_mode = deadlight_config_get_bool(ctx, "smtp", "bridge_mode", FALSE);
    const gchar *upstream_host = deadlight_config_get_string(ctx, "smtp", "upstream_host", NULL);
    gint upstream_port = deadlight_config_get_int(ctx, "smtp", "upstream_port", 25);

    if (bridge_mode) {
        // API Bridge Mode - Translate SMTP to HTTP API calls
        return smtp_handle_bridge_mode(conn, error);
    } else if (upstream_host) {
        // Proxy Mode - Forward to upstream SMTP server
        return smtp_handle_proxy_mode(conn, upstream_host, upstream_port, error);
    } else {
        // Local Mode - Handle SMTP directly (for blog integration)
        return smtp_handle_local_mode(conn, error);
    }
}

// Bridge mode: Translate SMTP to HTTP API calls for Cloudflare Worker
static DeadlightHandlerResult smtp_handle_bridge_mode(DeadlightConnection *conn, GError **error) {
    DeadlightContext *ctx = conn->context;
    const gchar *api_endpoint = deadlight_config_get_string(ctx, "smtp", "api_endpoint", 
                                                           "https://deadlight.boo/api/email/receive");
    
    g_info("SMTP bridge mode for conn %lu: Will translate to API calls to %s", conn->id, api_endpoint);
    
    // Initialize SMTP protocol data
    DeadlightSMTPData *smtp_data = g_new0(DeadlightSMTPData, 1);
    smtp_data->message_buffer = g_byte_array_new();
    conn->protocol_data = smtp_data;
    
    GInputStream *client_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    
    // Send greeting
    if (!g_output_stream_write_all(client_os, SMTP_GREETING, strlen(SMTP_GREETING), NULL, NULL, error)) {
        return HANDLER_ERROR;
    }
    
    // Main SMTP command loop
    gchar buffer[1024];
    gboolean running = TRUE;
    
    while (running) {
        gssize bytes_read = g_input_stream_read(client_is, buffer, sizeof(buffer) - 1, NULL, error);
        if (bytes_read <= 0) break;
        
        buffer[bytes_read] = '\0';
        gchar **lines = g_strsplit(buffer, "\r\n", -1);
        
        for (int i = 0; lines[i] && strlen(lines[i]) > 0; i++) {
            gchar *line = g_strstrip(lines[i]);
            g_info("SMTP bridge conn %lu received: %s", conn->id, line);
            
            if (g_str_has_prefix(line, "HELO") || g_str_has_prefix(line, "EHLO")) {
                g_output_stream_write_all(client_os, SMTP_OK, strlen(SMTP_OK), NULL, NULL, NULL);
                
            } else if (g_str_has_prefix(line, "MAIL FROM:")) {
                smtp_data->sender = g_strdup(line + 10); // Skip "MAIL FROM:"
                g_output_stream_write_all(client_os, SMTP_OK, strlen(SMTP_OK), NULL, NULL, NULL);
                
            } else if (g_str_has_prefix(line, "RCPT TO:")) {
                smtp_data->recipient = g_strdup(line + 8); // Skip "RCPT TO:"
                g_output_stream_write_all(client_os, SMTP_OK, strlen(SMTP_OK), NULL, NULL, NULL);
                
            } else if (g_str_has_prefix(line, "DATA")) {
                smtp_data->in_data_mode = TRUE;
                g_output_stream_write_all(client_os, SMTP_DATA_START, strlen(SMTP_DATA_START), NULL, NULL, NULL);
                
            } else if (smtp_data->in_data_mode) {
                if (g_str_equal(line, ".")) {
                    // End of message - send to API
                    if (smtp_send_to_api(conn, smtp_data, api_endpoint, error)) {
                        g_output_stream_write_all(client_os, SMTP_OK, strlen(SMTP_OK), NULL, NULL, NULL);
                    } else {
                        const gchar *error_msg = "550 Message processing failed\r\n";
                        g_output_stream_write_all(client_os, error_msg, strlen(error_msg), NULL, NULL, NULL);
                    }
                    smtp_data->in_data_mode = FALSE;
                    
                } else {
                    // Accumulate message data
                    g_byte_array_append(smtp_data->message_buffer, (guint8*)line, strlen(line));
                    g_byte_array_append(smtp_data->message_buffer, (guint8*)"\r\n", 2);
                }
                
            } else if (g_str_has_prefix(line, "QUIT")) {
                g_output_stream_write_all(client_os, SMTP_BYE, strlen(SMTP_BYE), NULL, NULL, NULL);
                running = FALSE;
            }
        }
        
        g_strfreev(lines);
    }
    
    return HANDLER_SUCCESS_CLEANUP_NOW;
}

// Helper function to send email to HTTP API
static gboolean smtp_send_to_api(DeadlightConnection *conn, DeadlightSMTPData *smtp_data, 
                                 const gchar *api_endpoint, GError **error) {
    // This would use libcurl or similar to POST to your Cloudflare Worker
    // Format: JSON payload with sender, recipient, message body
    
    g_info("SMTP bridge conn %lu: Sending email to API - From: %s, To: %s, Size: %u bytes",
           conn->id, smtp_data->sender, smtp_data->recipient, smtp_data->message_buffer->len);
    
    // TODO: Implement HTTP POST to API endpoint
    // For now, return success to complete the SMTP transaction
    return TRUE;
}

static void smtp_cleanup(DeadlightConnection *conn) {
    if (conn->protocol_data) {
        DeadlightSMTPData *smtp_data = (DeadlightSMTPData*)conn->protocol_data;
        g_free(smtp_data->sender);
        g_free(smtp_data->recipient);
        if (smtp_data->message_buffer) {
            g_byte_array_free(smtp_data->message_buffer, TRUE);
        }
        g_free(smtp_data);
        conn->protocol_data = NULL;
    }
}

// Add these missing function implementations at the end of smtp.c:

static DeadlightHandlerResult smtp_handle_proxy_mode(DeadlightConnection *conn, const gchar *upstream_host, gint upstream_port, GError **error) {
    g_info("SMTP proxy mode for conn %lu: Forwarding to %s:%d", conn->id, upstream_host, upstream_port);
    
    // Connect to upstream SMTP server
    if (!deadlight_network_connect_upstream(conn, upstream_host, upstream_port, error)) {
        g_warning("SMTP proxy mode for conn %lu: Failed to connect to %s:%d", conn->id, upstream_host, upstream_port);
        return HANDLER_ERROR;
    }
    
    // Send initial greeting if we have buffered client data
    if (conn->client_buffer && conn->client_buffer->len > 0) {
        GOutputStream *upstream_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
        if (!g_output_stream_write_all(upstream_os, conn->client_buffer->data, conn->client_buffer->len, NULL, NULL, error)) {
            g_warning("SMTP proxy mode for conn %lu: Failed to forward initial data", conn->id);
            return HANDLER_ERROR;
        }
    }
    
    // Start tunneling
    return deadlight_network_tunnel_data(conn, error) ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
}

static DeadlightHandlerResult smtp_handle_local_mode(DeadlightConnection *conn, GError **error) {
    g_info("SMTP local mode for conn %lu: Handling locally", conn->id);
    
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    
    // Send a basic greeting
    const gchar *greeting = "220 deadlight.proxy ESMTP Ready (Local Mode)\r\n";
    if (!g_output_stream_write_all(client_os, greeting, strlen(greeting), NULL, NULL, error)) {
        return HANDLER_ERROR;
    }
    
    // For now, just send a basic "not implemented" message and close
    const gchar *not_impl = "502 Command not implemented in local mode\r\n";
    g_output_stream_write_all(client_os, not_impl, strlen(not_impl), NULL, NULL, NULL);
    
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "Local SMTP mode not yet implemented");
    return HANDLER_ERROR;
}