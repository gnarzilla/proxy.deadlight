#include "ftp.h"
#include <string.h>
#include <ctype.h>

// FTP protocol states
typedef enum {
    FTP_STATE_INIT,
    FTP_STATE_USER,
    FTP_STATE_PASS,
    FTP_STATE_AUTHENTICATED,
    FTP_STATE_DATA
} FTPState;

typedef struct {
    FTPState state;
    gchar *username;
    gboolean passive_mode;
    gchar *data_host;
    guint16 data_port;
    GSocketConnection *data_connection;
} FTPProtocolData;
#include "ftp.h"
#include <string.h>
#include <ctype.h>

// Forward declarations
static gsize ftp_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult ftp_handle(DeadlightConnection *conn, GError **error);
static void ftp_cleanup(DeadlightConnection *conn);
static gboolean parse_ftp_target(DeadlightConnection *conn, gchar **host, guint16 *port);

static const DeadlightProtocolHandler ftp_protocol_handler = {
    .name = "FTP",
    .protocol_id = DEADLIGHT_PROTOCOL_FTP,
    .detect = ftp_detect,
    .handle = ftp_handle,
    .cleanup = ftp_cleanup
};

void deadlight_register_ftp_handler(void) {
    deadlight_protocol_register(&ftp_protocol_handler);
}

static gsize ftp_detect(const guint8 *data, gsize len) {
    if (len < 4) return 0;
    
    // Check if it's an HTTP request for FTP URL (curl uses this)
    if (len >= 4 && memcmp(data, "GET ", 4) == 0) {
        gchar *request = g_strndup((const gchar*)data, MIN(len, 100));
        gboolean is_ftp_url = strstr(request, "ftp://") != NULL;
        g_free(request);
        if (is_ftp_url) return 0; // Let HTTP handler deal with FTP URLs
    }
    
    // FTP commands are case-insensitive
    gchar *str = g_strndup((const gchar*)data, MIN(len, 10));
    gchar *upper = g_ascii_strup(str, -1);
    
    // Check for common FTP commands
    gboolean is_ftp = FALSE;
    if (g_str_has_prefix(upper, "USER ") ||
        g_str_has_prefix(upper, "PASS ") ||
        g_str_has_prefix(upper, "LIST") ||
        g_str_has_prefix(upper, "RETR ") ||
        g_str_has_prefix(upper, "STOR ") ||
        g_str_has_prefix(upper, "QUIT") ||
        g_str_has_prefix(upper, "PASV") ||
        g_str_has_prefix(upper, "PORT ") ||
        g_str_has_prefix(upper, "TYPE ") ||
        g_str_has_prefix(upper, "CWD ") ||
        g_str_has_prefix(upper, "PWD") ||
        g_str_has_prefix(upper, "MKD ") ||
        g_str_has_prefix(upper, "DELE ") ||
        g_str_has_prefix(upper, "FEAT") ||
        g_str_has_prefix(upper, "SYST")) {
        is_ftp = TRUE;
    }
    
    // Also check for FTP server responses (3 digit codes)
    if (!is_ftp && len >= 4 && 
        g_ascii_isdigit(data[0]) && 
        g_ascii_isdigit(data[1]) && 
        g_ascii_isdigit(data[2]) &&
        (data[3] == ' ' || data[3] == '-')) {
        // Common FTP response codes
        if (memcmp(data, "220", 3) == 0 ||  // Service ready
            memcmp(data, "331", 3) == 0 ||  // User OK, need password
            memcmp(data, "230", 3) == 0 ||  // User logged in
            memcmp(data, "227", 3) == 0 ||  // Entering passive mode
            memcmp(data, "150", 3) == 0 ||  // File status OK
            memcmp(data, "226", 3) == 0 ||  // Transfer complete
            memcmp(data, "250", 3) == 0 ||  // Requested file action okay
            memcmp(data, "257", 3) == 0) {  // Pathname created
            is_ftp = TRUE;
        }
    }
    
    g_free(str);
    g_free(upper);
    
    return is_ftp ? 5 : 0;  // Medium priority
}

static gboolean parse_ftp_target(DeadlightConnection *conn, gchar **host, guint16 *port) {
    DeadlightContext *ctx = conn->context;
    
    // Check if we have target info from a previous CONNECT or similar
    if (conn->target_host) {
        *host = g_strdup(conn->target_host);
        *port = conn->target_port ? conn->target_port : 21;
        return TRUE;
    }
    
    // Otherwise use configured upstream
    const gchar *upstream_host = deadlight_config_get_string(ctx, "ftp", "upstream_host", NULL);
    if (upstream_host && strlen(upstream_host) > 0) {
        *host = g_strdup(upstream_host);
        *port = deadlight_config_get_int(ctx, "ftp", "upstream_port", 21);
        return TRUE;
    }
    
    // No target found
    return FALSE;
}

static DeadlightHandlerResult ftp_handle(DeadlightConnection *conn, GError **error) {
    gchar *host = NULL;
    guint16 port = 21;
    
    // Try to determine the target FTP server
    if (!parse_ftp_target(conn, &host, &port)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                    "No FTP target server configured. Set [ftp] upstream_host in config.");
        
        // Send FTP error response
        const gchar *error_response = "421 No upstream FTP server configured.\r\n";
        GOutputStream *client_output = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output, error_response, strlen(error_response), 
                                 NULL, NULL, NULL);
        return HANDLER_ERROR;
    }
    
    g_info("Connection %lu: FTP connection, forwarding to %s:%d", 
           conn->id, host, port);
    
    // Create request object for plugin hooks
    conn->current_request = deadlight_request_new(conn);
    conn->current_request->method = g_strdup("FTP");
    conn->current_request->uri = g_strdup_printf("ftp://%s:%d", host, port);
    conn->current_request->host = g_strdup(host);
    
    // Call plugin hooks
    if (!deadlight_plugins_call_on_request_headers(conn->context, conn->current_request)) {
        g_info("Connection %lu: FTP request blocked by plugin", conn->id);
        
        // Send FTP error response
        const gchar *error_response = "530 Access denied by proxy policy.\r\n";
        GOutputStream *client_output = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output, error_response, strlen(error_response), 
                                 NULL, NULL, NULL);
        g_free(host);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }
    
    // Connect to upstream FTP server
    if (!deadlight_network_connect_upstream(conn, host, port, error)) {
        g_warning("Connection %lu: Failed to connect to FTP upstream %s:%d", 
                  conn->id, host, port);
        
        // Send FTP error response
        const gchar *error_response = "421 Service not available, remote server error.\r\n";
        GOutputStream *client_output = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output, error_response, strlen(error_response), 
                                 NULL, NULL, NULL);
        g_free(host);
        return HANDLER_ERROR;
    }
    
    g_free(host);
    
    // Send any initial data from client to upstream
    if (conn->client_buffer && conn->client_buffer->len > 0) {
        GOutputStream *upstream_os = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->upstream_connection));
        
        if (!g_output_stream_write_all(upstream_os, 
                                       conn->client_buffer->data, 
                                       conn->client_buffer->len, 
                                       NULL, NULL, error)) {
            return HANDLER_ERROR;
        }
    }
    
    // Start bidirectional tunneling
    g_info("Connection %lu: Starting FTP tunnel", conn->id);
    if (deadlight_network_tunnel_data(conn, error)) {
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        return HANDLER_ERROR;
    }
}

static void ftp_cleanup(DeadlightConnection *conn) {
    g_debug("FTP cleanup called for conn %lu", conn->id);
}