#include "http.h"
#include "core/ssl_tunnel.h"
#include "core/deadlight.h" // Ensure this is included for DeadlightHandlerResult
#include <string.h>
#include <glib.h>
#include <gio/gio.h>

// Helper function forward declarations
static gboolean parse_http_request_line(const gchar *line, gchar **method, gchar **uri, gchar **version);
static gboolean parse_host_port(const gchar *host_port, gchar **host, guint16 *port);

// Protocol handler forward declarations - These now match the header (http.h)
static gsize http_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult http_handle(DeadlightConnection *conn, GError **error);
static void http_cleanup(DeadlightConnection *conn);
static DeadlightHandlerResult handle_plain_http(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult handle_connect(DeadlightConnection *conn, GError **error);

// The handler object provided to the core
static const DeadlightProtocolHandler http_protocol_handler = {
    .name = "HTTP",
    .protocol_id = DEADLIGHT_PROTOCOL_HTTP,
    .detect = http_detect,
    .handle = http_handle,
    .cleanup = http_cleanup
};

// Public registration function
void deadlight_register_http_handler(void) {
    deadlight_protocol_register(&http_protocol_handler);
}

// --- Protocol Handler Implementation ---

static gsize http_detect(const guint8 *data, gsize len) {
    const gchar *http_methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "TRACE ", "CONNECT ", "PATCH ", NULL};
    for (int i = 0; http_methods[i]; i++) {
        gsize method_len = strlen(http_methods[i]);
        if (len >= method_len && memcmp(data, http_methods[i], method_len) == 0) {
            return method_len;
        }
    }
    return 0;
}

static DeadlightHandlerResult http_handle(DeadlightConnection *conn, GError **error) {
    if (conn->client_buffer->len > 8 && strncmp((char*)conn->client_buffer->data, "CONNECT ", 8) == 0) {
        conn->protocol = DEADLIGHT_PROTOCOL_CONNECT;
        return handle_connect(conn, error); // handle_connect also returns DeadlightHandlerResult
    }
    return handle_plain_http(conn, error); // handle_plain_http also returns DeadlightHandlerResult
}

static void http_cleanup(DeadlightConnection *conn) {
    (void)conn;
}

static DeadlightHandlerResult handle_plain_http(DeadlightConnection *conn, GError **error) {
    conn->current_request = deadlight_request_new(conn);

    // Parse headers first
    if (!deadlight_request_parse_headers(conn->current_request, (const gchar *)conn->client_buffer->data, conn->client_buffer->len)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Failed to parse HTTP request headers");
        return HANDLER_ERROR;
    }

    // Check if this is an API request BEFORE checking for proxy loops
    if (g_str_has_prefix(conn->current_request->uri, "/api/")) {
        const gchar *host_header = deadlight_request_get_header(conn->current_request, "host");
        if (host_header && (strstr(host_header, "localhost") || strstr(host_header, "127.0.0.1"))) {
            g_info("Connection %lu: API request detected, HTTP handler passing", conn->id);
            // Return error so the connection gets re-evaluated by other handlers
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "API request - wrong handler");
            return HANDLER_ERROR;
        }
    }

    const gchar *host_header = deadlight_request_get_header(conn->current_request, "host");
    if (!host_header) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Missing Host header");
        return HANDLER_ERROR; // Changed from FALSE
    }

    gchar *host = NULL;
    guint16 port = 80;
    if (!parse_host_port(host_header, &host, &port)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid Host header");
        return HANDLER_ERROR; // Changed from FALSE
    }

    // *** FIX FOR PROXY LOOP ***
    if ((g_strcmp0(host, conn->context->listen_address) == 0 || g_strcmp0(host, "localhost") == 0 || g_strcmp0(host, "127.0.0.1") == 0) && port == conn->context->listen_port) {
        g_warning("Connection %lu: Detected proxy loop to %s:%d. Denying request.", conn->id, host, port);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "Proxy loop detected");
        g_free(host);
        return HANDLER_ERROR; // Changed from FALSE
    }

    g_info("Connection %lu: HTTP request to %s:%d", conn->id, host, port);
    
    if (!deadlight_network_connect_upstream(conn, host, port, error)) {
        g_free(host);
        return HANDLER_ERROR;
    }
    g_free(host);

    GOutputStream *upstream_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
    if (g_output_stream_write_all(upstream_output, conn->client_buffer->data, conn->client_buffer->len, NULL, NULL, error) == FALSE) {
        return HANDLER_ERROR;
    }
    
    g_info("Connection %lu: Initial request sent, starting bidirectional tunnel.", conn->id);
    
    // deadlight_network_tunnel_data is BLOCKING. When it returns, the connection is finished.
    if (deadlight_network_tunnel_data(conn, error)) {
        return HANDLER_SUCCESS_CLEANUP_NOW; // <-- CORRECTED: The caller should clean up now.
    } else {
        return HANDLER_ERROR;
    }
}

// Changed return type from gboolean to DeadlightHandlerResult
static DeadlightHandlerResult handle_connect(DeadlightConnection *conn, GError **error) {
    gchar *request_line = g_strndup((gchar *)conn->client_buffer->data, conn->client_buffer->len);
    gchar **parts = g_strsplit(request_line, "\r\n", 2);
    gchar **req_parts = g_strsplit(parts[0], " ", 3);
    g_free(request_line);
    g_strfreev(parts);

    if (g_strv_length(req_parts) < 2) {
        g_strfreev(req_parts);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid CONNECT request line");
        return HANDLER_ERROR;
    }

    gchar *host = NULL;
    guint16 port = 443;
    if (!parse_host_port(req_parts[1], &host, &port)) {
        g_strfreev(req_parts);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid host:port in CONNECT request");
        return HANDLER_ERROR;
    }
    g_strfreev(req_parts);
    
    // Proxy loop prevention is perfect, keep it.
    if ((g_strcmp0(host, conn->context->listen_address) == 0 || g_strcmp0(host, "localhost") == 0 || g_strcmp0(host, "127.0.0.1") == 0) && port == conn->context->listen_port) {
        g_warning("Connection %lu: Detected proxy loop to %s:%d. Denying request.", conn->id, host, port);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "Proxy loop detected");
        g_free(host);
        return HANDLER_ERROR;
    }

    g_info("Connection %lu: CONNECT request to %s:%d", conn->id, host, port);
    conn->target_host = g_strdup(host);
    conn->target_port = port;

    if (!deadlight_network_connect_upstream(conn, host, port, error)) {
        g_free(host);
        return HANDLER_ERROR;
    }
    g_free(host);

    const gchar *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    GOutputStream *client_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    if (g_output_stream_write_all(client_output, response, strlen(response), NULL, NULL, error) == FALSE) {
        return HANDLER_ERROR;
    }

    if (conn->context->ssl_intercept_enabled) {
        if (deadlight_ssl_intercept_connection(conn, error)) {
            g_info("Connection %lu: Tunneling with intercepted client TLS.", conn->id);
            g_info("Connection %lu: Tunneling with upstream TLS.", conn->id);
            
            if (deadlight_tls_tunnel_data(conn, error)) {
                return HANDLER_SUCCESS_CLEANUP_NOW;
            } else {
                return HANDLER_ERROR;
            }
        } else {
            return HANDLER_ERROR;
        }
    } else {
        // Non-intercepted CONNECT - plain TCP tunnel
        g_info("Connection %lu: SSL intercept disabled. Starting plain TCP tunnel.", conn->id);
        if (deadlight_network_tunnel_data(conn, error)) {
            return HANDLER_SUCCESS_CLEANUP_NOW;
        } else {
            return HANDLER_ERROR;
        }
    }
}
// --- Helper Functions ---

static gboolean parse_http_request_line(const gchar *line, gchar **method, gchar **uri, gchar **version) {
    gchar **parts = g_strsplit(line, " ", 3);
    if (g_strv_length(parts) < 3) {
        g_strfreev(parts);
        return FALSE;
    }
    *method = g_strdup(parts[0]);
    *uri = g_strdup(parts[1]);
    *version = g_strdup(parts[2]);
    g_strfreev(parts);
    return TRUE;
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
    return (*host != NULL && *port > 0);
}