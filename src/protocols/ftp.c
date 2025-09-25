#include "ftp.h"
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

// FTP protocol states
typedef enum {
    FTP_STATE_INIT,
    FTP_STATE_USER_SENT,
    FTP_STATE_AUTHENTICATED,
    FTP_STATE_PASSIVE_REQUESTED,
    FTP_STATE_DATA_PENDING
} FTPState;

typedef struct {
    FTPState state;
    gchar *username;
    gboolean passive_mode;
    gchar *data_host;
    guint16 data_port;
    gchar *upstream_data_host;
    guint16 upstream_data_port;
    GSocketConnection *data_connection;
    GSocketService *data_listener;  // For active mode
    guint16 proxy_data_port;        // Port we listen on for data
    GThread *data_tunnel_thread;
} FTPProtocolData;

typedef struct {
    GSocketConnection *client_data_conn;
    GSocketConnection *upstream_data_conn;
} FTPDataTunnelArgs;

// Forward declarations
static gsize ftp_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult ftp_handle(DeadlightConnection *conn, GError **error);
static void ftp_cleanup(DeadlightConnection *conn);
static gboolean ftp_tunnel_with_inspection(DeadlightConnection *conn, GError **error);
static gboolean parse_pasv_response(const gchar *response, gchar **host, guint16 *port);
static gchar* rewrite_pasv_response(const gchar *original, const gchar *proxy_ip, guint16 proxy_port);
static gboolean handle_data_connection(DeadlightConnection *conn, const gchar *cmd);
static gboolean parse_ftp_target(DeadlightConnection *conn, gchar **host, guint16 *port);
static gboolean on_data_connection_incoming(GSocketService *service, GSocketConnection *client_conn,
                                           GObject *source_object, gpointer user_data);

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
    
    return FALSE;
}

// Parse PASV response: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
static gboolean parse_pasv_response(const gchar *response, gchar **host, guint16 *port) {
    gint h1, h2, h3, h4, p1, p2;
    if (sscanf(response, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)", 
               &h1, &h2, &h3, &h4, &p1, &p2) == 6) {
        *host = g_strdup_printf("%d.%d.%d.%d", h1, h2, h3, h4);
        *port = (p1 << 8) | p2;
        return TRUE;
    }
    return FALSE;
}

// Rewrite PASV response to point to our proxy
static gchar* rewrite_pasv_response(const gchar *original, const gchar *proxy_ip, guint16 proxy_port) {
    (void)original; // Suppress unused parameter warning
    
    // Convert IP to h1,h2,h3,h4 format
    gint h1, h2, h3, h4;
    sscanf(proxy_ip, "%d.%d.%d.%d", &h1, &h2, &h3, &h4);
    
    gint p1 = (proxy_port >> 8) & 0xFF;
    gint p2 = proxy_port & 0xFF;
    
    return g_strdup_printf("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",
                          h1, h2, h3, h4, p1, p2);
}

static gboolean handle_data_connection(DeadlightConnection *conn, const gchar *cmd) {
    // FTPProtocolData *ftp_data = (FTPProtocolData*)conn->protocol_data;
    (void)conn; // Suppress unused warning for now
    
    // In a full implementation, we would:
    // 1. Set up our own data listener for PASV mode
    // 2. Connect to the upstream data server
    // 3. Proxy the data connection
    
    g_debug("Connection %lu: FTP data command: %s", conn->id, cmd);
    
    return TRUE;
}

// This function will be run in a new thread to handle the data transfer.
static gpointer ftp_data_tunnel_thread(gpointer data) {
    FTPDataTunnelArgs *args = (FTPDataTunnelArgs *)data;
    
    deadlight_network_tunnel_socket_connections(args->client_data_conn, args->upstream_data_conn);

    // Cleanup after tunnel finishes
    g_io_stream_close(G_IO_STREAM(args->client_data_conn), NULL, NULL);
    g_io_stream_close(G_IO_STREAM(args->upstream_data_conn), NULL, NULL);
    g_object_unref(args->client_data_conn);
    g_object_unref(args->upstream_data_conn);
    g_free(args);

    g_debug("FTP data tunnel thread finished.");
    return NULL;
}

// FTP-aware tunneling that inspects commands
static gboolean ftp_tunnel_with_inspection(DeadlightConnection *conn, GError **error) {
    FTPProtocolData *ftp_data = (FTPProtocolData*)conn->protocol_data;
    GInputStream *client_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    GInputStream *upstream_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_connection));
    GOutputStream *upstream_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
    
    gchar buffer[4096];
    gboolean running = TRUE;
    
    // Set up polling
    GPollFD fds[2];
    GSocket *client_socket = g_socket_connection_get_socket(conn->client_connection);
    GSocket *upstream_socket = g_socket_connection_get_socket(conn->upstream_connection);
    
    fds[0].fd = g_socket_get_fd(client_socket);
    fds[1].fd = g_socket_get_fd(upstream_socket);
    
    while (running) {
        fds[0].events = G_IO_IN | G_IO_HUP | G_IO_ERR;
        fds[1].events = G_IO_IN | G_IO_HUP | G_IO_ERR;
        
        gint ready = g_poll(fds, 2, -1);
        if (ready < 0) {
            running = FALSE;
            continue;
        }
        
        // Client -> Upstream (inspect commands)
        if (fds[0].revents & G_IO_IN) {
            gssize bytes = g_input_stream_read(client_is, buffer, sizeof(buffer) - 1, NULL, error);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                
                // Check for FTP commands
                gchar *cmd_upper = g_ascii_strup(buffer, 4);
                
                if (g_str_has_prefix(cmd_upper, "USER")) {
                    ftp_data->state = FTP_STATE_USER_SENT;
                    g_free(ftp_data->username);
                    // Extract username
                    gchar *user_line = g_strndup(buffer, strcspn(buffer, "\r\n"));
                    gchar **parts = g_strsplit(user_line, " ", 2);
                    if (parts[1]) {
                        ftp_data->username = g_strdup(parts[1]);
                        g_info("Connection %lu: FTP USER %s", conn->id, ftp_data->username);
                    }
                    g_strfreev(parts);
                    g_free(user_line);
                } else if (g_str_has_prefix(cmd_upper, "PASV")) {
                    ftp_data->state = FTP_STATE_PASSIVE_REQUESTED;
                    g_info("Connection %lu: FTP PASV command detected", conn->id);
                } else if (g_str_has_prefix(cmd_upper, "LIST") || 
                          g_str_has_prefix(cmd_upper, "RETR") ||
                          g_str_has_prefix(cmd_upper, "STOR")) {
                    // Data transfer commands
                    handle_data_connection(conn, buffer);
                }
                
                g_free(cmd_upper);
                
                // Forward to upstream
                if (!g_output_stream_write_all(upstream_os, buffer, bytes, NULL, NULL, error)) {
                    running = FALSE;
                }
                conn->bytes_client_to_upstream += bytes;
            } else {
                running = FALSE;
            }
        }

        // Upstream -> Client (inspect responses)
        if (fds[1].revents & G_IO_IN) {
            gssize bytes = g_input_stream_read(upstream_is, buffer, sizeof(buffer) - 1, NULL, error);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                gboolean forward_original = TRUE;

                // Check for PASV response
                if (ftp_data->state == FTP_STATE_PASSIVE_REQUESTED && g_str_has_prefix(buffer, "227 ")) {
                    g_info("Connection %lu: FTP PASV response detected, attempting to rewrite.", conn->id);
                    forward_original = FALSE; // We will handle the response from here.

                    // 1. Parse the server's response to get the real destination
                    if (parse_pasv_response(buffer, &ftp_data->upstream_data_host, &ftp_data->upstream_data_port)) {
                        g_info("Connection %lu: Upstream wants data connection to %s:%d", conn->id, ftp_data->upstream_data_host, ftp_data->upstream_data_port);

                        // 2. Manually create and bind a socket to get a free port from the OS.
                        GSocket *listen_socket = g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, error);
                        if (listen_socket) {
                            GInetAddress *proxy_addr = g_inet_address_new_from_string("0.0.0.0");
                            GSocketAddress *bind_addr = g_inet_socket_address_new(proxy_addr, 0); // Port 0 asks for a free port
                            
                            // Bind the socket
                            if (g_socket_bind(listen_socket, bind_addr, TRUE, error)) {
                                // Now that it's bound, get the address to see what port we got
                                GSocketAddress *effective_addr = g_socket_get_local_address(listen_socket, error);
                                if (effective_addr) {
                                    GInetAddress *proxy_inet_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(effective_addr));
                                    gchar *proxy_ip_str = g_inet_address_to_string(proxy_inet_addr);
                                    guint16 proxy_port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(effective_addr));

                                    // 3. Use our function to rewrite the PASV response string
                                    gchar *rewritten_response = rewrite_pasv_response(buffer, "127.0.0.1", proxy_port); // Using 127.0.0.1 for local testing
                                    
                                    g_info("Connection %lu: Rewriting PASV response to point to %s:%d", conn->id, "127.0.0.1", proxy_port);

                                    // 4. Create the service and add our *already bound* socket to it
                                    ftp_data->data_listener = g_socket_service_new();
                                    g_socket_listener_add_socket(G_SOCKET_LISTENER(ftp_data->data_listener), listen_socket, NULL, error);
                                    g_signal_connect(ftp_data->data_listener, "incoming", G_CALLBACK(on_data_connection_incoming), conn);
                                    g_socket_service_start(ftp_data->data_listener);

                                    // 5. Send the rewritten response to the client
                                    if (!g_output_stream_write_all(client_os, rewritten_response, strlen(rewritten_response), NULL, NULL, error)) {
                                        running = FALSE;
                                    }

                                    // Cleanup from this block
                                    g_free(rewritten_response);
                                    g_free(proxy_ip_str);
                                    g_object_unref(proxy_inet_addr);
                                    g_object_unref(effective_addr);
                                }
                            }
                            g_object_unref(bind_addr);
                            g_object_unref(proxy_addr);
                            g_object_unref(listen_socket); // The listener now owns a ref
                        }

                        if (*error) {
                            g_warning("Connection %lu: Failed during PASV rewrite setup: %s", conn->id, (*error)->message);
                            forward_original = TRUE; // Fallback to forwarding the original broken response
                        }
                    }
                    ftp_data->state = FTP_STATE_DATA_PENDING;
                }

                
                // Check for successful login
                if (g_str_has_prefix(buffer, "230 ")) {
                    ftp_data->state = FTP_STATE_AUTHENTICATED;
                    g_info("Connection %lu: FTP authentication successful", conn->id);
                }
                
                // Forward to client if we haven't already sent a rewritten response
                if (forward_original) {
                    if (!g_output_stream_write_all(client_os, buffer, bytes, NULL, NULL, error)) {
                        running = FALSE;
                    }
                }
                conn->bytes_upstream_to_client += bytes;
            } else {
                running = FALSE;
            }
        }
        
        // Check for socket errors
        if ((fds[0].revents | fds[1].revents) & (G_IO_HUP | G_IO_ERR)) {
            running = FALSE;
        }
    }
    
    g_info("Connection %lu: FTP tunnel closed (client->upstream: %lu B, upstream->client: %lu B)",
           conn->id, conn->bytes_client_to_upstream, conn->bytes_upstream_to_client);
    
    return TRUE;
}

static gboolean on_data_connection_incoming(GSocketService *service, GSocketConnection *client_conn,
                                           GObject *source_object, gpointer user_data) {
    (void)source_object;
    DeadlightConnection *conn = (DeadlightConnection *)user_data;
    FTPProtocolData *ftp_data = (FTPProtocolData *)conn->protocol_data;
    GError *error = NULL;

    g_info("Connection %lu: Accepted incoming FTP data connection from client.", conn->id);
    
    // We have the client's data connection. Now, connect to the upstream server's data port.
    GSocketConnection *upstream_conn = deadlight_network_connect_tcp(
        conn->context,
        ftp_data->upstream_data_host,
        ftp_data->upstream_data_port,
        &error
    );

    if (!upstream_conn) {
        g_warning("Connection %lu: Failed to connect to upstream FTP data port %s:%d: %s", 
                  conn->id, ftp_data->upstream_data_host, ftp_data->upstream_data_port, error->message);
        g_io_stream_close(G_IO_STREAM(client_conn), NULL, NULL); // Close the client side
        g_error_free(error);
        return TRUE; // Stop further processing for this connection
    }

    g_info("Connection %lu: Connected to upstream FTP data port. Starting tunnel.", conn->id);

    // Prepare arguments for the tunnel thread
    FTPDataTunnelArgs *args = g_new0(FTPDataTunnelArgs, 1);
    args->client_data_conn = g_object_ref(client_conn);
    args->upstream_data_conn = upstream_conn; // no ref needed, we own it

    // Launch the tunnel in a new thread
    ftp_data->data_tunnel_thread = g_thread_new("ftp-data-tunnel", ftp_data_tunnel_thread, args);

    // Stop listening, we only need one data connection for this command.
    g_socket_service_stop(service);
    g_object_unref(ftp_data->data_listener);
    ftp_data->data_listener = NULL;

    return TRUE; // We handled it.
}

static DeadlightHandlerResult ftp_handle(DeadlightConnection *conn, GError **error) {
    gchar *host = NULL;
    guint16 port = 21;
    
    // Try to determine the target FTP server
    if (!parse_ftp_target(conn, &host, &port)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                    "No FTP target server configured");
        
        const gchar *error_response = "421 No upstream FTP server configured.\r\n";
        GOutputStream *client_output = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output, error_response, strlen(error_response), 
                                 NULL, NULL, NULL);
        return HANDLER_ERROR;
    }
    
    g_info("Connection %lu: FTP connection to %s:%d", conn->id, host, port);
    
    // Allocate FTP protocol data
    FTPProtocolData *ftp_data = g_new0(FTPProtocolData, 1);
    ftp_data->state = FTP_STATE_INIT;
    conn->protocol_data = ftp_data;
    
    // Create request for plugin hooks
    conn->current_request = deadlight_request_new(conn);
    conn->current_request->method = g_strdup("FTP");
    conn->current_request->uri = g_strdup_printf("ftp://%s:%d", host, port);
    conn->current_request->host = g_strdup(host);
    
    if (!deadlight_plugins_call_on_request_headers(conn->context, conn->current_request)) {
        g_info("Connection %lu: FTP request blocked by plugin", conn->id);
        const gchar *error_response = "530 Access denied by proxy policy.\r\n";
        GOutputStream *client_output = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output, error_response, strlen(error_response), 
                                 NULL, NULL, NULL);
        g_free(host);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }
    
    // Connect to upstream
    if (!deadlight_network_connect_upstream(conn, host, port, error)) {
        g_warning("Connection %lu: Failed to connect to FTP upstream %s:%d", 
                  conn->id, host, port);
        
        const gchar *error_response = "421 Service not available.\r\n";
        GOutputStream *client_output = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output, error_response, strlen(error_response), 
                                 NULL, NULL, NULL);
        g_free(host);
        return HANDLER_ERROR;
    }
    
    // Store the upstream host for PASV rewriting
    ftp_data->data_host = host; // Take ownership
    
    // Send initial client data if any
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
    
    // Use FTP-aware tunneling
    g_info("Connection %lu: Starting FTP tunnel with command inspection", conn->id);
    if (ftp_tunnel_with_inspection(conn, error)) {
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        return HANDLER_ERROR;
    }
}

static void ftp_cleanup(DeadlightConnection *conn) {
    if (conn->protocol_data) {
        FTPProtocolData *ftp_data = (FTPProtocolData*)conn->protocol_data;
        
        g_free(ftp_data->username);
        g_free(ftp_data->upstream_data_host);
        
        // Stop the listener if it's still running
        if (ftp_data->data_listener) {
            g_socket_service_stop(ftp_data->data_listener);
            g_object_unref(ftp_data->data_listener);
        }
        
        // If a thread was created, we just let it finish.
        if (ftp_data->data_tunnel_thread) {
            g_thread_unref(ftp_data->data_tunnel_thread);
        }
        
        g_free(ftp_data);
        conn->protocol_data = NULL;
    }
    
    g_debug("FTP cleanup called for conn %lu", conn->id);
}