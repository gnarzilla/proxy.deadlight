/**
 * Deadlight Proxy v4.0 - Network Module
 *
 * Socket management, connection handling, and data transfer
 */
#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h> 
#include "deadlight.h"

// Network manager structure
struct _DeadlightNetworkManager {
    GSocketService *listener;
    GSocketAddress *bind_address;
    guint16 port;
    
    // Connection tracking
    guint64 next_connection_id;
    GMutex connection_mutex;
    
    // Statistics
    guint64 total_accepted;
    guint64 total_rejected;
};

// Forward declarations
static gboolean on_incoming_connection(GSocketService *service,
                                      GSocketConnection *connection,
                                      GObject *source_object,
                                      gpointer user_data);
static void connection_thread_func(gpointer data, gpointer user_data);
static void cleanup_connection(DeadlightConnection *conn);

/**
 * Initialize network module
 */
gboolean deadlight_network_init(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
    
    g_info("Initializing network module...");
    
    // Create network manager
    context->network = g_new0(DeadlightNetworkManager, 1);
    g_mutex_init(&context->network->connection_mutex);
    context->network->next_connection_id = 1;
    
    // Initialize connection tracking
    context->connections = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                                g_free, (GDestroyNotify)cleanup_connection);
    
    // Create worker thread pool
    gint worker_threads = deadlight_config_get_int(context, "core", "worker_threads", 4);
    context->worker_pool = g_thread_pool_new(connection_thread_func, context,
                                           worker_threads, FALSE, error);
    if (!context->worker_pool) {
        return FALSE;
    }
    
    // Initialize connection pool
    gint max_per_host = deadlight_config_get_int(context, "network", 
                                                "connection_pool_size", 10);
    gint idle_timeout = deadlight_config_get_int(context, "network", 
                                                "connection_pool_timeout", 300);
    context->conn_pool = connection_pool_new(max_per_host, idle_timeout);
    
    g_info("Network module initialized with %d worker threads and connection pooling", 
           worker_threads);
    return TRUE;
}

/**
 * Start network listener
 */
gboolean deadlight_network_start_listener(DeadlightContext *context, gint port, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(context->network != NULL, FALSE);
    g_return_val_if_fail(port > 0 && port < 65536, FALSE);
    
    // Create socket service
    context->network->listener = g_socket_service_new();
    
    // Get bind address from config
    const gchar *bind_addr = context->listen_address ? context->listen_address : "0.0.0.0";
    
    // Parse address
    GInetAddress *inet_addr = g_inet_address_new_from_string(bind_addr);
    if (!inet_addr) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "Invalid bind address: %s", bind_addr);
        return FALSE;
    }
    
    // Create socket address
    GSocketAddress *sock_addr = g_inet_socket_address_new(inet_addr, port);
    g_object_unref(inet_addr);
    
    // Add address to listener
    if (!g_socket_listener_add_address(G_SOCKET_LISTENER(context->network->listener),
                                      sock_addr, G_SOCKET_TYPE_STREAM,
                                      G_SOCKET_PROTOCOL_TCP, NULL,
                                      &context->network->bind_address, error)) {
        g_object_unref(sock_addr);
        return FALSE;
    }
    g_object_unref(sock_addr);
    
    // Store port
    context->network->port = port;
    
    // Connect incoming connection signal
    g_signal_connect(context->network->listener, "incoming",
                    G_CALLBACK(on_incoming_connection), context);
    
    // Start the service
    g_socket_service_start(context->network->listener);
    
    g_info("Network listener started on %s:%d", bind_addr, port);
    return TRUE;
}

/**
 * Stop network listener
 */
void deadlight_network_stop(DeadlightContext *context) {
    g_return_if_fail(context != NULL);
    
    g_info("Stopping network module...");
    
    if (context->network) {
        // Stop accepting new connections
        if (context->network->listener) {
            g_socket_service_stop(context->network->listener);
            g_object_unref(context->network->listener);
            context->network->listener = NULL;
        }
        
        // Close all active connections
        if (context->connections) {
            g_hash_table_remove_all(context->connections);
        }
        
        // Shutdown thread pool
        if (context->worker_pool) {
            g_thread_pool_free(context->worker_pool, TRUE, TRUE);
            context->worker_pool = NULL;
        }
        
        g_mutex_clear(&context->network->connection_mutex);
        g_free(context->network);
        context->network = NULL;
    }
    
    g_info("Network module stopped");
}

/**
 * Handle incoming connection
 */
static gboolean on_incoming_connection(GSocketService *service,
                                     GSocketConnection *connection,
                                     GObject *source_object,
                                     gpointer user_data) {
    (void)service;  // Mark as unused
    (void)source_object;  // Mark as unused
    
    DeadlightContext *context = (DeadlightContext *)user_data;
    
    // Check if we're shutting down
    if (context->shutdown_requested) {
        return FALSE;
    }
    
    // Check connection limit
    g_mutex_lock(&context->network->connection_mutex);
    guint active_count = g_hash_table_size(context->connections);
    g_mutex_unlock(&context->network->connection_mutex);
    
    if (active_count >= context->max_connections) {
        g_warning("Connection limit reached (%d), rejecting new connection", 
                 context->max_connections);
        context->network->total_rejected++;
        return FALSE;
    }
    
    // Accept the connection
    g_object_ref(connection);
    context->network->total_accepted++;
    
    // Get client address
    GSocketAddress *remote_addr = g_socket_connection_get_remote_address(connection, NULL);
    gchar *client_str = NULL;
    
    if (remote_addr) {
        if (G_IS_INET_SOCKET_ADDRESS(remote_addr)) {
            GInetSocketAddress *inet_addr = G_INET_SOCKET_ADDRESS(remote_addr);
            GInetAddress *addr = g_inet_socket_address_get_address(inet_addr);
            guint16 port = g_inet_socket_address_get_port(inet_addr);
            gchar *addr_str = g_inet_address_to_string(addr);
            client_str = g_strdup_printf("%s:%d", addr_str, port);
            g_free(addr_str);
        }
        g_object_unref(remote_addr);
    }
    
    g_info("New connection from %s", client_str ? client_str : "unknown");
    
    // Create connection object
    DeadlightConnection *conn = deadlight_connection_new(context, connection);
    conn->client_address = client_str;

    // Call plugin hook for new connection
    if (!deadlight_plugins_call_on_connection_accept(context, conn)) {
        g_info("Connection %lu rejected by plugin", conn->id);
        deadlight_connection_free(conn);
        return FALSE;
    }
    
    // Add to connection table
    g_mutex_lock(&context->network->connection_mutex);
    guint64 *id_ptr = g_new(guint64, 1);
    *id_ptr = conn->id;
    g_hash_table_insert(context->connections, id_ptr, conn);
    context->active_connections++;
    context->total_connections++;
    g_mutex_unlock(&context->network->connection_mutex);
    
    // Queue for processing
    GError *error = NULL;
    if (!g_thread_pool_push(context->worker_pool, conn, &error)) {
        g_error("Failed to queue connection: %s", error->message);
        g_error_free(error);
        
        // Remove from table
        g_mutex_lock(&context->network->connection_mutex);
        g_hash_table_remove(context->connections, &conn->id);
        context->active_connections--;
        g_mutex_unlock(&context->network->connection_mutex);
        
        return FALSE;
    }
    
    return TRUE;
}

/**
 * Create new connection object
 */
DeadlightConnection *deadlight_connection_new(DeadlightContext *context,
                                            GSocketConnection *client_connection) {
    DeadlightConnection *conn = g_new0(DeadlightConnection, 1);
    
    // Set ID
    g_mutex_lock(&context->network->connection_mutex);
    conn->id = context->network->next_connection_id++;
    g_mutex_unlock(&context->network->connection_mutex);
    
    // Initialize connection
    conn->context = context;
    conn->client_connection = g_object_ref(client_connection);
    conn->state = DEADLIGHT_STATE_INIT;
    conn->protocol = DEADLIGHT_PROTOCOL_UNKNOWN;
    
    // Create buffers
    conn->client_buffer = g_byte_array_new();
    conn->upstream_buffer = g_byte_array_new();
    
    // Plugin data storage
    conn->plugin_data = g_hash_table_new_full(g_str_hash, g_str_equal,
                                             g_free, g_free);
    
    // Start timer
    conn->connection_timer = g_timer_new();
    
    return conn;
}

/**
 * Free connection object
 */
// In src/core/network.c

void deadlight_connection_free(DeadlightConnection *conn) {
    if (!conn) return;

    // Remove from the master list first.
    g_mutex_lock(&conn->context->network->connection_mutex);
    g_hash_table_remove(conn->context->connections, &conn->id);
    conn->context->active_connections--;
    g_mutex_unlock(&conn->context->network->connection_mutex);

    // Now call the main cleanup worker.
    cleanup_connection(conn);
}

/**
 * Worker thread function
 */
// In src/core/network.c

static void connection_thread_func(gpointer data, gpointer user_data) {
    DeadlightConnection *conn = (DeadlightConnection *)data;
    DeadlightContext *context = (DeadlightContext *)user_data;
    GError *error = NULL;

    g_debug("Worker thread processing connection %lu", conn->id);

    conn->state = DEADLIGHT_STATE_DETECTING;

    // --- Your existing socket setup and initial read logic is perfect and stays here ---
    GSocket *socket = g_socket_connection_get_socket(conn->client_connection);
    g_socket_set_blocking(socket, FALSE);
    guint8 peek_buffer[2048];
    gssize bytes_peeked = 0;
    gint timeout = deadlight_config_get_int(context, "protocols", "protocol_detection_timeout", 5);
    gint64 end_time = g_get_monotonic_time() + (timeout * G_TIME_SPAN_SECOND);

    while (TRUE) {
        bytes_peeked = g_socket_receive(socket, (gchar *)peek_buffer, sizeof(peek_buffer), NULL, &error);
        if (bytes_peeked > 0) {
            g_byte_array_append(conn->client_buffer, peek_buffer, bytes_peeked);
            break;
        }
        if (bytes_peeked == 0 || (error && !g_error_matches(error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) || g_get_monotonic_time() > end_time) {
            if(bytes_peeked == 0) g_info("Connection %lu: Client closed before sending data.", conn->id);
            else if(error) g_warning("Connection %lu: Read error: %s", conn->id, error->message);
            else g_warning("Connection %lu: Protocol detection timeout.", conn->id);
            g_clear_error(&error);
            goto cleanup; 
        }
        g_clear_error(&error);
        g_usleep(10000); // 10ms
    }

    const DeadlightProtocolHandler *handler = deadlight_protocol_detect_and_assign(conn, conn->client_buffer->data, conn->client_buffer->len);

    if (!handler) {
        g_warning("Connection %lu: Could not detect a known protocol.", conn->id);
        goto cleanup;
    }

    g_info("Connection %lu: Detected protocol '%s'", conn->id, handler->name);
    conn->state = DEADLIGHT_STATE_CONNECTING;

    // Call plugin hook for protocol detection
    if (!deadlight_plugins_call_on_protocol_detect(context, conn)) {
        g_info("Connection %lu blocked by plugin after protocol detection", conn->id);
        goto cleanup;
    }

    gchar *config_key = g_strdup_printf("%s_enabled", g_ascii_strdown(handler->name, -1));
    gboolean enabled = deadlight_config_get_bool(context, "protocols", config_key, TRUE);
    g_free(config_key);

    if (!enabled) {
        g_warning("Connection %lu: Protocol '%s' is disabled in configuration.", conn->id, handler->name);
        goto cleanup;
    }

    // ==========================================================
    // ===== THE NEW, SIMPLIFIED PROTOCOL HANDLING LOGIC ========
    // ==========================================================


    DeadlightHandlerResult handler_result = handler->handle(conn, &error);

    // The switch is now simpler
    switch (handler_result) {
        case HANDLER_SUCCESS_CLEANUP_NOW:
            g_info("Connection %lu: Synchronous handler for '%s' completed.", 
                conn->id, deadlight_protocol_to_string(conn->protocol));
            cleanup_connection(conn);
            break;
            
        case HANDLER_SUCCESS_ASYNC:
            g_debug("Connection %lu: Asynchronous handler for '%s' started; worker thread exiting without cleanup.", 
                    conn->id, deadlight_protocol_to_string(conn->protocol));
            // Do nothing else - handler will manage lifecycle and cleanup
            break;
            
        case HANDLER_ERROR:
        {
            const gchar *msg = error ? error->message : "Unknown error";
            g_warning("Connection %lu: Handler for '%s' failed: %s",
                      conn->id, handler->name, msg);
            g_clear_error(&error);
            goto cleanup;
        }

        default:
            g_warning("Connection %lu: Unexpected handler result %d", conn->id, handler_result);
            cleanup_connection(conn);
            break;
    }

    cleanup:
    // This block is now ONLY reached by synchronous handlers or errors.
    if (conn->handler && conn->handler->cleanup) {
        conn->handler->cleanup(conn);
    }
    
    g_mutex_lock(&context->network->connection_mutex);
    g_hash_table_remove(context->connections, &conn->id);
    context->active_connections--;
    g_mutex_unlock(&context->network->connection_mutex);
}

/**
 * Connect to upstream server
 */
gboolean deadlight_network_connect_upstream(DeadlightConnection *conn, 
                                          const gchar *host, 
                                          guint16 port,
                                          GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(host != NULL, FALSE);
    g_return_val_if_fail(port > 0, FALSE);
    
    DeadlightContext *context = conn->context;

    // Try to get a pooled connection first
    GSocketConnection *pooled = connection_pool_get(context->conn_pool, host, port, FALSE);
    
    if (pooled) {
        conn->upstream_connection = pooled;
        // Make sure to set target info for pooled connections too!
        if (!conn->target_host) {
            conn->target_host = g_strdup(host);
        }
        conn->target_port = port;
        g_info("Connection %lu: Reused pooled connection to %s:%d", 
               conn->id, host, port);
        return TRUE;
    }

    g_info("Connection %lu: Connecting to upstream %s:%d", conn->id, host, port);
    
    // Create socket client
    GSocketClient *client = g_socket_client_new();
    
    // Set timeout
    gint timeout = deadlight_config_get_int(context, "network", "upstream_timeout", 30);
    g_socket_client_set_timeout(client, timeout);
    
    // Set IPv6 support
    gboolean ipv6_enabled = deadlight_config_get_bool(context, "network", "ipv6_enabled", TRUE);
    g_socket_client_set_enable_proxy(client, FALSE);
    
    // Don't set family when IPv6 is enabled - let GLib choose
    if (!ipv6_enabled) {
        g_socket_client_set_family(client, G_SOCKET_FAMILY_IPV4);
    }
    
    // Connect
    conn->upstream_connection = g_socket_client_connect_to_host(client, host, port, NULL, error);
    g_object_unref(client);
    
    if (!conn->upstream_connection) {
        return FALSE;
    }
    
    // Store target info - THIS IS CRITICAL FOR SSL INTERCEPTION
    if (!conn->target_host) {  // Only set if not already set
        conn->target_host = g_strdup(host);
    }
    conn->target_port = port;
    
    // Set socket options
    GSocket *socket = g_socket_connection_get_socket(conn->upstream_connection);
    g_socket_set_blocking(socket, FALSE);
    
    gint optval = 1;
    g_socket_set_option(socket, SOL_SOCKET, SO_KEEPALIVE, optval, NULL);
    
    if (deadlight_config_get_bool(context, "network", "tcp_nodelay", TRUE)) {
        g_socket_set_option(socket, IPPROTO_TCP, TCP_NODELAY, optval, NULL);
    }
    
    g_info("Connection %lu: Connected to upstream %s:%d", conn->id, host, port);
    return TRUE;
}

/**
 * Cleanup connection resources
 */
static void cleanup_connection(DeadlightConnection *conn) {
    if (!conn) return;
    
    g_debug("Cleaning up connection %lu", conn->id);

    // Notify plugins of connection close
    if (conn->context) {
        deadlight_plugins_call_on_connection_close(conn->context, conn);
    }

    // Return upstream connection to pool if possible
    if (conn->upstream_connection && conn->target_host && conn->state == DEADLIGHT_STATE_CLOSING) {
        // Check if connection is reusable (HTTP keep-alive, etc)
        gboolean reusable = FALSE;
        if (conn->current_request) {
            const gchar *connection_header = g_hash_table_lookup(
                conn->current_request->headers, "Connection");
            reusable = (connection_header &&
                        g_ascii_strcasecmp(connection_header, "keep-alive") == 0);
        }

        if (reusable && !conn->upstream_tls) { // Don't reuse TLS connections
            connection_pool_release(conn->context->conn_pool,
                                  conn->upstream_connection, 
                                  conn->target_host, 
                                  conn->target_port, FALSE);
            conn->upstream_connection = NULL; // Don't close it
        }
    }
    
    // IMPORTANT: Close TLS connections BEFORE underlying socket connections
    // because TLS connections wrap the socket connections
    
    if (conn->client_tls) {
        if (G_IS_IO_STREAM(conn->client_tls)) {
            g_io_stream_close(G_IO_STREAM(conn->client_tls), NULL, NULL);
        }
        g_object_unref(conn->client_tls);
        conn->client_tls = NULL;
    }
    
    if (conn->upstream_tls) {
        if (G_IS_IO_STREAM(conn->upstream_tls)) {
            g_io_stream_close(G_IO_STREAM(conn->upstream_tls), NULL, NULL);
        }
        g_object_unref(conn->upstream_tls);
        conn->upstream_tls = NULL;
    }

    // Now close the underlying socket connections
    if (conn->client_connection) {
        if (G_IS_IO_STREAM(conn->client_connection)) {
            g_io_stream_close(G_IO_STREAM(conn->client_connection), NULL, NULL);
        }
        if (G_IS_OBJECT(conn->client_connection)) {
            g_object_unref(conn->client_connection);
        }
        conn->client_connection = NULL;
    }
    
    if (conn->upstream_connection) {
        if (G_IS_IO_STREAM(conn->upstream_connection)) {
            g_io_stream_close(G_IO_STREAM(conn->upstream_connection), NULL, NULL);
        }
        if (G_IS_OBJECT(conn->upstream_connection)) {
            g_object_unref(conn->upstream_connection);
        }
        conn->upstream_connection = NULL;
    }

    // Clean up OpenSSL objects (if any remain from old code)
    if (conn->client_ssl) {
        SSL_shutdown(conn->client_ssl);
        SSL_free(conn->client_ssl);
    }

    if (conn->upstream_ssl) {
        SSL_shutdown(conn->upstream_ssl);
        SSL_free(conn->upstream_ssl);
    }

    if (conn->ssl_ctx) {
        SSL_CTX_free(conn->ssl_ctx);
    }
    
    // Clean up certificate reference
    if (conn->upstream_peer_cert) {
        g_object_unref(conn->upstream_peer_cert);
        conn->upstream_peer_cert = NULL;
    }
    
    // Free buffers
    if (conn->client_buffer) {
        g_byte_array_free(conn->client_buffer, TRUE);
    }
    
    if (conn->upstream_buffer) {
        g_byte_array_free(conn->upstream_buffer, TRUE);
    }
    
    // Free strings
    g_free(conn->client_address);
    g_free(conn->target_host);
    g_free(conn->username);
    g_free(conn->session_token);
    
    // Free plugin data
    if (conn->plugin_data) {
        g_hash_table_destroy(conn->plugin_data);
    }
    
    // Free request/response
    if (conn->current_request) {
        deadlight_request_free(conn->current_request);
    }
    
    if (conn->current_response) {
        deadlight_response_free(conn->current_response);
    }
    
    // Stop timer
    if (conn->connection_timer) {
        g_timer_destroy(conn->connection_timer);
    }
    
    // Update stats
    if (conn->context) {
        conn->context->bytes_transferred += conn->bytes_client_to_upstream + 
                                           conn->bytes_upstream_to_client;
    }
    
    g_free(conn);
}

gboolean deadlight_tls_tunnel_data(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->client_tls != NULL, FALSE);
    g_return_val_if_fail(conn->upstream_tls != NULL, FALSE);
    
    g_info("Connection %lu: Starting TLS tunnel", conn->id);
    
    // Get TLS connection properties for debugging
    gchar *negotiated_protocol = NULL;
    g_object_get(conn->client_tls, "negotiated-protocol", &negotiated_protocol, NULL);
    if (negotiated_protocol) {
        g_debug("Connection %lu: Client negotiated protocol: %s", conn->id, negotiated_protocol);
        g_free(negotiated_protocol);
    }
    
    GInputStream *client_input = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_tls));
    GOutputStream *client_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_tls));
    GInputStream *upstream_input = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_tls));
    GOutputStream *upstream_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_tls));
    
    guchar buffer[16384];
    gboolean running = TRUE;
    conn->state = DEADLIGHT_STATE_TUNNELING;
    
    // Keep track of consecutive empty reads
    gint empty_reads = 0;
    const gint MAX_EMPTY_READS = 50; // 50ms timeout if nothing happening
    
    // Make sure underlying sockets are in non-blocking mode for better control
    GSocket *client_socket = NULL;
    GSocket *upstream_socket = NULL;
    
    if (G_IS_SOCKET_CONNECTION(conn->client_connection)) {
        client_socket = g_socket_connection_get_socket(G_SOCKET_CONNECTION(conn->client_connection));
        g_socket_set_blocking(client_socket, FALSE);
    }
    if (G_IS_SOCKET_CONNECTION(conn->upstream_connection)) {
        upstream_socket = g_socket_connection_get_socket(G_SOCKET_CONNECTION(conn->upstream_connection));
        g_socket_set_blocking(upstream_socket, FALSE);
    }
    
    while (running && conn->state == DEADLIGHT_STATE_TUNNELING) {
        GError *local_error = NULL;
        gssize bytes_read, bytes_written;
        gboolean data_transferred = FALSE;
        gboolean client_would_block = FALSE;
        gboolean upstream_would_block = FALSE;
        
        // Client -> Upstream
        if (g_pollable_input_stream_is_readable(G_POLLABLE_INPUT_STREAM(client_input))) {
            bytes_read = g_pollable_input_stream_read_nonblocking(
                G_POLLABLE_INPUT_STREAM(client_input),
                buffer, sizeof(buffer),
                NULL, &local_error
            );
            
            if (bytes_read > 0) {
                empty_reads = 0;
                bytes_written = g_output_stream_write_all(
                    upstream_output, buffer, bytes_read, 
                    NULL, NULL, &local_error
                );
                if (bytes_written) {
                    conn->bytes_client_to_upstream += bytes_read;
                    data_transferred = TRUE;
                    g_output_stream_flush(upstream_output, NULL, NULL);
                }
                if (local_error) {
                    g_debug("Write to upstream error: %s", local_error->message);
                    g_clear_error(&local_error);
                }
            } else if (bytes_read == 0) {
                // Clean EOF
                g_debug("Connection %lu: Client closed connection cleanly", conn->id);
                running = FALSE;
            } else if (local_error) {
                if (g_error_matches(local_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    client_would_block = TRUE;
                } else if (g_error_matches(local_error, G_TLS_ERROR, G_TLS_ERROR_EOF)) {
                    g_debug("Connection %lu: Client TLS EOF", conn->id);
                    running = FALSE;
                } else {
                    g_debug("Connection %lu: Client read error: %s", conn->id, local_error->message);
                    running = FALSE;
                }
                g_clear_error(&local_error);
            }
        } else {
            client_would_block = TRUE;
        }
        
        // Upstream -> Client
        if (g_pollable_input_stream_is_readable(G_POLLABLE_INPUT_STREAM(upstream_input))) {
            bytes_read = g_pollable_input_stream_read_nonblocking(
                G_POLLABLE_INPUT_STREAM(upstream_input),
                buffer, sizeof(buffer),
                NULL, &local_error
            );
            
            if (bytes_read > 0) {
                empty_reads = 0;
                bytes_written = g_output_stream_write_all(
                    client_output, buffer, bytes_read,
                    NULL, NULL, &local_error
                );
                if (bytes_written) {
                    conn->bytes_upstream_to_client += bytes_read;
                    data_transferred = TRUE;
                    g_output_stream_flush(client_output, NULL, NULL);
                }
                if (local_error) {
                    g_debug("Write to client error: %s", local_error->message);
                    g_clear_error(&local_error);
                }
            } else if (bytes_read == 0) {
                // Clean EOF
                g_debug("Connection %lu: Upstream closed connection cleanly", conn->id);
                running = FALSE;
            } else if (local_error) {
                if (g_error_matches(local_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    upstream_would_block = TRUE;
                } else if (g_error_matches(local_error, G_TLS_ERROR, G_TLS_ERROR_EOF)) {
                    g_debug("Connection %lu: Upstream TLS EOF", conn->id);
                    running = FALSE;
                } else {
                    g_debug("Connection %lu: Upstream read error: %s", conn->id, local_error->message);
                    running = FALSE;
                }
                g_clear_error(&local_error);
            }
        } else {
            upstream_would_block = TRUE;
        }
        
        // If both would block and no data transferred, check for timeout
        if (running && !data_transferred) {
            if (client_would_block && upstream_would_block) {
                empty_reads++;
                if (empty_reads > MAX_EMPTY_READS) {
                    // Check if connections are still alive
                    if (client_socket && !g_socket_is_connected(client_socket)) {
                        g_debug("Connection %lu: Client socket disconnected", conn->id);
                        running = FALSE;
                    }
                    if (upstream_socket && !g_socket_is_connected(upstream_socket)) {
                        g_debug("Connection %lu: Upstream socket disconnected", conn->id);
                        running = FALSE;
                    }
                }
            }
            g_usleep(1000); // 1ms
        }
    }
    
    g_info("Connection %lu: TLS tunnel closed (client->upstream: %lu B, upstream->client: %lu B)",
           conn->id, conn->bytes_client_to_upstream, conn->bytes_upstream_to_client);
    
    conn->state = DEADLIGHT_STATE_CLOSING;
    
    (void)error; // Suppress unused parameter warning
    return TRUE;
}
/**
 * Transfer data between client and upstream
 */

gboolean deadlight_network_tunnel_data(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->client_connection != NULL, FALSE);
    g_return_val_if_fail(conn->upstream_connection != NULL, FALSE);

    // Client streams
    GInputStream *client_is;
    GOutputStream *client_os;
    if (conn->client_tls) {
        g_info("Connection %lu: Tunneling with intercepted client TLS.", conn->id);
        client_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_tls));
        client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_tls));
    } else {
        g_info("Connection %lu: Tunneling with plain-text client.", conn->id);
        client_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
        client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    }

    // Upstream streams
    GInputStream *upstream_is;
    GOutputStream *upstream_os;
    if (conn->upstream_tls) {
        g_info("Connection %lu: Tunneling with upstream TLS.", conn->id);
        upstream_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_tls));
        upstream_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_tls));
    } else {
        g_info("Connection %lu: Tunneling with plain-text upstream.", conn->id);
        upstream_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_connection));
        upstream_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
    }

    // Your existing bidirectional tunnel logic (polling, reading, writing)
    guint8 buffer[16384];
    gboolean running = TRUE;
    GPollFD fds[2];
    gint nfds = 2;

    // Set up poll fds (adjust based on your exact impl; this assumes socket-based)
    GSocket *client_socket = g_socket_connection_get_socket(conn->client_connection);
    GSocket *upstream_socket = g_socket_connection_get_socket(conn->upstream_connection);
    fds[0].fd = g_socket_get_fd(client_socket);
    fds[1].fd = g_socket_get_fd(upstream_socket);
    fds[0].events = G_IO_IN | G_IO_HUP | G_IO_ERR;
    fds[1].events = G_IO_IN | G_IO_HUP | G_IO_ERR;

    while (running) {
        gint ready = g_poll(fds, nfds, -1);  // Timeout -1 for blocking
        if (ready < 0) {
            g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno), "Poll failed: %s", g_strerror(errno));
            return FALSE;
        }

        // Client to upstream
        if (fds[0].revents & (G_IO_IN | G_IO_HUP | G_IO_ERR)) {
            gssize bytes_read = g_input_stream_read(client_is, buffer, sizeof(buffer), NULL, error);
            if (bytes_read > 0) {
                if (!g_output_stream_write_all(upstream_os, buffer, bytes_read, NULL, NULL, error)) {
                    g_warning("Connection %lu: Failed to write to upstream: %s", conn->id, (*error)->message);
                    running = FALSE;
                } else {
                    conn->bytes_client_to_upstream += bytes_read;
                }
            } else {
                running = FALSE;
            }
        }

        // Upstream to client
        if (fds[1].revents & (G_IO_IN | G_IO_HUP | G_IO_ERR)) {
            gssize bytes_read = g_input_stream_read(upstream_is, buffer, sizeof(buffer), NULL, error);
            if (bytes_read > 0) {
                if (!g_output_stream_write_all(client_os, buffer, bytes_read, NULL, NULL, error)) {
                    g_warning("Connection %lu: Failed to write to client: %s", conn->id, (*error)->message);
                    running = FALSE;
                } else {
                    conn->bytes_upstream_to_client += bytes_read;
                }
            } else {
                running = FALSE;
            }
        }
    }

    conn->state = DEADLIGHT_STATE_CLOSING;
    g_info("Connection %lu: Tunnel closed (client->upstream: %s, upstream->client: %s)",
           conn->id,
           deadlight_format_bytes(conn->bytes_client_to_upstream),
           deadlight_format_bytes(conn->bytes_upstream_to_client));

    return TRUE;
}
