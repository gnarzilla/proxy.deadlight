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
    
    g_info("Network module initialized with %d worker threads", worker_threads);
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
void deadlight_connection_free(DeadlightConnection *conn) {
    if (!conn) return;
    
    cleanup_connection(conn);
}

/**
 * Worker thread function
 */
static void connection_thread_func(gpointer data, gpointer user_data) {
    DeadlightConnection *conn = (DeadlightConnection *)data;
    DeadlightContext *context = (DeadlightContext *)user_data;
    
    g_debug("Worker thread processing connection %lu", conn->id);
    
    // Set connection state
    conn->state = DEADLIGHT_STATE_DETECTING;
    
    // Set socket to non-blocking
    GSocket *socket = g_socket_connection_get_socket(conn->client_connection);
    g_socket_set_blocking(socket, FALSE);
    
    // Set socket options
    gint optval = 1;
    g_socket_set_option(socket, SOL_SOCKET, SO_KEEPALIVE, optval, NULL);
    
    if (deadlight_config_get_bool(context, "network", "tcp_nodelay", TRUE)) {
        g_socket_set_option(socket, IPPROTO_TCP, TCP_NODELAY, optval, NULL);
    }
    
    // Initial read to detect protocol
    guint8 peek_buffer[1024];
    gssize bytes_peeked;
    GError *error = NULL;
    
    // Wait for data with timeout
    gint timeout = deadlight_config_get_int(context, "protocols", 
                                          "protocol_detection_timeout", 5);
    gint64 end_time = g_get_monotonic_time() + (timeout * G_TIME_SPAN_SECOND);
    
    while (TRUE) {
        bytes_peeked = g_socket_receive(socket, (gchar *)peek_buffer, 
                                       sizeof(peek_buffer), NULL, &error);
        
        if (bytes_peeked > 0) {
            // Detect protocol
            conn->protocol = deadlight_protocol_detect(peek_buffer, bytes_peeked);
            g_info("Connection %lu: Detected protocol %s", conn->id,
                   deadlight_protocol_to_string(conn->protocol));
            
            // Store peeked data
            g_byte_array_append(conn->client_buffer, peek_buffer, bytes_peeked);
            break;
        }
        
        if (error) {
            if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                g_clear_error(&error);
                
                // Check timeout
                if (g_get_monotonic_time() > end_time) {
                    g_warning("Connection %lu: Protocol detection timeout", conn->id);
                    goto cleanup;
                }
                
                // Wait a bit before retry
                g_usleep(10000); // 10ms
                continue;
            } else {
                g_warning("Connection %lu: Read error: %s", conn->id, error->message);
                g_error_free(error);
                goto cleanup;
            }
        }
        
        // Connection closed
        if (bytes_peeked == 0) {
            g_info("Connection %lu: Client closed connection", conn->id);
            goto cleanup;
        }
    }
    
    // Check if protocol is supported
    if (conn->protocol == DEADLIGHT_PROTOCOL_UNKNOWN) {
        g_warning("Connection %lu: Unknown protocol", conn->id);
        goto cleanup;
    }
    
    // Check if protocol is enabled
    gboolean protocol_enabled = FALSE;
    switch (conn->protocol) {
        case DEADLIGHT_PROTOCOL_HTTP:
            protocol_enabled = deadlight_config_get_bool(context, "protocols", "http_enabled", TRUE);
            break;
        case DEADLIGHT_PROTOCOL_HTTPS:
        case DEADLIGHT_PROTOCOL_CONNECT:
            protocol_enabled = deadlight_config_get_bool(context, "protocols", "https_enabled", TRUE);
            break;
        case DEADLIGHT_PROTOCOL_SOCKS4:
            protocol_enabled = deadlight_config_get_bool(context, "protocols", "socks4_enabled", TRUE);
            break;
        case DEADLIGHT_PROTOCOL_SOCKS5:
            protocol_enabled = deadlight_config_get_bool(context, "protocols", "socks5_enabled", TRUE);
            break;
        case DEADLIGHT_PROTOCOL_WEBSOCKET:
            protocol_enabled = deadlight_config_get_bool(context, "protocols", "websocket_enabled", TRUE);
            break;
        default:
            break;
    }
    
    if (!protocol_enabled) {
        g_warning("Connection %lu: Protocol %s is disabled", conn->id,
                 deadlight_protocol_to_string(conn->protocol));
        goto cleanup;
    }
    
    // Call plugin hooks
    if (context->plugins) {
        // TODO: Call on_connection_accept and on_protocol_detect hooks
    }
    
    // Handle the protocol
    conn->state = DEADLIGHT_STATE_CONNECTING;
    
    if (!deadlight_protocol_handle_request(conn, &error)) {
        g_warning("Connection %lu: Failed to handle request: %s", 
                 conn->id, error ? error->message : "Unknown error");
        if (error) g_error_free(error);
        goto cleanup;
    }
    
    // Connection handling complete
    g_info("Connection %lu: Completed successfully", conn->id);
    
cleanup:
    // Remove from active connections
    g_mutex_lock(&context->network->connection_mutex);
    g_hash_table_remove(context->connections, &conn->id);
    context->active_connections--;
    g_mutex_unlock(&context->network->connection_mutex);
}

/**
 * Cleanup connection resources
 */
static void cleanup_connection(DeadlightConnection *conn) {
    if (!conn) return;
    
    g_debug("Cleaning up connection %lu", conn->id);
    
    // Close connections
    if (conn->client_connection) {
        g_io_stream_close(G_IO_STREAM(conn->client_connection), NULL, NULL);
        g_object_unref(conn->client_connection);
    }
    
    if (conn->upstream_connection) {
        g_io_stream_close(G_IO_STREAM(conn->upstream_connection), NULL, NULL);
        g_object_unref(conn->upstream_connection);
    }
    
    if (conn->client_tls) {
        g_io_stream_close(G_IO_STREAM(conn->client_tls), NULL, NULL);
        g_object_unref(conn->client_tls);
    }
    
    if (conn->upstream_tls) {
        g_io_stream_close(G_IO_STREAM(conn->upstream_tls), NULL, NULL);
        g_object_unref(conn->upstream_tls);
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
    
    g_info("Connection %lu: Connecting to upstream %s:%d", conn->id, host, port);
    
    // Create socket client
    GSocketClient *client = g_socket_client_new();
    
    // Set timeout
    gint timeout = deadlight_config_get_int(context, "network", "upstream_timeout", 30);
    g_socket_client_set_timeout(client, timeout);
    
    // Set IPv6 support
    gboolean ipv6_enabled = deadlight_config_get_bool(context, "network", "ipv6_enabled", TRUE);
    g_socket_client_set_enable_proxy(client, FALSE);
    g_socket_client_set_family(client, ipv6_enabled ? G_SOCKET_FAMILY_IPV4 : G_SOCKET_FAMILY_IPV4);
    
    // Connect
    conn->upstream_connection = g_socket_client_connect_to_host(client, host, port, NULL, error);
    g_object_unref(client);
    
    if (!conn->upstream_connection) {
        return FALSE;
    }
    
    // Store target info
    conn->target_host = g_strdup(host);
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
 * Transfer data between client and upstream
 */
gboolean deadlight_network_tunnel_data(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->client_connection != NULL, FALSE);
    g_return_val_if_fail(conn->upstream_connection != NULL, FALSE);
    
    conn->state = DEADLIGHT_STATE_TUNNELING;
    
    // Get streams
    GInputStream *client_input = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
    GOutputStream *client_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    GInputStream *upstream_input = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_connection));
    GOutputStream *upstream_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
    
    // Buffer for data transfer
    guint8 buffer[8192];
    gssize bytes_read, bytes_written;
    gboolean client_closed = FALSE;
    gboolean upstream_closed = FALSE;
    
    g_debug("Connection %lu: Starting data tunnel", conn->id);
    
    while (!client_closed && !upstream_closed) {
        // Client to upstream
        bytes_read = g_input_stream_read(client_input, buffer, sizeof(buffer), NULL, error);
        if (bytes_read > 0) {
            bytes_written = g_output_stream_write(upstream_output, buffer, bytes_read, NULL, error);
            if (bytes_written > 0) {
                conn->bytes_client_to_upstream += bytes_written;
            } else if (bytes_written < 0) {
                upstream_closed = TRUE;
            }
        } else if (bytes_read == 0) {
            client_closed = TRUE;
        } else if (error && *error) {
            if (!g_error_matches(*error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                client_closed = TRUE;
            }
            g_clear_error(error);
        }
        
        // Upstream to client
        bytes_read = g_input_stream_read(upstream_input, buffer, sizeof(buffer), NULL, error);
        if (bytes_read > 0) {
            bytes_written = g_output_stream_write(client_output, buffer, bytes_read, NULL, error);
            if (bytes_written > 0) {
                conn->bytes_upstream_to_client += bytes_written;
            } else if (bytes_written < 0) {
                client_closed = TRUE;
            }
        } else if (bytes_read == 0) {
            upstream_closed = TRUE;
        } else if (error && *error) {
            if (!g_error_matches(*error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                upstream_closed = TRUE;
            }
            g_clear_error(error);
        }
        
        // Small delay to prevent CPU spinning
        g_usleep(1000); // 1ms
    }
    
    conn->state = DEADLIGHT_STATE_CLOSING;
    
    g_info("Connection %lu: Tunnel closed (client->upstream: %s, upstream->client: %s)",
           conn->id,
           deadlight_format_bytes(conn->bytes_client_to_upstream),
           deadlight_format_bytes(conn->bytes_upstream_to_client));
    
    return TRUE;
}
