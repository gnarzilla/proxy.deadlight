/**
 * Deadlight Proxy v1.0 - Network Module
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
#include "utils.h"

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
GSocketConnection* deadlight_network_connect_tcp(DeadlightContext *context, const gchar *host, guint16 port, GError **error);
void deadlight_network_tunnel_socket_connections(GSocketConnection *conn1, GSocketConnection *conn2);
static void cleanup_connection_internal(DeadlightConnection *conn, gboolean remove_from_table);
static void connection_pool_log_stats(ConnectionPool *pool);

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
    context->connections = g_hash_table_new_full(
        g_int64_hash, 
        g_int64_equal,
        g_free,  // Free the guint64* key
        (GDestroyNotify)cleanup_connection  // Clean up DeadlightConnection value
    );
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
 * Determine if an upstream connection will use SSL
 * 
 * This function predicts whether the connection will be SSL-secured
 * BEFORE actually connecting, so can look up the correct pool entry.
 * 
 * Accounts for:
 * - Protocol type (HTTPS, IMAPS always SSL)
 * - Target port (443, 993, 995, 465, 989 → likely SSL)
 * - SSL interception settings
 * - Already-negotiated TLS state
 */
static gboolean network_should_use_ssl(DeadlightProtocol protocol,
                                       DeadlightConnection *conn) {
    g_return_val_if_fail(conn != NULL, FALSE);
    
    // Already have TLS established
    if (conn->upstream_tls != NULL) {
        return TRUE;
    }
    
    switch (protocol) {
        case DEADLIGHT_PROTOCOL_HTTPS:
        case DEADLIGHT_PROTOCOL_IMAPS:
            return TRUE;
        
        case DEADLIGHT_PROTOCOL_CONNECT:
            // CONNECT never auto-establishes SSL
            // The handler decides later based on interception settings
            return FALSE;
        
        case DEADLIGHT_PROTOCOL_HTTP:
        {
            // Plain HTTP never uses SSL on upstream
            // (HTTPS comes through CONNECT, not HTTP)
            return FALSE;
        }
        
        // Text protocols: plain initially, might upgrade
        case DEADLIGHT_PROTOCOL_SMTP:
        case DEADLIGHT_PROTOCOL_IMAP:
            return FALSE;
        
        // SOCKS: depends on target port
        case DEADLIGHT_PROTOCOL_SOCKS:
        case DEADLIGHT_PROTOCOL_SOCKS4:
        case DEADLIGHT_PROTOCOL_SOCKS5:
        {
            if (conn->target_port > 0) {
                return conn->target_port == 443 ||
                       conn->target_port == 993 ||
                       conn->target_port == 995 ||
                       conn->target_port == 465 ||
                       conn->target_port == 989;
            }
            return FALSE;
        }
        
        case DEADLIGHT_PROTOCOL_WEBSOCKET:
            return conn->target_port == 443;
        
        case DEADLIGHT_PROTOCOL_FTP:
            return conn->target_port == 989;
        
        default:
            return FALSE;
    }
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

/**
 * Fixed network stop function
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
        
        // Close all active connections CAREFULLY
        if (context->connections) {
            guint count = g_hash_table_size(context->connections);
            g_info("Closing %u active connections...", count);
            
            // Extract all connections to a list first
            GList *conn_list = g_hash_table_get_values(context->connections);
            
            // Clean up each connection without modifying the hash table
            for (GList *l = conn_list; l != NULL; l = l->next) {
                DeadlightConnection *conn = (DeadlightConnection *)l->data;
                if (conn) {
                    cleanup_connection_internal(conn, FALSE);  // Don't remove from table
                }
            }
            g_list_free(conn_list);
            
            // Now destroy the emptied hash table
            g_hash_table_destroy(context->connections);
            context->connections = NULL;
        }
        
        // Shutdown thread pool (wait for workers to finish)
        if (context->worker_pool) {
            g_thread_pool_free(context->worker_pool, FALSE, TRUE);
            context->worker_pool = NULL;
        }
        
        // Log and destroy connection pool
        if (context->conn_pool) {
            connection_pool_log_stats(context->conn_pool);
            connection_pool_free(context->conn_pool);
            context->conn_pool = NULL;
        }
        
        g_mutex_clear(&context->network->connection_mutex);
        g_free(context->network);
        context->network = NULL;
    }
    
    g_info("Network module stopped");
}

/**
 * Free connection object
 */

void deadlight_connection_free(DeadlightConnection *conn) {
    if (!conn) return;

    // This API function should now delegate the full cleanup logic
    // and rely on the state machine to be clean.
    // Given its current use in on_incoming_connection for a *rejected* conn:
    cleanup_connection(conn); // <-- Call full cleanup/free
    // The cleanup_connection will handle the context removal and g_free(conn).
}
/**
 * Handle incoming connection
 */
static gboolean on_incoming_connection(GSocketService *service,
                                     GSocketConnection *connection,
                                     GObject *source_object,
                                     gpointer user_data) {
    (void)service; 
    (void)source_object; 
    
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
    DeadlightConnection *conn = deadlight_connection_new(context, connection, client_str); 

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
                                            GSocketConnection *client_connection,
                                             gchar *client_address_str) {
    DeadlightConnection *conn = g_new0(DeadlightConnection, 1);

    
    // Set ID
    g_mutex_lock(&context->network->connection_mutex);
    conn->id = context->network->next_connection_id++;
    g_mutex_unlock(&context->network->connection_mutex);
    
    // Initialize connection
    conn->cleaned = FALSE;
    conn->context = context;
    conn->client_connection = g_object_ref(client_connection);
    conn->state = DEADLIGHT_STATE_INIT;
    conn->client_address = client_address_str;
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
 * Worker thread function
 */

static void connection_thread_func(gpointer data, gpointer user_data) {
    DeadlightConnection *conn = (DeadlightConnection *)data;
    DeadlightContext *context = (DeadlightContext *)user_data;
    GError *error = NULL;

    g_debug("Worker thread processing connection %lu", conn->id);

    conn->state = DEADLIGHT_STATE_DETECTING;

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
    // ===== PROTOCOL HANDLING LOGIC ========
    // ==========================================================


    DeadlightHandlerResult handler_result = handler->handle(conn, &error);

    switch (handler_result) {
        case HANDLER_SUCCESS_CLEANUP_NOW:
            g_info("Connection %lu: Synchronous handler for '%s' completed.", 
                conn->id, deadlight_protocol_to_string(conn->protocol));
            cleanup_connection(conn);
            return;
            
        case HANDLER_SUCCESS_ASYNC:
            g_debug("Connection %lu: Asynchronous handler for '%s' started; worker thread exiting.", 
                    conn->id, deadlight_protocol_to_string(conn->protocol));
            // Handler now owns the connection lifecycle
            // If handler crashes or forgets cleanup, connection will be orphaned
            // TODO: Consider adding a timeout-based cleanup watchdog
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
            goto cleanup;
    }
    
    return;  // Exit cleanly for ASYNC case
    
    cleanup:
        if (conn->handler && conn->handler->cleanup) {
            conn->handler->cleanup(conn);
        }
        cleanup_connection_internal(conn, TRUE);  // <-- Explicitly remove from table
}

// ==============================================================
// Upstream connection with pool 
// ==============================================================
/**
 * Connect to upstream server
 * 
 * UPDATED: SSL-aware pooling with protocol-specific logic
 * 
 * This function:
 * 1. Determines if SSL will be used based on protocol
 * 2. Checks the pool for a matching connection (with correct SSL status)
 * 3. Creates a new connection if pool miss
 * 4. Registers the connection for tracking
 * 5. Establishes SSL if needed
 */
gboolean deadlight_network_connect_upstream(DeadlightConnection *conn, 
                                          const gchar *host, 
                                          guint16 port,
                                          GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(host != NULL, FALSE);
    g_return_val_if_fail(port > 0, FALSE);
    
    DeadlightContext *context = conn->context;
    
    // === STEP 1: Store target info ===
    if (!conn->target_host) {
        conn->target_host = g_strdup(host);
    }
    conn->target_port = port;
    
    // === STEP 2: Already connected to same target? ===
    if (conn->upstream_connection) {
        if (g_strcmp0(conn->target_host, host) == 0 && 
            conn->target_port == port) {
            g_debug("Connection %lu: Upstream already connected to %s:%d",
                   conn->id, host, port);
            return TRUE;
        }
        
        // Different target (shouldn't happen in normal flow)
        g_warning("Connection %lu: Changing upstream target from %s:%d to %s:%d",
                 conn->id, conn->target_host, conn->target_port, host, port);
        g_object_unref(conn->upstream_connection);
        conn->upstream_connection = NULL;
    }
    
    // === STEP 3: Determine SSL requirement AT THIS MOMENT ===
    gboolean will_use_ssl = network_should_use_ssl(conn->protocol, conn);
    
    g_debug("Connection %lu: Upstream lookup: %s:%d (protocol=%s, will_ssl=%d)",
           conn->id, host, port,
           deadlight_protocol_to_string(conn->protocol), will_use_ssl);
    
    // === STEP 4: Check pool ===
    GSocketConnection *pooled = connection_pool_get(
        context->conn_pool, host, port, will_use_ssl);
    
    if (pooled) {
        conn->upstream_connection = pooled;
        g_info("Connection %lu: Pool HIT: Reused %s:%d (SSL=%d)",
               conn->id, host, port, will_use_ssl);
        
        // For SSL connections from pool, ensure TLS is established
        if (will_use_ssl && !conn->upstream_tls) {
            g_debug("Connection %lu: Establishing SSL on pooled connection", conn->id);
            if (!deadlight_network_establish_upstream_ssl(conn, error)) {
                g_warning("Connection %lu: SSL failed on pooled connection: %s",
                         conn->id, error && *error ? (*error)->message : "unknown");
                // Don't return to pool - this connection is broken
                g_object_unref(conn->upstream_connection);
                conn->upstream_connection = NULL;
                return FALSE;
            }
        }
        
        return TRUE;
    }
    
    // === STEP 5: Pool miss - create new connection ===
    g_debug("Connection %lu: Pool MISS - creating new connection to %s:%d",
           conn->id, host, port);
    
    GSocketClient *client = g_socket_client_new();
    
    // Get timeout from config
    gint timeout = deadlight_config_get_int(context, "network", 
                                           "upstream_timeout", 30);
    g_socket_client_set_timeout(client, timeout);
    
    // Check IPv6 preference
    gboolean ipv6_enabled = deadlight_config_get_bool(context, "network", 
                                                     "ipv6_enabled", TRUE);
    g_socket_client_set_enable_proxy(client, FALSE);
    if (!ipv6_enabled) {
        g_socket_client_set_family(client, G_SOCKET_FAMILY_IPV4);
    }
    
    // Attempt connection
    conn->upstream_connection = g_socket_client_connect_to_host(
        client, host, port, NULL, error);
    g_object_unref(client);
    
    if (!conn->upstream_connection) {
        g_warning("Connection %lu: Failed to connect to %s:%d: %s",
                 conn->id, host, port,
                 error && *error ? (*error)->message : "unknown");
        return FALSE;
    }
    
    // === STEP 6: Register with pool for future reuse ===
    connection_pool_register(context->conn_pool, 
                            conn->upstream_connection,
                            host, port, will_use_ssl);
    
    // === STEP 7: Configure socket options ===
    GSocket *socket = g_socket_connection_get_socket(conn->upstream_connection);
    g_socket_set_blocking(socket, FALSE);
    
    gint optval = 1;
    g_socket_set_option(socket, SOL_SOCKET, SO_KEEPALIVE, optval, NULL);
    
    if (deadlight_config_get_bool(context, "network", "tcp_nodelay", TRUE)) {
        g_socket_set_option(socket, IPPROTO_TCP, TCP_NODELAY, optval, NULL);
    }
    
    // === STEP 8: Establish SSL if needed ===
    if (will_use_ssl) {
        g_debug("Connection %lu: Establishing SSL for new connection", conn->id);
        if (!deadlight_network_establish_upstream_ssl(conn, error)) {
            g_warning("Connection %lu: Failed to establish SSL: %s",
                     conn->id, error && *error ? (*error)->message : "unknown");
            // Connection broken, close it
            g_object_unref(conn->upstream_connection);
            conn->upstream_connection = NULL;
            return FALSE;
        }
    }
    
    g_info("Connection %lu: Connected to %s:%d (SSL=%d)",
           conn->id, host, port, will_use_ssl);
    
    return TRUE;
}

/**
 * Internal cleanup with proper NULL checks and safe object handling
 */
static void cleanup_connection_internal(DeadlightConnection *conn, gboolean remove_from_table) {
    if (!conn) return;
    
    if (conn->cleaned) {
        g_debug("Connection %lu already cleaned, skipping", conn->id);
        return;
    }
    conn->cleaned = TRUE;

    g_debug("Cleaning up connection %lu (state=%d, remove_from_table=%d)", 
            conn->id, conn->state, remove_from_table);

    // Notify plugins FIRST (while connection is still valid)
    if (conn->context) {
        deadlight_plugins_call_on_connection_close(conn->context, conn);
    }
    
    // === POOL RELEASE: Return connection if appropriate ===
    if (conn->upstream_connection && conn->target_host && conn->context && conn->context->conn_pool) {
        // Check if this connection is actually in the pool
        // The pool will handle its own reference counting
        
        gboolean use_ssl = conn->upstream_tls != NULL;
        gboolean should_pool = FALSE;
        const gchar *reason = "unknown";
        
        // Check 1: Socket health
        GSocket *socket = g_socket_connection_get_socket(conn->upstream_connection);
        gboolean socket_ok = FALSE;
        
        if (socket && G_IS_SOCKET(socket)) {
            socket_ok = (g_socket_is_connected(socket) && 
                        g_socket_condition_check(socket, G_IO_ERR | G_IO_HUP) == 0);
        }
        
        if (!socket_ok) {
            reason = "socket dead";
        }
        // Check 2: Connection state
        else if (conn->state != DEADLIGHT_STATE_CLOSING &&
                 conn->state != DEADLIGHT_STATE_CONNECTED &&
                 conn->state != DEADLIGHT_STATE_TUNNELING) {
            reason = "bad state";
        }
        // Check 3: Protocol-specific rules
        else {
            switch (conn->protocol) {
                case DEADLIGHT_PROTOCOL_HTTP:
                {
                    gboolean keep_alive = TRUE;
                    if (conn->current_request) {
                        const gchar *conn_hdr = g_hash_table_lookup(
                            conn->current_request->headers, "Connection");
                        if (conn_hdr && g_ascii_strcasecmp(conn_hdr, "close") == 0) {
                            keep_alive = FALSE;
                        }
                    }
                    
                    if (keep_alive) {
                        should_pool = TRUE;
                        reason = "HTTP keep-alive";
                    } else {
                        reason = "HTTP Connection: close";
                    }
                    break;
                }
                
                case DEADLIGHT_PROTOCOL_HTTPS:
                    if (conn->state == DEADLIGHT_STATE_CONNECTED && use_ssl) {
                        should_pool = TRUE;
                        reason = "HTTPS clean";
                    } else {
                        reason = "HTTPS incomplete";
                    }
                    break;
                
                case DEADLIGHT_PROTOCOL_IMAP:
                case DEADLIGHT_PROTOCOL_IMAPS:
                    if (conn->authenticated && conn->state == DEADLIGHT_STATE_CONNECTED) {
                        should_pool = TRUE;
                        reason = "IMAP auth OK";
                    } else {
                        reason = "IMAP not auth";
                    }
                    break;
                
                case DEADLIGHT_PROTOCOL_SMTP:
                    if (conn->state == DEADLIGHT_STATE_CONNECTED) {
                        should_pool = TRUE;
                        reason = "SMTP OK";
                    } else {
                        reason = "SMTP incomplete";
                    }
                    break;
                
                // One-way protocols - never pool
                case DEADLIGHT_PROTOCOL_CONNECT:
                case DEADLIGHT_PROTOCOL_SOCKS:
                case DEADLIGHT_PROTOCOL_SOCKS4:
                case DEADLIGHT_PROTOCOL_SOCKS5:
                case DEADLIGHT_PROTOCOL_WEBSOCKET:
                    reason = "one-way protocol";
                    break;
                
                case DEADLIGHT_PROTOCOL_FTP:
                    reason = "FTP complex";
                    break;
                
                default:
                    reason = "unknown protocol";
                    break;
            }
        }
        if (should_pool) {
            g_info("Connection %lu: Returning to pool: %s:%d (SSL=%d, reason=%s)",
                conn->id, conn->target_host, conn->target_port, use_ssl, reason);
            
            connection_pool_release(
                conn->context->conn_pool,
                conn->upstream_connection,
                conn->target_host,
                conn->target_port,
                use_ssl
            );
            
            // Pool now owns the reference - clear our pointer but don't unref
            conn->upstream_connection = NULL;
        } else {
            g_debug("Connection %lu: Not pooling: %s:%d (SSL=%d, reason=%s)",
                conn->id, conn->target_host, conn->target_port, use_ssl, reason);
            // We still own this connection, will be cleaned up below
        }
    }
    
    // === CLOSE TLS CONNECTIONS (before underlying sockets) ===
    if (conn->client_tls) {
        if (G_IS_IO_STREAM(conn->client_tls)) {
            GError *close_error = NULL;
            if (!g_io_stream_close(G_IO_STREAM(conn->client_tls), NULL, &close_error)) {
                if (close_error) {
                    g_debug("Connection %lu: Client TLS close error: %s", 
                           conn->id, close_error->message);
                    g_error_free(close_error);
                }
            }
        }
        if (G_IS_OBJECT(conn->client_tls)) {
            g_object_unref(conn->client_tls);
        }
        conn->client_tls = NULL;
    }
    
    if (conn->upstream_tls) {
        if (G_IS_IO_STREAM(conn->upstream_tls)) {
            GError *close_error = NULL;
            if (!g_io_stream_close(G_IO_STREAM(conn->upstream_tls), NULL, &close_error)) {
                if (close_error) {
                    g_debug("Connection %lu: Upstream TLS close error: %s",
                           conn->id, close_error->message);
                    g_error_free(close_error);
                }
            }
        }
        if (G_IS_OBJECT(conn->upstream_tls)) {
            g_object_unref(conn->upstream_tls);
        }
        conn->upstream_tls = NULL;
    }

    // === CLOSE UNDERLYING SOCKET CONNECTIONS ===
    if (conn->client_connection) {
        if (G_IS_IO_STREAM(conn->client_connection)) {
            GError *close_error = NULL;
            if (!g_io_stream_close(G_IO_STREAM(conn->client_connection), NULL, &close_error)) {
                if (close_error) {
                    g_debug("Connection %lu: Client socket close error: %s",
                           conn->id, close_error->message);
                    g_error_free(close_error);
                }
            }
        }
        if (G_IS_OBJECT(conn->client_connection)) {
            g_object_unref(conn->client_connection);
        }
        conn->client_connection = NULL;
    }
    
    if (conn->upstream_connection) {
        // Only close if not pooled (would be NULL if pooled)
        if (G_IS_IO_STREAM(conn->upstream_connection)) {
            GError *close_error = NULL;
            if (!g_io_stream_close(G_IO_STREAM(conn->upstream_connection), NULL, &close_error)) {
                if (close_error) {
                    g_debug("Connection %lu: Upstream socket close error: %s",
                           conn->id, close_error->message);
                    g_error_free(close_error);
                }
            }
        }
        if (G_IS_OBJECT(conn->upstream_connection)) {
            g_object_unref(conn->upstream_connection);
        }
        conn->upstream_connection = NULL;
    }
    
    // === FREE OTHER RESOURCES ===
    if (conn->upstream_peer_cert && G_IS_OBJECT(conn->upstream_peer_cert)) {
        g_object_unref(conn->upstream_peer_cert);
        conn->upstream_peer_cert = NULL;
    }
    
    if (conn->client_buffer) {
        g_byte_array_free(conn->client_buffer, TRUE);
        conn->client_buffer = NULL;
    }
    
    if (conn->upstream_buffer) {
        g_byte_array_free(conn->upstream_buffer, TRUE);
        conn->upstream_buffer = NULL;
    }
    
    g_free(conn->client_address);
    conn->client_address = NULL;
    
    g_free(conn->target_host);
    conn->target_host = NULL;
    
    g_free(conn->username);
    conn->username = NULL;
    
    g_free(conn->session_token);
    conn->session_token = NULL;
    
    if (conn->plugin_data) {
        g_hash_table_destroy(conn->plugin_data);
        conn->plugin_data = NULL;
    }
    
    if (conn->current_request) {
        deadlight_request_free(conn->current_request);
        conn->current_request = NULL;
    }
    
    if (conn->current_response) {
        deadlight_response_free(conn->current_response);
        conn->current_response = NULL;
    }
    
    if (conn->connection_timer) {
        g_timer_destroy(conn->connection_timer);
        conn->connection_timer = NULL;
    }
    
    // === UPDATE STATS AND REMOVE FROM TABLE ===
    if (conn->context) {
        // Update stats
        g_mutex_lock(&conn->context->stats_mutex);
        conn->context->bytes_transferred += 
            conn->bytes_client_to_upstream + conn->bytes_upstream_to_client;
        g_mutex_unlock(&conn->context->stats_mutex);
        
        // Remove from connection table
        if (remove_from_table && conn->context->network && conn->context->connections) {
            g_mutex_lock(&conn->context->network->connection_mutex);
            
            // Find the connection by value and remove it
            GHashTableIter iter;
            gpointer key, value;
            g_hash_table_iter_init(&iter, conn->context->connections);
            
            while (g_hash_table_iter_next(&iter, &key, &value)) {
                if (value == conn) {
                    g_hash_table_iter_remove(&iter);  // This will call the destructor
                    conn->context->active_connections--;
                    break;
                }
            }
            
            g_mutex_unlock(&conn->context->network->connection_mutex);
            
            // IMPORTANT: Don't free conn here! 
            // g_hash_table_iter_remove already called the destructor which freed it
            return;  // <-- ADD THIS RETURN
        }
    }
    
    // Only free if we didn't remove from table (and thus destructor wasn't called)
    g_free(conn);
}

/**
 * Public cleanup function - used as hash table destructor
 * This is called BY the hash table, so DON'T remove from table
 */
static void cleanup_connection(DeadlightConnection *conn) {
    cleanup_connection_internal(conn, FALSE);  // Don't remove from table
}

/**
 * Worker thread cleanup - DOES remove from table
 * This is called BY worker threads, so DO remove from table
 */
static void cleanup_connection_and_remove(DeadlightConnection *conn) {
    cleanup_connection_internal(conn, TRUE);  // Remove from table
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
 * A simple, blocking TCP connection function.
 */
GSocketConnection* deadlight_network_connect_tcp(DeadlightContext *context, const gchar *host, guint16 port, GError **error) {
    // We now have the context if we need it for config values.
    // Since we aren't using it yet, we can mark it to prevent new warnings.
    (void)context;

    GSocketClient *client = g_socket_client_new();

    // FUTURE USE: g_socket_client_set_timeout(client, deadlight_config_get_int(context, "network", "upstream_timeout", 30));

    GSocketConnection *connection = g_socket_client_connect_to_host(client, host, port, NULL, error);
    g_object_unref(client);

    return connection;
}

/**
 * Tunnels data between two GSocketConnections using a g_poll loop.
 * This is a generic version of the SSL tunnel logic.
 */
void deadlight_network_tunnel_socket_connections(GSocketConnection *conn1, GSocketConnection *conn2) {
    // This logic is nearly identical to the refactored start_ssl_tunnel_blocking
    
    GPollFD fds[2];
    fds[0].fd = g_socket_get_fd(g_socket_connection_get_socket(conn1));
    fds[0].events = G_IO_IN;
    fds[1].fd = g_socket_get_fd(g_socket_connection_get_socket(conn2));
    fds[1].events = G_IO_IN;
    
    GInputStream *in1 = g_io_stream_get_input_stream(G_IO_STREAM(conn1));
    GOutputStream *out1 = g_io_stream_get_output_stream(G_IO_STREAM(conn1));
    GInputStream *in2 = g_io_stream_get_input_stream(G_IO_STREAM(conn2));
    GOutputStream *out2 = g_io_stream_get_output_stream(G_IO_STREAM(conn2));

    guchar buffer[16384];
    gboolean running = TRUE;

    while (running) {
        int ret = g_poll(fds, 2, 30000); // 30 second timeout
        if (ret <= 0) break; // Error or timeout

        if (fds[0].revents & (G_IO_IN | G_IO_HUP | G_IO_ERR)) {
            gssize bytes = g_input_stream_read(in1, buffer, sizeof(buffer), NULL, NULL);
            if (bytes <= 0 || !g_output_stream_write_all(out2, buffer, bytes, NULL, NULL, NULL)) {
                running = FALSE;
            }
        }

        if (running && (fds[1].revents & (G_IO_IN | G_IO_HUP | G_IO_ERR))) {
            gssize bytes = g_input_stream_read(in2, buffer, sizeof(buffer), NULL, NULL);
            if (bytes <= 0 || !g_output_stream_write_all(out1, buffer, bytes, NULL, NULL, NULL)) {
                running = FALSE;
            }
        }
    }
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

    // Bidirectional tunnel logic (polling, reading, writing)
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

/**
 * Print detailed pool statistics to log
 */
static void connection_pool_log_stats(ConnectionPool *pool) {
    guint idle = 0;
    guint active = 0;
    guint64 total_gets = 0;
    guint64 cache_hits = 0;
    gdouble hit_rate = 0.0;

    connection_pool_get_stats(pool, &idle, &active, &total_gets, &cache_hits, &hit_rate);

    g_info("Pool Statistics: "
           "Hits: %lu, Misses: %lu, Hit Rate: %.1f%%, "
           "Active: %u, Idle: %u, Total: %u, "
           "Evicted: %u, Failed: %u",
           (unsigned long)cache_hits, 
           (unsigned long)(total_gets - cache_hits), 
           hit_rate,
           active, 
           idle, 
           active + idle,  // Calculate total from active + idle
           (guint)0,      // Placeholder for evicted (implement if needed)
           (guint)0);     // Placeholder for failed (implement if needed)
}