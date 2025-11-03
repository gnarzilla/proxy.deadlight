/**
 * Deadlight Proxy v1.0 - Connection Pool Implementation
 * 
 */

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include "deadlight.h"

//==============================================================
// STRUCT DEFINITIONS 
//==============================================================
typedef struct _PooledConnection {
    GSocketConnection *connection;
    gchar *host;
    guint16 port;
    gint64 last_used;
    gboolean is_ssl;
    guint64 requests_served; 
} PooledConnection;

struct _ConnectionPool {
    GQueue *idle_connections;
    GHashTable *active_connections;  // Key: GSocketConnection*, Value: PooledConnection*
    GMutex mutex;
    gint max_per_host;
    gint max_total_idle;
    gint idle_timeout;
    guint cleanup_source_id;
    
    // Statistics
    guint64 total_gets;
    guint64 cache_hits;
    guint64 cache_misses;
    guint64 connections_created;
    guint64 connections_closed;
};

// Forward declarations
static gboolean cleanup_idle_connections(gpointer user_data);
static void pooled_connection_free(PooledConnection *pc);
static gboolean connection_is_healthy(GSocketConnection *conn);

/**
 * Free a pooled connection
 */
static void pooled_connection_free(PooledConnection *pc) {
    if (!pc) return;
    
    if (pc->connection) {
        g_object_unref(pc->connection);
    }
    g_free(pc->host);
    g_free(pc);
}

/**
 * Check if a connection is still healthy
 * 
 * NOTE: For TLS connections, this only checks the underlying socket.
 * The TLS session state is managed separately.
 */
static gboolean connection_is_healthy(GSocketConnection *conn) {
    if (!conn) return FALSE;
    
    GSocket *socket = g_socket_connection_get_socket(conn);
    if (!socket) return FALSE;
    
    // Check socket state
    if (!g_socket_is_connected(socket)) {
        return FALSE;
    }
    
    // Check for errors/hangup without blocking
    if (g_socket_condition_check(socket, G_IO_ERR | G_IO_HUP) != 0) {
        return FALSE;
    }
    
    // TODO: For TLS connections, we could add more sophisticated checks:
    // - Verify TLS session is still valid
    // - Check for pending close_notify
    // For now, rely on socket health
    
    return TRUE;
}

/**
 * Create new connection pool
 */
ConnectionPool* connection_pool_new(gint max_per_host, gint idle_timeout) {
    ConnectionPool *pool = g_new0(ConnectionPool, 1);
    pool->idle_connections = g_queue_new();
    

    pool->active_connections = g_hash_table_new_full(
        g_direct_hash, 
        g_direct_equal,
        NULL,  // Key is just a pointer, no cleanup needed
        (GDestroyNotify)pooled_connection_free  // Value cleanup
    );
    
    g_mutex_init(&pool->mutex);
    pool->max_per_host = max_per_host;
    pool->max_total_idle = max_per_host * 10;  // Global limit
    pool->idle_timeout = idle_timeout;
    
    // Start cleanup timer
    pool->cleanup_source_id = g_timeout_add_seconds(30, cleanup_idle_connections, pool);
    
    g_info("Connection pool created: max_per_host=%d, idle_timeout=%ds", 
           max_per_host, idle_timeout);
    
    return pool;
}

/**
 * Free connection pool
 */
void connection_pool_free(ConnectionPool *pool) {
    if (!pool) return;
    
    g_info("Destroying connection pool (stats: gets=%lu, hits=%lu, misses=%lu, created=%lu, closed=%lu)",
           pool->total_gets, pool->cache_hits, pool->cache_misses,
           pool->connections_created, pool->connections_closed);
    
    // Cancel cleanup timer
    if (pool->cleanup_source_id) {
        g_source_remove(pool->cleanup_source_id);
    }
    
    // Clean up idle connections
    PooledConnection *pc;
    while ((pc = g_queue_pop_head(pool->idle_connections))) {
        pooled_connection_free(pc);
    }
    g_queue_free(pool->idle_connections);
    
    // Clean up active connections (destructor handles PooledConnection cleanup)
    g_hash_table_destroy(pool->active_connections);
    
    g_mutex_clear(&pool->mutex);
    g_free(pool);
}

/**
 * Get connection from pool (or return NULL if none available)
 */
GSocketConnection* connection_pool_get(ConnectionPool *pool, 
                                      const gchar *host, 
                                      guint16 port,
                                      gboolean is_ssl) {
    if (!pool || !host) return NULL;
    
    g_mutex_lock(&pool->mutex);
    pool->total_gets++;
    
    // Look for matching idle connection
    GList *link = pool->idle_connections->head;
    while (link) {
        PooledConnection *pc = (PooledConnection *)link->data;
        GList *next = link->next;
        
        if (strcmp(pc->host, host) == 0 && 
            pc->port == port && 
            pc->is_ssl == is_ssl) {
            
            // Validate connection health
            if (connection_is_healthy(pc->connection)) {
                // Remove from idle queue
                g_queue_delete_link(pool->idle_connections, link);
                
                // Add to active table
                g_hash_table_insert(pool->active_connections, 
                                   pc->connection, pc);
                
                pool->cache_hits++;
                pc->requests_served++;
                
                g_mutex_unlock(&pool->mutex);
                g_info("Pool HIT: Reusing connection to %s:%d (served %lu requests)", 
                       host, port, pc->requests_served);
                return pc->connection;
            } else {
                // Connection is dead, remove it
                g_info("Pool: Removing dead connection to %s:%d", host, port);
                g_queue_delete_link(pool->idle_connections, link);
                pooled_connection_free(pc);
                pool->connections_closed++;
            }
        }
        
        link = next;
    }
    
    // No matching connection found
    pool->cache_misses++;
    g_mutex_unlock(&pool->mutex);
    
    g_debug("Pool MISS: No connection available for %s:%d (hit rate: %.2f%%)",
            host, port, 
            pool->total_gets > 0 ? (pool->cache_hits * 100.0 / pool->total_gets) : 0.0);
    
    return NULL;
}

/**
 * Release connection back to pool
 */
void connection_pool_release(ConnectionPool *pool, 
                            GSocketConnection *connection,
                            const gchar *host,
                            guint16 port,
                            gboolean is_ssl) {
    if (!pool || !connection || !host) return;
    
    g_mutex_lock(&pool->mutex);
    
    // Lookup and STEAL (don't destroy) from active table
    PooledConnection *pc = g_hash_table_lookup(pool->active_connections, connection);
    
    if (!pc) {
        // This connection wasn't from the pool - just close it
        g_warning("Attempted to release connection to %s:%d not from pool", host, port);
        g_mutex_unlock(&pool->mutex);
        g_object_unref(connection);
        pool->connections_closed++;
        return;
    }
    
    // Remove from active WITHOUT destroying
    g_hash_table_steal(pool->active_connections, connection);
    
    // Validate connection is still healthy
    if (!connection_is_healthy(connection)) {
        g_info("Pool: Connection to %s:%d unhealthy on release, closing", host, port);
        pooled_connection_free(pc);
        pool->connections_closed++;
        g_mutex_unlock(&pool->mutex);
        return;
    }
    
    // Check global pool limit
    if (pool->idle_connections->length >= (guint)pool->max_total_idle) {
        g_info("Pool: Global limit reached (%d), closing connection to %s:%d", 
               pool->max_total_idle, host, port);
        pooled_connection_free(pc);
        pool->connections_closed++;
        g_mutex_unlock(&pool->mutex);
        return;
    }
    
    // Reuse existing PooledConnection, just update timestamp
    pc->last_used = g_get_monotonic_time();
    
    // Add to idle queue
    g_queue_push_tail(pool->idle_connections, pc);
    
    g_debug("Pool: Released connection to %s:%d (idle queue: %u)", 
            host, port, g_queue_get_length(pool->idle_connections));
    
    g_mutex_unlock(&pool->mutex);
}

/**
 * Register a new connection with the pool
 * Used when creating a brand new connection that should be tracked
 */
gboolean connection_pool_register(ConnectionPool *pool,
                                  GSocketConnection *connection,
                                  const gchar *host,
                                  guint16 port,
                                  gboolean is_ssl) {
    if (!pool || !connection || !host) return FALSE;
    
    g_mutex_lock(&pool->mutex);
    
    // Create new PooledConnection
    PooledConnection *pc = g_new0(PooledConnection, 1);
    pc->connection = g_object_ref(connection);
    pc->host = g_strdup(host);
    pc->port = port;
    pc->is_ssl = is_ssl;
    pc->last_used = g_get_monotonic_time();
    pc->requests_served = 0;
    
    // Add to active table
    g_hash_table_insert(pool->active_connections, connection, pc);
    pool->connections_created++;
    
    g_debug("Pool: Registered new connection to %s:%d", host, port);
    
    g_mutex_unlock(&pool->mutex);
    return TRUE;
}

/**
 * Periodic cleanup of idle connections
 */
static gboolean cleanup_idle_connections(gpointer user_data) {
    ConnectionPool *pool = (ConnectionPool *)user_data;
    gint64 now = g_get_monotonic_time();
    gint64 timeout_usec = pool->idle_timeout * G_TIME_SPAN_SECOND;
    
    g_mutex_lock(&pool->mutex);
    
    guint cleaned = 0;
    GList *link = pool->idle_connections->head;
    
    while (link) {
        PooledConnection *pc = (PooledConnection *)link->data;
        GList *next = link->next;
        
        gboolean should_remove = FALSE;
        
        // Check timeout
        if (now - pc->last_used > timeout_usec) {
            g_debug("Pool: Connection to %s:%d expired (idle for %ld seconds)",
                   pc->host, pc->port, 
                   (now - pc->last_used) / G_TIME_SPAN_SECOND);
            should_remove = TRUE;
        }
        // Also check health
        else if (!connection_is_healthy(pc->connection)) {
            g_debug("Pool: Connection to %s:%d became unhealthy", 
                   pc->host, pc->port);
            should_remove = TRUE;
        }
        
        if (should_remove) {
            g_queue_delete_link(pool->idle_connections, link);
            pooled_connection_free(pc);
            pool->connections_closed++;
            cleaned++;
        }
        
        link = next;
    }
    
    if (cleaned > 0) {
        g_info("Pool: Cleaned %u idle connections (%u remaining, hit rate: %.2f%%)",
               cleaned, g_queue_get_length(pool->idle_connections),
               pool->total_gets > 0 ? (pool->cache_hits * 100.0 / pool->total_gets) : 0.0);
    }
    
    g_mutex_unlock(&pool->mutex);
    return G_SOURCE_CONTINUE;
}

/**
 * Get pool statistics
 */
void connection_pool_get_stats(ConnectionPool *pool,
                              guint *idle_count,
                              guint *active_count,
                              guint64 *total_gets,
                              guint64 *cache_hits,
                              gdouble *hit_rate) {
    if (!pool) return;
    
    g_mutex_lock(&pool->mutex);
    
    if (idle_count) *idle_count = g_queue_get_length(pool->idle_connections);
    if (active_count) *active_count = g_hash_table_size(pool->active_connections);
    if (total_gets) *total_gets = pool->total_gets;
    if (cache_hits) *cache_hits = pool->cache_hits;
    if (hit_rate) {
        *hit_rate = pool->total_gets > 0 
                   ? (pool->cache_hits * 100.0 / pool->total_gets) 
                   : 0.0;
    }
    
    g_mutex_unlock(&pool->mutex);
}
