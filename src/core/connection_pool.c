/**
 * Deadlight Proxy v4.0 - Connection Pool Implementation
 */

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include "deadlight.h"

static gboolean cleanup_idle_connections(gpointer user_data);

ConnectionPool* connection_pool_new(gint max_per_host, gint idle_timeout) {
    ConnectionPool *pool = g_new0(ConnectionPool, 1);
    pool->idle_connections = g_queue_new();
    pool->active_connections = g_hash_table_new(g_direct_hash, g_direct_equal);
    g_mutex_init(&pool->mutex);
    pool->max_per_host = max_per_host;
    pool->idle_timeout = idle_timeout;
    
    // Start cleanup timer
    pool->cleanup_source_id = g_timeout_add_seconds(30, cleanup_idle_connections, pool);
    
    return pool;
}

void connection_pool_free(ConnectionPool *pool) {
    if (!pool) return;
    
    // Cancel cleanup timer
    if (pool->cleanup_source_id) {
        g_source_remove(pool->cleanup_source_id);
    }
    
    // Clean up idle connections
    PooledConnection *pc;
    while ((pc = g_queue_pop_head(pool->idle_connections))) {
        g_object_unref(pc->connection);
        g_free(pc->host);
        g_free(pc);
    }
    g_queue_free(pool->idle_connections);
    
    // Clean up active connections
    g_hash_table_destroy(pool->active_connections);
    
    g_mutex_clear(&pool->mutex);
    g_free(pool);
}

GSocketConnection* connection_pool_get(ConnectionPool *pool, 
                                      const gchar *host, 
                                      guint16 port,
                                      gboolean is_ssl) {
    g_mutex_lock(&pool->mutex);
    
    // Look for a matching idle connection
    GList *link = pool->idle_connections->head;
    while (link) {
        PooledConnection *pc = (PooledConnection *)link->data;
        if (strcmp(pc->host, host) == 0 && 
            pc->port == port && 
            pc->is_ssl == is_ssl) {
            
            // Check if still alive
            GSocket *socket = g_socket_connection_get_socket(pc->connection);
            if (g_socket_condition_check(socket, G_IO_ERR | G_IO_HUP) == 0) {
                // Remove from idle queue
                g_queue_delete_link(pool->idle_connections, link);
                
                // Add to active
                g_hash_table_insert(pool->active_connections, 
                                   pc->connection, pc);
                
                g_mutex_unlock(&pool->mutex);
                g_info("Reusing connection to %s:%d", host, port);
                return pc->connection;
            } else {
                // Connection is dead, remove it
                GList *next = link->next;
                g_queue_delete_link(pool->idle_connections, link);
                g_object_unref(pc->connection);
                g_free(pc->host);
                g_free(pc);
                link = next;
                continue;
            }
        }
        link = link->next;
    }
    
    g_mutex_unlock(&pool->mutex);
    return NULL;
}

void connection_pool_release(ConnectionPool *pool, 
                           GSocketConnection *connection,
                           const gchar *host,
                           guint16 port,
                           gboolean is_ssl) {
    g_mutex_lock(&pool->mutex);
    
    // Remove from active
    g_hash_table_remove(pool->active_connections, connection);
    
    // Create pooled connection
    PooledConnection *pc = g_new0(PooledConnection, 1);
    pc->connection = g_object_ref(connection);
    pc->host = g_strdup(host);
    pc->port = port;
    pc->is_ssl = is_ssl;
    pc->last_used = g_get_monotonic_time();
    
    // Add to idle queue
    g_queue_push_tail(pool->idle_connections, pc);
    
    g_mutex_unlock(&pool->mutex);
}

static gboolean cleanup_idle_connections(gpointer user_data) {
    ConnectionPool *pool = (ConnectionPool *)user_data;
    gint64 now = g_get_monotonic_time();
    gint64 timeout_usec = pool->idle_timeout * G_TIME_SPAN_SECOND;
    
    g_mutex_lock(&pool->mutex);
    
    GList *link = pool->idle_connections->head;
    while (link) {
        PooledConnection *pc = (PooledConnection *)link->data;
        GList *next = link->next;
        
        if (now - pc->last_used > timeout_usec) {
            // Connection expired
            g_queue_delete_link(pool->idle_connections, link);
            g_object_unref(pc->connection);
            g_free(pc->host);
            g_free(pc);
        }
        
        link = next;
    }
    
    g_mutex_unlock(&pool->mutex);
    return G_SOURCE_CONTINUE;
}
