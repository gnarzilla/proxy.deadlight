/**
 * Deadlight Proxy v4.0 - Context Management
 *
 * Core context creation and lifecycle management
 */

#include <glib.h>
#include <stdlib.h>
#include "deadlight.h"

/**
 * Create new Deadlight context
 */
DeadlightContext *deadlight_context_new(void) {
    DeadlightContext *ctx = g_new0(DeadlightContext, 1);
    
    // Initialize hash tables
    ctx->certificates = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    
    // Initialize plugin data storage
    ctx->plugins_data = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    
    // Initialize statistics
    ctx->total_connections = 0;
    ctx->active_connections = 0;
    ctx->bytes_transferred = 0;
    ctx->uptime_timer = g_timer_new();
    
    g_mutex_init(&ctx->stats_mutex);

    // Set defaults
    ctx->shutdown_requested = FALSE;
    
    return ctx;
}
/**
 * Free Deadlight context
 */
void deadlight_context_free(DeadlightContext *ctx) {
    if (!ctx) return;
    
    // Stop main loop if running
    if (ctx->main_loop) {
        if (g_main_loop_is_running(ctx->main_loop)) {
            g_main_loop_quit(ctx->main_loop);
        }
        g_main_loop_unref(ctx->main_loop);
    }
    
    // Clean up connections
    if (ctx->connections) {
        g_hash_table_destroy(ctx->connections);
    }
    
    // Clean up certificates
    if (ctx->certificates) {
        g_hash_table_destroy(ctx->certificates);
    }

    // Clean up plugin data
    if (ctx->plugins_data) {
        g_hash_table_destroy(ctx->plugins_data);
    }
    
    // Stop worker pool
    if (ctx->worker_pool) {
        g_thread_pool_free(ctx->worker_pool, TRUE, TRUE);
    }
    
    // Stop uptime timer
    if (ctx->uptime_timer) {
        g_timer_destroy(ctx->uptime_timer);
    }

    g_mutex_clear(&ctx->stats_mutex);
    
    // Free cached strings
    g_free(ctx->listen_address);
    
    // Free managers (these should have their own cleanup)
    g_free(ctx->network);
    g_free(ctx->ssl);
    g_free(ctx->plugins);
    
    // Free config
    if (ctx->config) {
        if (ctx->config->file_monitor) {
            g_file_monitor_cancel(ctx->config->file_monitor);
            g_object_unref(ctx->config->file_monitor);
        }
        if (ctx->config->keyfile) {
            g_key_file_free(ctx->config->keyfile);
        }
        if (ctx->config->string_cache) {
            g_hash_table_destroy(ctx->config->string_cache);
        }
        if (ctx->config->int_cache) {
            g_hash_table_destroy(ctx->config->int_cache);
        }
        if (ctx->config->bool_cache) {
            g_hash_table_destroy(ctx->config->bool_cache);
        }
        g_free(ctx->config->config_path);
        g_free(ctx->config);
    }
    
    g_free(ctx);
}