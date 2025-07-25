/**
 * Deadlight Proxy v4.0 - Plugin System
 *
 * Dynamic plugin loading and management
 */

#include <glib.h>
#include <gio/gio.h>
#include <gmodule.h>

#include "deadlight.h"

// Plugin manager structure
struct _DeadlightPluginManager {
    GHashTable *plugins;        // Loaded plugins
    gchar *plugin_dir;          // Plugin directory
    gboolean initialized;
};

/**
 * Initialize plugin system
 */
gboolean deadlight_plugins_init(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
    
    g_info("Initializing plugin system...");
    
    // Create plugin manager
    context->plugins = g_new0(DeadlightPluginManager, 1);
    context->plugins->plugins = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                    g_free, NULL);
    
    // Get plugin directory
    context->plugins->plugin_dir = deadlight_config_get_string(context, "plugins",
                                                             "plugin_dir",
                                                             "/usr/lib/deadlight/plugins");
    
    // Check if plugins are enabled
    if (!deadlight_config_get_bool(context, "plugins", "enabled", TRUE)) {
        g_info("Plugin system disabled by configuration");
        context->plugins->initialized = TRUE;
        return TRUE;
    }
    
    // TODO: Load plugins from directory
    
    context->plugins->initialized = TRUE;
    g_info("Plugin system initialized");
    
    return TRUE;
}

/**
 * Cleanup plugin system
 */
void deadlight_plugins_cleanup(DeadlightContext *context) {
    g_return_if_fail(context != NULL);
    
    g_info("Cleaning up plugin system...");
    
    if (context->plugins) {
        if (context->plugins->plugins) {
            // TODO: Unload all plugins
            g_hash_table_destroy(context->plugins->plugins);
        }
        
        g_free(context->plugins->plugin_dir);
        g_free(context->plugins);
        context->plugins = NULL;
    }
}

/**
 * Get plugin count
 */
gint deadlight_plugins_count(DeadlightContext *context) {
    g_return_val_if_fail(context != NULL, 0);
    g_return_val_if_fail(context->plugins != NULL, 0);
    
    return g_hash_table_size(context->plugins->plugins);
}

/**
 * Register a plugin
 */
gboolean deadlight_plugin_register(DeadlightContext *context, DeadlightPlugin *plugin) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(context->plugins != NULL, FALSE);
    g_return_val_if_fail(plugin != NULL, FALSE);
    g_return_val_if_fail(plugin->name != NULL, FALSE);
    
    // Check if plugin already exists
    if (g_hash_table_contains(context->plugins->plugins, plugin->name)) {
        g_warning("Plugin %s already registered", plugin->name);
        return FALSE;
    }
    
    // Initialize plugin
    if (plugin->init && !plugin->init(context)) {
        g_warning("Plugin %s initialization failed", plugin->name);
        return FALSE;
    }
    
    // Add to plugin table
    g_hash_table_insert(context->plugins->plugins, 
                       g_strdup(plugin->name), plugin);
    
    g_info("Plugin %s registered successfully", plugin->name);
    return TRUE;
}

/**
 * Unregister a plugin
 */
gboolean deadlight_plugin_unregister(DeadlightContext *context, const gchar *name) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(context->plugins != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);
    
    DeadlightPlugin *plugin = g_hash_table_lookup(context->plugins->plugins, name);
    if (!plugin) {
        g_warning("Plugin %s not found", name);
        return FALSE;
    }
    
    // Cleanup plugin
    if (plugin->cleanup) {
        plugin->cleanup(context);
    }
    
    // Remove from table
    g_hash_table_remove(context->plugins->plugins, name);
    
    g_info("Plugin %s unregistered", name);
    return TRUE;
}

/**
 * Find a plugin by name
 */
DeadlightPlugin *deadlight_plugin_find(DeadlightContext *context, const gchar *name) {
    g_return_val_if_fail(context != NULL, NULL);
    g_return_val_if_fail(context->plugins != NULL, NULL);
    g_return_val_if_fail(name != NULL, NULL);
    
    return g_hash_table_lookup(context->plugins->plugins, name);
}