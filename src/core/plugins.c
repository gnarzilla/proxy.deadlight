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

// Forward declarations
static gboolean load_plugin_from_file(DeadlightContext *context, const gchar *filepath, GError **error);
static gboolean load_plugins_from_directory(DeadlightContext *context, GError **error);
gboolean deadlight_plugin_register(DeadlightContext *context, DeadlightPlugin *plugin);

/**
 * Load a plugin from file
 */
static gboolean load_plugin_from_file(DeadlightContext *context, const gchar *filepath, GError **error) {
    GModule *module = NULL;
    DeadlightPlugin *plugin = NULL;
    gboolean (*get_plugin_info)(DeadlightPlugin **plugin);
    
    g_info("Loading plugin from %s", filepath);
    
    // Open the module
    module = g_module_open(filepath, G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);
    if (!module) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to load plugin %s: %s", filepath, g_module_error());
        return FALSE;
    }
    
    // Look for the plugin info function
    if (!g_module_symbol(module, "deadlight_plugin_get_info", (gpointer *)&get_plugin_info)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Plugin %s missing deadlight_plugin_get_info function", filepath);
        g_module_close(module);
        return FALSE;
    }
    
    // Get plugin information
    if (!get_plugin_info(&plugin) || !plugin) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to get plugin info from %s", filepath);
        g_module_close(module);
        return FALSE;
    }
    
    // Make module resident so it doesn't get unloaded
    g_module_make_resident(module);
    
    // Register the plugin
    if (!deadlight_plugin_register(context, plugin)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to register plugin %s", plugin->name);
        g_module_close(module);
        return FALSE;
    }
    
    g_info("Successfully loaded plugin: %s v%s by %s", 
           plugin->name, plugin->version, plugin->author);
    
    return TRUE;
}

/**
 * Load all plugins from directory
 */
static gboolean load_plugins_from_directory(DeadlightContext *context, GError **error) {
    GDir *dir;
    const gchar *filename;
    gchar *filepath;
    GError *local_error = NULL;
    gint loaded = 0;
    
    (void)error; // Suppress unused parameter warning
    
    g_info("Looking for plugins in: %s", context->plugins->plugin_dir);
    
    // Check if directory exists
    if (!g_file_test(context->plugins->plugin_dir, G_FILE_TEST_IS_DIR)) {
        g_warning("Plugin directory does not exist: %s", context->plugins->plugin_dir);
        return TRUE; // Not a fatal error
    }
    
    // Open directory
    dir = g_dir_open(context->plugins->plugin_dir, 0, &local_error);
    if (!dir) {
        g_warning("Failed to open plugin directory %s: %s",
                 context->plugins->plugin_dir, local_error->message);
        g_error_free(local_error);
        return TRUE; // Not a fatal error
    }
    
    // Iterate through files
    while ((filename = g_dir_read_name(dir)) != NULL) {
        // Only load .so files
        if (!g_str_has_suffix(filename, ".so")) {
            continue;
        }
        
        filepath = g_build_filename(context->plugins->plugin_dir, filename, NULL);
        
        // Load the plugin
        local_error = NULL;
        if (load_plugin_from_file(context, filepath, &local_error)) {
            loaded++;
        } else {
            g_warning("Failed to load plugin %s: %s", 
                     filename, local_error ? local_error->message : "Unknown error");
            if (local_error) {
                g_error_free(local_error);
            }
        }
        
        g_free(filepath);
    }
    
    g_dir_close(dir);
    g_info("Loaded %d plugins from %s", loaded, context->plugins->plugin_dir);
    
    return TRUE;
}

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
    
    // Load plugins from directory
    if (!load_plugins_from_directory(context, error)) {
        return FALSE;
    }
    
    context->plugins->initialized = TRUE;
    g_info("Plugin system initialized with %d plugins", deadlight_plugins_count(context));
    
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

gchar **deadlight_config_get_string_list(DeadlightContext *context, 
                                        const gchar *section, 
                                        const gchar *key, 
                                        gchar **default_value) {
    // Suppress unused parameter warnings
    (void)context;
    (void)section;
    (void)key;
    // Simple implementation - just return default for now
    return default_value;
}
