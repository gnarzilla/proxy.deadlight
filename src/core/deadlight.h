/**
 * Deadlight Proxy v4.0 - Main Header File
 * 
 * Public API definitions for the modular proxy system
 */

#ifndef DEADLIGHT_H
#define DEADLIGHT_H

#include <glib.h>
#include <gio/gio.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

// Version information
#define DEADLIGHT_VERSION_MAJOR 4
#define DEADLIGHT_VERSION_MINOR 0
#define DEADLIGHT_VERSION_PATCH 0
#define DEADLIGHT_VERSION_STRING "4.0.0"

// Default configuration
#define DEADLIGHT_DEFAULT_PORT 8080
#define DEADLIGHT_DEFAULT_CONFIG_FILE "/etc/deadlight/deadlight.conf"
#define DEADLIGHT_DEFAULT_LOG_LEVEL "info"
#define DEADLIGHT_DEFAULT_MAX_CONNECTIONS 500

// Protocol types
typedef enum {
    DEADLIGHT_PROTOCOL_UNKNOWN = 0,
    DEADLIGHT_PROTOCOL_HTTP,
    DEADLIGHT_PROTOCOL_HTTPS,
    DEADLIGHT_PROTOCOL_SOCKS4,
    DEADLIGHT_PROTOCOL_SOCKS5,
    DEADLIGHT_PROTOCOL_CONNECT,
    DEADLIGHT_PROTOCOL_WEBSOCKET
} DeadlightProtocol;

// Connection states
typedef enum {
    DEADLIGHT_STATE_INIT = 0,
    DEADLIGHT_STATE_DETECTING,
    DEADLIGHT_STATE_CONNECTING,
    DEADLIGHT_STATE_CONNECTED,
    DEADLIGHT_STATE_TUNNELING,
    DEADLIGHT_STATE_CLOSING,
    DEADLIGHT_STATE_CLOSED
} DeadlightConnectionState;

// Log levels
typedef enum {
    DEADLIGHT_LOG_ERROR = 0,
    DEADLIGHT_LOG_WARNING,
    DEADLIGHT_LOG_INFO,
    DEADLIGHT_LOG_DEBUG
} DeadlightLogLevel;

// Forward declarations
typedef struct _DeadlightContext DeadlightContext;
typedef struct _DeadlightConnection DeadlightConnection;
typedef struct _DeadlightPlugin DeadlightPlugin;
typedef struct _DeadlightRequest DeadlightRequest;
typedef struct _DeadlightResponse DeadlightResponse;
typedef struct _DeadlightConfig DeadlightConfig;
typedef struct _DeadlightNetworkManager DeadlightNetworkManager;
typedef struct _DeadlightSSLManager DeadlightSSLManager;
typedef struct _DeadlightPluginManager DeadlightPluginManager;

// Main context structure
struct _DeadlightContext {
    // Core components
    GMainLoop *main_loop;
    DeadlightConfig *config;
    DeadlightNetworkManager *network;
    DeadlightSSLManager *ssl;
    DeadlightPluginManager *plugins;
    
    // Runtime state
    GHashTable *connections;        // Active connections
    GHashTable *certificates;       // SSL certificate cache
    GThreadPool *worker_pool;       // Worker thread pool
    
    // Statistics
    guint64 total_connections;
    guint64 active_connections;
    guint64 bytes_transferred;
    GTimer *uptime_timer;
    
    // Configuration cache (for performance)
    gint listen_port;
    gchar *listen_address;
    gint max_connections;
    DeadlightLogLevel log_level;
    gboolean ssl_intercept_enabled;
    
    // Shutdown flag
    gboolean shutdown_requested;
};

// Configuration structure
struct _DeadlightConfig {
    GKeyFile *keyfile;
    gchar *config_path;
    GFileMonitor *file_monitor;
    
    // Cached values
    GHashTable *string_cache;
    GHashTable *int_cache;
    GHashTable *bool_cache;
};

// Connection structure
struct _DeadlightConnection {
    // Unique identifier
    guint64 id;
    
    // Network details
    GSocketConnection *client_connection;
    GSocketConnection *upstream_connection;
    gchar *client_address;
    gchar *target_host;
    gint target_port;
    
    // Protocol information
    DeadlightProtocol protocol;
    DeadlightConnectionState state;
    
    // SSL/TLS
    GTlsConnection *client_tls;
    GTlsConnection *upstream_tls;
    gboolean ssl_established;
    
    // Buffering
    GByteArray *client_buffer;
    GByteArray *upstream_buffer;
    
    // Statistics
    guint64 bytes_client_to_upstream;
    guint64 bytes_upstream_to_client;
    GTimer *connection_timer;
    
    // Plugin support
    GHashTable *plugin_data;
    
    // Request/response tracking
    DeadlightRequest *current_request;
    DeadlightResponse *current_response;
    
    // Context reference
    DeadlightContext *context;
};

// HTTP Request structure
struct _DeadlightRequest {
    // HTTP basics
    gchar *method;
    gchar *uri;
    gchar *version;
    GHashTable *headers;
    GByteArray *body;
    
    // Parsed details
    gchar *host;
    gint port;
    gchar *path;
    gchar *query;
    
    // Connection reference
    DeadlightConnection *connection;
    
    // Plugin modifications
    gboolean modified;
    gboolean blocked;
    gchar *block_reason;
};

// HTTP Response structure
struct _DeadlightResponse {
    // HTTP basics
    gchar *version;
    gint status_code;
    gchar *reason_phrase;
    GHashTable *headers;
    GByteArray *body;
    
    // Connection reference
    DeadlightConnection *connection;
    
    // Plugin modifications
    gboolean modified;
    gboolean blocked;
    gchar *block_reason;
};

// Plugin structure
struct _DeadlightPlugin {
    // Plugin metadata
    gchar *name;
    gchar *version;
    gchar *description;
    gchar *author;
    
    // Plugin lifecycle
    gboolean (*init)(DeadlightContext *context);
    void (*cleanup)(DeadlightContext *context);
    
    // Protocol hooks
    gboolean (*on_connection_accept)(DeadlightConnection *conn);
    gboolean (*on_protocol_detect)(DeadlightConnection *conn, DeadlightProtocol proto);
    gboolean (*on_request_headers)(DeadlightRequest *request);
    gboolean (*on_request_body)(DeadlightRequest *request);
    gboolean (*on_response_headers)(DeadlightResponse *response);
    gboolean (*on_response_body)(DeadlightResponse *response);
    gboolean (*on_connection_close)(DeadlightConnection *conn);
    
    // Configuration hook
    gboolean (*on_config_change)(DeadlightContext *context, const gchar *section, const gchar *key);
    
    // Plugin-specific data
    gpointer private_data;
    
    // Reference count
    gint ref_count;
};

// Core API - Context management
DeadlightContext *deadlight_context_new(void);
void deadlight_context_free(DeadlightContext *context);

// Core API - Configuration
gboolean deadlight_config_load(DeadlightContext *context, const gchar *config_file, GError **error);
gboolean deadlight_config_save(DeadlightContext *context, GError **error);
gint deadlight_config_get_int(DeadlightContext *context, const gchar *section, const gchar *key, gint default_value);
gchar *deadlight_config_get_string(DeadlightContext *context, const gchar *section, const gchar *key, const gchar *default_value);
gboolean deadlight_config_get_bool(DeadlightContext *context, const gchar *section, const gchar *key, gboolean default_value);
void deadlight_config_set_int(DeadlightContext *context, const gchar *section, const gchar *key, gint value);
void deadlight_config_set_string(DeadlightContext *context, const gchar *section, const gchar *key, const gchar *value);
void deadlight_config_set_bool(DeadlightContext *context, const gchar *section, const gchar *key, gboolean value);

// Core API - Logging
void deadlight_log_handler(const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data);
gboolean deadlight_logging_init(DeadlightContext *context, GError **error);
void deadlight_logging_cleanup(DeadlightContext *context);

// Network API
gboolean deadlight_network_init(DeadlightContext *context, GError **error);
gboolean deadlight_network_start_listener(DeadlightContext *context, gint port, GError **error);
void deadlight_network_stop(DeadlightContext *context);
DeadlightConnection *deadlight_connection_new(DeadlightContext *context, GSocketConnection *client_connection);
// Add this to deadlight.h after deadlight_connection_free
gboolean deadlight_network_connect_upstream(DeadlightConnection *conn, 
                                          const gchar *host, 
                                          guint16 port,
                                          GError **error);
gboolean deadlight_network_tunnel_data(DeadlightConnection *conn, GError **error);

// Protocol API
DeadlightProtocol deadlight_protocol_detect(const guint8 *data, gsize length);
gboolean deadlight_protocol_handle_request(DeadlightConnection *connection, GError **error);
gboolean deadlight_protocol_handle_response(DeadlightConnection *connection, GError **error);

// SSL API
gboolean deadlight_ssl_init(DeadlightContext *context, GError **error);
void deadlight_ssl_cleanup(DeadlightContext *context);
gboolean deadlight_ssl_intercept_connection(DeadlightConnection *connection, GError **error);
gboolean deadlight_ssl_create_ca_certificate(const gchar *cert_file, const gchar *key_file, GError **error);

// Plugin API
gboolean deadlight_plugins_init(DeadlightContext *context, GError **error);
void deadlight_plugins_cleanup(DeadlightContext *context);
gboolean deadlight_plugin_register(DeadlightContext *context, DeadlightPlugin *plugin);
gboolean deadlight_plugin_unregister(DeadlightContext *context, const gchar *name);
DeadlightPlugin *deadlight_plugin_find(DeadlightContext *context, const gchar *name);
gint deadlight_plugins_count(DeadlightContext *context);

// Request/Response API
DeadlightRequest *deadlight_request_new(DeadlightConnection *connection);
void deadlight_request_free(DeadlightRequest *request);
gboolean deadlight_request_parse_headers(DeadlightRequest *request, const gchar *data, gsize length);
gchar *deadlight_request_get_header(DeadlightRequest *request, const gchar *name);
void deadlight_request_set_header(DeadlightRequest *request, const gchar *name, const gchar *value);

DeadlightResponse *deadlight_response_new(DeadlightConnection *connection);
void deadlight_response_free(DeadlightResponse *response);
gboolean deadlight_response_parse_headers(DeadlightResponse *response, const gchar *data, gsize length);
gchar *deadlight_response_get_header(DeadlightResponse *response, const gchar *name);
void deadlight_response_set_header(DeadlightResponse *response, const gchar *name, const gchar *value);

// Testing API
gboolean deadlight_test_module(const gchar *module_name);

// Utility functions
const gchar *deadlight_protocol_to_string(DeadlightProtocol protocol);
const gchar *deadlight_state_to_string(DeadlightConnectionState state);
gchar *deadlight_format_bytes(guint64 bytes);
gchar *deadlight_format_duration(gdouble seconds);

// Built-in plugins
DeadlightPlugin *deadlight_plugin_adblocker_new(void);
DeadlightPlugin *deadlight_plugin_logger_new(void);
DeadlightPlugin *deadlight_plugin_stats_new(void);
DeadlightPlugin *deadlight_plugin_auth_new(void);

#ifdef __cplusplus
}
#endif

#endif // DEADLIGHT_H
