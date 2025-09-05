/**
 * Deadlight Proxy v4.0 - Main Header File
 */
#ifndef DEADLIGHT_H
#define DEADLIGHT_H

#include <glib.h>
#include <gio/gio.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

//===[ MACROS AND DEFINES (RESTORED) ]===
#define DEADLIGHT_VERSION_MAJOR 4
#define DEADLIGHT_VERSION_MINOR 0
#define DEADLIGHT_VERSION_PATCH 0
#define DEADLIGHT_VERSION_STRING "4.0.0"

#define DEADLIGHT_DEFAULT_PORT 8080
#define DEADLIGHT_DEFAULT_CONFIG_FILE "/etc/deadlight/deadlight.conf"
#define DEADLIGHT_DEFAULT_LOG_LEVEL "info"
#define DEADLIGHT_DEFAULT_MAX_CONNECTIONS 500

//===[ ENUMS ]===
typedef enum {
    DEADLIGHT_PROTOCOL_UNKNOWN = 0, DEADLIGHT_PROTOCOL_HTTP, DEADLIGHT_PROTOCOL_HTTPS,
    DEADLIGHT_PROTOCOL_SOCKS, DEADLIGHT_PROTOCOL_CONNECT,
    DEADLIGHT_PROTOCOL_WEBSOCKET, DEADLIGHT_PROTOCOL_IMAP,
    DEADLIGHT_PROTOCOL_IMAPS, DEADLIGHT_PROTOCOL_SMTP, DEADLIGHT_PROTOCOL_API
} DeadlightProtocol;

typedef enum {
    DEADLIGHT_STATE_INIT = 0, DEADLIGHT_STATE_DETECTING, DEADLIGHT_STATE_CONNECTING,
    DEADLIGHT_STATE_CONNECTED, DEADLIGHT_STATE_TUNNELING, DEADLIGHT_STATE_CLOSING,
    DEADLIGHT_STATE_CLOSED
} DeadlightConnectionState;

typedef enum {
    DEADLIGHT_LOG_ERROR = 0, DEADLIGHT_LOG_WARNING, DEADLIGHT_LOG_INFO, DEADLIGHT_LOG_DEBUG
} DeadlightLogLevel;

typedef enum {
    HANDLER_ERROR = 0,               // The handler failed. The caller MUST clean up.
    HANDLER_SUCCESS_CLEANUP_NOW = 1, // The handler finished synchronously. The caller MUST clean up.
    HANDLER_SUCCESS_ASYNC = 2        // The handler started an async process. The caller MUST NOT clean up.
} DeadlightHandlerResult;

//===[ FORWARD DECLARATIONS ]===
typedef struct _DeadlightContext DeadlightContext;
typedef struct _DeadlightConnection DeadlightConnection;
typedef struct _DeadlightPlugin DeadlightPlugin;
typedef struct _DeadlightRequest DeadlightRequest;
typedef struct _DeadlightResponse DeadlightResponse;
typedef struct _DeadlightConfig DeadlightConfig;
typedef struct _DeadlightNetworkManager DeadlightNetworkManager;
typedef struct _DeadlightSSLManager DeadlightSSLManager;
typedef struct _DeadlightPluginManager DeadlightPluginManager;
typedef struct _ConnectionPool ConnectionPool;

//===[ PROTOCOL HANDLER DEFINITION ]===
typedef struct _DeadlightProtocolHandler {
    const gchar *name;
    DeadlightProtocol protocol_id;
    gsize (*detect)(const guint8 *initial_data, gsize len);
    DeadlightHandlerResult (*handle)(DeadlightConnection *conn, GError **error);
    void (*cleanup)(DeadlightConnection *conn);
} DeadlightProtocolHandler;


//===[ STRUCT DEFINITIONS ]===
struct _DeadlightConfig {
    GKeyFile *keyfile;
    gchar *config_path;
    GFileMonitor *file_monitor;
    GHashTable *string_cache;
    GHashTable *int_cache;
    GHashTable *bool_cache;
};

struct _DeadlightContext {
    GMainLoop *main_loop;
    DeadlightConfig *config;
    DeadlightNetworkManager *network;
    DeadlightSSLManager *ssl;
    DeadlightPluginManager *plugins;
    GHashTable *plugins_data;
    GHashTable *connections;
    GHashTable *certificates;
    GThreadPool *worker_pool;
    guint64 total_connections;
    guint64 active_connections;
    guint64 bytes_transferred;
    GTimer *uptime_timer;
    gint listen_port;
    gchar *listen_address;
    guint max_connections;
    DeadlightLogLevel log_level;
    gboolean ssl_intercept_enabled;
    ConnectionPool *conn_pool;
    gchar *auth_endpoint;
    gchar *auth_secret;
    gboolean shutdown_requested;
};

struct _DeadlightConnection {
    guint64 id;
    GSocketConnection *client_connection;
    GSocketConnection *upstream_connection;
    gchar *client_address;
    gchar *target_host;
    gint target_port;
    gchar *username;
    gchar *session_token;
    gboolean authenticated;
    DeadlightProtocol protocol;
    DeadlightConnectionState state;
    const DeadlightProtocolHandler *handler;
    gpointer protocol_data;
    GTlsConnection *client_tls;
    GTlsConnection *upstream_tls;
    gboolean ssl_established;
    SSL *client_ssl;
    SSL *upstream_ssl;
    SSL_CTX *ssl_ctx;
    GByteArray *client_buffer;
    GByteArray *upstream_buffer;
    guint64 bytes_client_to_upstream;
    guint64 bytes_upstream_to_client;
    GTimer *connection_timer;
    GHashTable *plugin_data;
    DeadlightRequest *current_request;
    DeadlightResponse *current_response;
    DeadlightContext *context;
    // Fields for tunneling (used by both plain and SSL tunnels)
    GIOChannel *client_channel;
    GIOChannel *upstream_channel;
    GTlsCertificate *upstream_peer_cert;
    gint client_fd;
    gint upstream_fd;
};

struct _DeadlightRequest {
    gchar *method;
    gchar *uri;
    gchar *version;
    GHashTable *headers;
    GByteArray *body;
    gchar *host;
    gint port;
    gchar *path;
    gchar *query;
    DeadlightConnection *connection;
    gboolean modified;
    gboolean blocked;
    gchar *block_reason;
};

struct _DeadlightResponse {
    gchar *version;
    gint status_code;
    gchar *reason_phrase;
    GHashTable *headers;
    GByteArray *body;
    DeadlightConnection *connection;
    gboolean modified;
    gboolean blocked;
    gchar *block_reason;
};

struct _DeadlightPlugin {
    gchar *name;
    gchar *version;
    gchar *description;
    gchar *author;
    gboolean (*init)(DeadlightContext *context);
    void (*cleanup)(DeadlightContext *context);
    gboolean (*on_connection_accept)(DeadlightConnection *conn);
    gboolean (*on_protocol_detect)(DeadlightConnection *conn, DeadlightProtocol proto);
    gboolean (*on_request_headers)(DeadlightRequest *request);
    gboolean (*on_request_body)(DeadlightRequest *request);
    gboolean (*on_response_headers)(DeadlightResponse *response);
    gboolean (*on_response_body)(DeadlightResponse *response);
    gboolean (*on_connection_close)(DeadlightConnection *conn);
    gboolean (*on_config_change)(DeadlightContext *context, const gchar *section, const gchar *key);
    gpointer private_data;
    gint ref_count;
};


//===[ API FUNCTION PROTOTYPES ]===

// Context API
DeadlightContext *deadlight_context_new(void);
void deadlight_context_free(DeadlightContext *context);

// Config API
gboolean deadlight_config_load(DeadlightContext *context, const gchar *config_file, GError **error);
gboolean deadlight_config_save(DeadlightContext *context, GError **error);
gint deadlight_config_get_int(DeadlightContext *context, const gchar *section, const gchar *key, gint default_value);
gchar *deadlight_config_get_string(DeadlightContext *context, const gchar *section, const gchar *key, const gchar *default_value);
gboolean deadlight_config_get_bool(DeadlightContext *context, const gchar *section, const gchar *key, gboolean default_value);
void deadlight_config_set_int(DeadlightContext *context, const gchar *section, const gchar *key, gint value);
void deadlight_config_set_string(DeadlightContext *context, const gchar *section, const gchar *key, const gchar *value);
void deadlight_config_set_bool(DeadlightContext *context, const gchar *section, const gchar *key, gboolean value);

// Logging API
void deadlight_log_handler(const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data);
gboolean deadlight_logging_init(DeadlightContext *context, GError **error);
void deadlight_logging_cleanup(DeadlightContext *context);

// Network API
gboolean deadlight_network_init(DeadlightContext *context, GError **error);
gboolean deadlight_network_start_listener(DeadlightContext *context, gint port, GError **error);
void deadlight_network_stop(DeadlightContext *context);
DeadlightConnection *deadlight_connection_new(DeadlightContext *context, GSocketConnection *client_connection);
gboolean deadlight_network_connect_upstream(DeadlightConnection *conn, const gchar *host, guint16 port, GError **error);
gboolean deadlight_network_tunnel_data(DeadlightConnection *conn, GError **error);
gboolean deadlight_tls_tunnel_data(DeadlightConnection *conn, GError **error);

// Protocol API
gboolean deadlight_protocol_handle_response(DeadlightConnection *connection, GError **error);
void deadlight_protocols_init(DeadlightContext *context);
void deadlight_protocol_register(const DeadlightProtocolHandler *handler); 
const DeadlightProtocolHandler* deadlight_protocol_detect_and_assign(DeadlightConnection *conn, const guint8 *data, gsize length);

// SSL API
gboolean deadlight_ssl_init(DeadlightContext *context, GError **error);
void deadlight_ssl_cleanup(DeadlightContext *context);
gboolean deadlight_ssl_intercept_connection(DeadlightConnection *connection, GError **error);
gboolean deadlight_ssl_tunnel_data(DeadlightConnection *conn, GError **error);
gboolean deadlight_network_establish_upstream_ssl(DeadlightConnection *conn, GError **error);
gboolean deadlight_ssl_create_ca_certificate(const gchar *cert_file, const gchar *key_file, GError **error);
gboolean deadlight_ssl_load_ca_certificate(DeadlightSSLManager *ssl_mgr, GError **error);
gboolean deadlight_ssl_generate_host_certificate(DeadlightSSLManager *ssl_mgr, const gchar *hostname, X509 **out_cert, EVP_PKEY **out_key, GError **error);

// Plugin API
gboolean deadlight_plugins_init(DeadlightContext *context, GError **error);
void deadlight_plugins_cleanup(DeadlightContext *context);
gint deadlight_plugins_count(DeadlightContext *context);
gboolean deadlight_plugins_call_on_connection_accept(DeadlightContext *context, DeadlightConnection *conn);
gboolean deadlight_plugins_call_on_protocol_detect(DeadlightContext *context, DeadlightConnection *conn);
gboolean deadlight_plugins_call_on_request_headers(DeadlightContext *context, DeadlightRequest *request);
gboolean deadlight_plugins_call_on_request_body(DeadlightContext *context, DeadlightRequest *request);
gboolean deadlight_plugins_call_on_response_headers(DeadlightContext *context, DeadlightResponse *response);
gboolean deadlight_plugins_call_on_response_body(DeadlightContext *context, DeadlightResponse *response);
gboolean deadlight_plugins_call_on_connection_close(DeadlightContext *context, DeadlightConnection *conn);
void deadlight_plugins_call_on_config_change(DeadlightContext *context, const gchar *section, const gchar *key);

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

// Connection Pool API
ConnectionPool* connection_pool_new(gint max_per_host, gint idle_timeout);
void connection_pool_free(ConnectionPool *pool);
GSocketConnection* connection_pool_get(ConnectionPool *pool, const gchar *host, guint16 port, gboolean is_ssl);
void connection_pool_release(ConnectionPool *pool, GSocketConnection *connection, const gchar *host, guint16 port, gboolean is_ssl);

// Testing API
gboolean deadlight_test_module(const gchar *module_name);

// Utility API
const gchar *deadlight_protocol_to_string(DeadlightProtocol protocol);
gchar *deadlight_format_bytes(guint64 bytes); // Restored

#ifdef __cplusplus
}
#endif
#endif // DEADLIGHT_H
