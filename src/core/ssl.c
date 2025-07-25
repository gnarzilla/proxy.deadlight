/**
 * Deadlight Proxy v4.0 - SSL/TLS Module
 *
 * SSL interception and certificate management
 */

#include <glib.h>
#include <gio/gio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "deadlight.h"

// SSL Manager structure
struct _DeadlightSSLManager {
    SSL_CTX *server_ctx;        // Context for server-side connections
    SSL_CTX *client_ctx;        // Context for client-side connections
    
    X509 *ca_cert;              // CA certificate for signing
    EVP_PKEY *ca_key;           // CA private key
    
    gchar *ca_cert_file;        // CA certificate file path
    gchar *ca_key_file;         // CA key file path
    gchar *cert_cache_dir;      // Generated certificates cache
    
    GMutex cert_mutex;          // Mutex for certificate generation
    GHashTable *cert_cache;     // Cache of generated certificates
    
    gboolean initialized;
};

// Forward declarations
static gboolean load_ca_certificate(DeadlightSSLManager *ssl_mgr, GError **error);
static SSL_CTX *create_ssl_context(gboolean is_server, GError **error);

/**
 * Initialize SSL module
 */
gboolean deadlight_ssl_init(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
    
    g_info("Initializing SSL module...");
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Create SSL manager
    context->ssl = g_new0(DeadlightSSLManager, 1);
    g_mutex_init(&context->ssl->cert_mutex);
    
    // Get configuration
    context->ssl->ca_cert_file = deadlight_config_get_string(context, "ssl", 
                                                           "ca_cert_file", 
                                                           "/etc/deadlight/ca.crt");
    context->ssl->ca_key_file = deadlight_config_get_string(context, "ssl", 
                                                          "ca_key_file", 
                                                          "/etc/deadlight/ca.key");
    context->ssl->cert_cache_dir = deadlight_config_get_string(context, "ssl", 
                                                             "cert_cache_dir", 
                                                             "/tmp/deadlight_certs");
    
    // Create certificate cache
    context->ssl->cert_cache = g_hash_table_new_full(g_str_hash, g_str_equal, 
                                                    g_free, NULL);
    
    // Create SSL contexts
    context->ssl->server_ctx = create_ssl_context(TRUE, error);
    if (!context->ssl->server_ctx) {
        return FALSE;
    }
    
    context->ssl->client_ctx = create_ssl_context(FALSE, error);
    if (!context->ssl->client_ctx) {
        SSL_CTX_free(context->ssl->server_ctx);
        return FALSE;
    }
    
    // Load CA certificate if SSL interception is enabled
    if (context->ssl_intercept_enabled) {
        if (!load_ca_certificate(context->ssl, error)) {
            SSL_CTX_free(context->ssl->server_ctx);
            SSL_CTX_free(context->ssl->client_ctx);
            return FALSE;
        }
        
        // Create cert cache directory
        if (g_mkdir_with_parents(context->ssl->cert_cache_dir, 0700) != 0) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "Failed to create certificate cache directory: %s",
                       context->ssl->cert_cache_dir);
            return FALSE;
        }
    }
    
    context->ssl->initialized = TRUE;
    g_info("SSL module initialized successfully");
    
    return TRUE;
}

/**
 * Cleanup SSL module
 */
void deadlight_ssl_cleanup(DeadlightContext *context) {
    g_return_if_fail(context != NULL);
    
    g_info("Cleaning up SSL module...");
    
    if (context->ssl) {
        if (context->ssl->server_ctx) {
            SSL_CTX_free(context->ssl->server_ctx);
        }
        
        if (context->ssl->client_ctx) {
            SSL_CTX_free(context->ssl->client_ctx);
        }
        
        if (context->ssl->ca_cert) {
            X509_free(context->ssl->ca_cert);
        }
        
        if (context->ssl->ca_key) {
            EVP_PKEY_free(context->ssl->ca_key);
        }
        
        if (context->ssl->cert_cache) {
            g_hash_table_destroy(context->ssl->cert_cache);
        }
        
        g_free(context->ssl->ca_cert_file);
        g_free(context->ssl->ca_key_file);
        g_free(context->ssl->cert_cache_dir);
        
        g_mutex_clear(&context->ssl->cert_mutex);
        g_free(context->ssl);
        context->ssl = NULL;
    }
    
    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
}

/**
 * Create SSL context
 */
static SSL_CTX *create_ssl_context(gboolean is_server, GError **error) {
    const SSL_METHOD *method = is_server ? TLS_server_method() : TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to create SSL context: %s",
                   ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    
    // Set options
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    
    return ctx;
}

/**
 * Load CA certificate and key
 */
static gboolean load_ca_certificate(DeadlightSSLManager *ssl_mgr, GError **error) {
    FILE *fp;
    
    // Load CA certificate
    fp = fopen(ssl_mgr->ca_cert_file, "r");
    if (!fp) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                   "Failed to open CA certificate file: %s",
                   ssl_mgr->ca_cert_file);
        return FALSE;
    }
    
    ssl_mgr->ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!ssl_mgr->ca_cert) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to load CA certificate: %s",
                   ERR_error_string(ERR_get_error(), NULL));
        return FALSE;
    }
    
    // Load CA private key
    fp = fopen(ssl_mgr->ca_key_file, "r");
    if (!fp) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                   "Failed to open CA key file: %s",
                   ssl_mgr->ca_key_file);
        return FALSE;
    }
    
    ssl_mgr->ca_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!ssl_mgr->ca_key) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to load CA private key: %s",
                   ERR_error_string(ERR_get_error(), NULL));
        return FALSE;
    }
    
    g_info("CA certificate and key loaded successfully");
    return TRUE;
}

/**
 * Intercept SSL connection (stub for now)
 */
gboolean deadlight_ssl_intercept_connection(DeadlightConnection *connection, GError **error) {
    g_return_val_if_fail(connection != NULL, FALSE);
    
    // TODO: Implement SSL interception
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
               "SSL interception not yet implemented");
    return FALSE;
}

/**
 * Create CA certificate (utility function)
 */
gboolean deadlight_ssl_create_ca_certificate(const gchar *cert_file, 
                                           const gchar *key_file, 
                                           GError **error) {
    // TODO: Implement CA certificate generation
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
               "CA certificate generation not yet implemented");
    return FALSE;
}