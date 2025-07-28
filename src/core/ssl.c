/**
 * Deadlight Proxy v4.0 - SSL/TLS Module
 *
 * SSL interception and certificate management
 */

#include <glib.h>
#include <gio/gio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
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
    
    // Set more permissive options for better compatibility
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    
    // Set minimum and maximum TLS versions
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    // For client contexts, set verification mode
    if (!is_server) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    
    // Set cipher list for compatibility
    SSL_CTX_set_cipher_list(ctx, "DEFAULT:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4");
    
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
 * Intercept SSL connection 
 */

/**
 * Generate a certificate for the given hostname, signed by our CA
 */
static X509* generate_host_certificate(DeadlightSSLManager *ssl_mgr, 
                                      const gchar *hostname,
                                      EVP_PKEY **out_key,
                                      GError **error) {
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bn = NULL;
    X509_NAME *name = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    
    // Generate key using modern EVP API
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to create key context");
        goto cleanup;
    }
    
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to initialize key generation");
        goto cleanup;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to set key size");
        goto cleanup;
    }
    
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to generate key");
        goto cleanup;
    }
    
    // Create certificate
    cert = X509_new();
    if (!cert) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to create certificate");
        goto cleanup;
    }
    
    // Set version and serial number
    X509_set_version(cert, 2); // X509v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 
                    (long)g_random_int_range(1000000, 9999999));
    
    // Set validity period (1 year)
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    
    // Set subject
    name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, 
                              (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                              (unsigned char *)"Deadlight Proxy", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                              (unsigned char *)hostname, -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_NAME_free(name);
    
    // Set issuer to our CA
    X509_set_issuer_name(cert, X509_get_subject_name(ssl_mgr->ca_cert));
    
    // Set public key
    X509_set_pubkey(cert, pkey);
    
    // Add extensions
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ssl_mgr->ca_cert, cert, NULL, NULL, 0);
    
    // Subject Alternative Name
    gchar *san = g_strdup_printf("DNS:%s", hostname);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, 
                                              NID_subject_alt_name, san);
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    g_free(san);
    
    // Key usage
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
                             "digitalSignature,keyEncipherment");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Sign with CA key
    if (!X509_sign(cert, ssl_mgr->ca_key, EVP_sha256())) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to sign certificate: %s",
                   ERR_error_string(ERR_get_error(), NULL));
        X509_free(cert);
        cert = NULL;
        goto cleanup;
    }
    
    *out_key = pkey;
    pkey = NULL; // Caller owns it now
    
cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (bn) BN_free(bn);
    
    return cert;
}

/**
 * Get or generate certificate for hostname
 */
static gboolean get_host_certificate(DeadlightSSLManager *ssl_mgr,
                                   const gchar *hostname,
                                   X509 **cert,
                                   EVP_PKEY **key,
                                   GError **error) {
    g_mutex_lock(&ssl_mgr->cert_mutex);
    
    // Check cache first
    gchar *cert_path = g_strdup_printf("%s/%s.crt", 
                                      ssl_mgr->cert_cache_dir, hostname);
    gchar *key_path = g_strdup_printf("%s/%s.key", 
                                     ssl_mgr->cert_cache_dir, hostname);
    
    // Try to load from cache
    FILE *fp = fopen(cert_path, "r");
    if (fp) {
        *cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);
        
        fp = fopen(key_path, "r");
        if (fp) {
            *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
            fclose(fp);
            
            if (*cert && *key) {
                g_debug("Using cached certificate for %s", hostname);
                g_free(cert_path);
                g_free(key_path);
                g_mutex_unlock(&ssl_mgr->cert_mutex);
                return TRUE;
            }
        }
    }
    
    // Generate new certificate
    g_info("Generating certificate for %s", hostname);
    *cert = generate_host_certificate(ssl_mgr, hostname, key, error);
    
    if (!*cert) {
        g_free(cert_path);
        g_free(key_path);
        g_mutex_unlock(&ssl_mgr->cert_mutex);
        return FALSE;
    }
    
    // Save to cache
    fp = fopen(cert_path, "w");
    if (fp) {
        PEM_write_X509(fp, *cert);
        fclose(fp);
    }
    
    fp = fopen(key_path, "w");
    if (fp) {
        PEM_write_PrivateKey(fp, *key, NULL, NULL, 0, NULL, NULL);
        fclose(fp);
    }
    
    g_free(cert_path);
    g_free(key_path);
    g_mutex_unlock(&ssl_mgr->cert_mutex);
    
    return TRUE;
}

/**
 * Intercept SSL connection - Complete implementation
 */
/**
 * Intercept SSL connection - Complete implementation
 */
gboolean deadlight_ssl_intercept_connection(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->context != NULL, FALSE);
    g_return_val_if_fail(conn->context->ssl != NULL, FALSE);
    
    DeadlightSSLManager *ssl_mgr = conn->context->ssl;
    
    if (!conn->target_host) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "No target host specified for SSL interception");
        return FALSE;
    }
    
    g_info("Intercepting SSL connection to %s", conn->target_host);
    
    // Get certificate for target host
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    
    if (!get_host_certificate(ssl_mgr, conn->target_host, &cert, &key, error)) {
        return FALSE;
    }
    // In deadlight_ssl_intercept_connection, replace the SSL_CTX creation with:
    
    // Create SSL context for this connection
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        X509_free(cert);
        EVP_PKEY_free(key);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to create SSL context");
        return FALSE;
    }
    
    // Configure SSL context for better compatibility
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    // Set cipher suites
    SSL_CTX_set_cipher_list(ctx, "DEFAULT:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4");
    
    // Set ECDH curve for better compatibility
    SSL_CTX_set_ecdh_auto(ctx, 1);
    
    // Set certificate and key
    if (SSL_CTX_use_certificate(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, key) != 1) {
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(key);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to set certificate/key");
        return FALSE;
    }
    
    // Create SSL structure for client connection
    SSL *client_ssl = SSL_new(ctx);
    if (!client_ssl) {
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(key);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to create SSL structure");
        return FALSE;
    }
    
    // Get client socket
    GSocket *client_socket = g_socket_connection_get_socket(conn->client_connection);
    int client_fd = g_socket_get_fd(client_socket);
    
    // Set up SSL on client socket
    SSL_set_fd(client_ssl, client_fd);
    SSL_set_accept_state(client_ssl);
    
    // Set socket to blocking mode temporarily for SSL handshake
    g_socket_set_blocking(client_socket, TRUE);
    
    // Perform SSL handshake with client with retries
    int ret;
    int retries = 0;
    const int max_retries = 50; // 5 seconds max
    
    while ((ret = SSL_accept(client_ssl)) <= 0 && retries < max_retries) {
        int ssl_error = SSL_get_error(client_ssl, ret);
        
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            // Non-blocking operation would block, wait a bit
            g_usleep(100000); // 100ms
            retries++;
            continue;
        } else {
            // Real error
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            SSL_free(client_ssl);
            SSL_CTX_free(ctx);
            X509_free(cert);
            EVP_PKEY_free(key);
            g_socket_set_blocking(client_socket, FALSE); // Restore non-blocking
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "SSL handshake failed: %s (error %d)", err_buf, ssl_error);
            return FALSE;
        }
    }
    
    if (ret <= 0) {
        SSL_free(client_ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(key);
        g_socket_set_blocking(client_socket, FALSE);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                   "SSL handshake timed out");
        return FALSE;
    }
    
    // Set socket back to non-blocking
    g_socket_set_blocking(client_socket, FALSE);
    
    // Now establish SSL connection to upstream
    SSL *upstream_ssl = SSL_new(ssl_mgr->client_ctx);
    if (!upstream_ssl) {
        SSL_free(client_ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(key);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to create upstream SSL");
        return FALSE;
    }
    
    // Get upstream socket
    GSocket *upstream_socket = g_socket_connection_get_socket(conn->upstream_connection);
    int upstream_fd = g_socket_get_fd(upstream_socket);
    
    SSL_set_fd(upstream_ssl, upstream_fd);
    SSL_set_connect_state(upstream_ssl);
    SSL_set_tlsext_host_name(upstream_ssl, conn->target_host);
    
    // Set upstream to blocking for handshake
    g_socket_set_blocking(upstream_socket, TRUE);
    
    // Connect to upstream with retries
    retries = 0;
    while ((ret = SSL_connect(upstream_ssl)) <= 0 && retries < max_retries) {
        int ssl_error = SSL_get_error(upstream_ssl, ret);
        
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            g_usleep(100000); // 100ms
            retries++;
            continue;
        } else {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            SSL_free(upstream_ssl);
            SSL_free(client_ssl);
            SSL_CTX_free(ctx);
            X509_free(cert);
            EVP_PKEY_free(key);
            g_socket_set_blocking(client_socket, FALSE);
            g_socket_set_blocking(upstream_socket, FALSE);
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "Upstream SSL handshake failed: %s (error %d)", err_buf, ssl_error);
            return FALSE;
        }
    }
    
    if (ret <= 0) {
        SSL_free(upstream_ssl);
        SSL_free(client_ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(key);
        g_socket_set_blocking(client_socket, FALSE);
        g_socket_set_blocking(upstream_socket, FALSE);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                   "Upstream SSL handshake timed out");
        return FALSE;
    }
    
    // Set upstream back to non-blocking
    g_socket_set_blocking(upstream_socket, FALSE);
    
    // Store SSL objects in connection
    conn->ssl_established = TRUE;
    conn->client_ssl = client_ssl;
    conn->upstream_ssl = upstream_ssl;
    conn->ssl_ctx = ctx;
    
    // Clean up (SSL objects have their own references)
    X509_free(cert);
    EVP_PKEY_free(key);
    
    g_info("SSL interception established for %s", conn->target_host);
    return TRUE;
}

/**
 * Create CA certificate - Complete implementation
 */
gboolean deadlight_ssl_create_ca_certificate(const gchar *cert_file, 
                                           const gchar *key_file, 
                                           GError **error) {
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bn = NULL;
    X509_NAME *name = NULL;
    FILE *fp = NULL;
    gboolean success = FALSE;
    EVP_PKEY_CTX *pctx = NULL;
    
    // Generate key using modern EVP API
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to create key context");
        goto cleanup;
    }
    
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to initialize key generation");
        goto cleanup;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 4096) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to set key size");
        goto cleanup;
    }
    
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to generate key");
        goto cleanup;
    }
    
    // Create certificate
    cert = X509_new();
    if (!cert) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to create certificate");
        goto cleanup;
    }
    
    // Set version and serial
    X509_set_version(cert, 2);  // X509v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    
    // Set validity (10 years)
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 315360000L);
    
    // Set subject and issuer (self-signed)
    name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, 
                              (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                              (unsigned char *)"Deadlight Proxy", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                              (unsigned char *)"Deadlight CA", -1, -1, 0);
    
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);  // Self-signed
    X509_NAME_free(name);
    
    // Set public key
    X509_set_pubkey(cert, pkey);
    
    // Add CA extensions
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    
    X509_EXTENSION *ext;
    
    // Basic constraints - CA:TRUE
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:TRUE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Key usage
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, 
                             "digitalSignature,keyCertSign,cRLSign");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Subject key identifier
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Sign the certificate
    if (!X509_sign(cert, pkey, EVP_sha256())) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to sign CA certificate: %s",
                   ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    
    // Save certificate
    fp = fopen(cert_file, "w");
    if (!fp) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to open certificate file for writing: %s", cert_file);
        goto cleanup;
    }
    
    if (!PEM_write_X509(fp, cert)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to write certificate");
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);
    
    // Save private key
    fp = fopen(key_file, "w");
    if (!fp) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to open key file for writing: %s", key_file);
        goto cleanup;
    }
    
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to write private key");
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);
    
    g_info("CA certificate created successfully");
    success = TRUE;
    
cleanup:
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (bn) BN_free(bn);
    
    return success;
}