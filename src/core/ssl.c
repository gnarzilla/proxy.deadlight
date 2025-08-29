// in src/core/ssl.c

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
    SSL_CTX *server_ctx;
    SSL_CTX *client_ctx;
    X509 *ca_cert;
    EVP_PKEY *ca_key;
    gchar *ca_cert_file;
    gchar *ca_key_file;
    gchar *cert_cache_dir;
    GMutex cert_mutex;
    GHashTable *cert_cache;
    GTlsDatabase *system_trust_db; // System trust database for certificate validation
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
    
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    context->ssl = g_new0(DeadlightSSLManager, 1);
    g_mutex_init(&context->ssl->cert_mutex);
    
    // --- FIXED: Load system trust store ---
    g_info("Loading system CA certificates for upstream validation...");
    const gchar *ca_bundle_file = "/etc/ssl/certs/ca-certificates.crt";
    context->ssl->system_trust_db = g_tls_file_database_new(ca_bundle_file, error);

    if (context->ssl->system_trust_db == NULL) {
        g_warning("FATAL: Failed to load system CA trust store from %s: %s", ca_bundle_file, (*error)->message);
        g_free(context->ssl);
        context->ssl = NULL;
        return FALSE; 
    }
    g_info("System CA trust store loaded successfully.");
    
    // Get configuration for our own CA (used for interception)
    context->ssl->ca_cert_file = deadlight_config_get_string(context, "ssl", "ca_cert_file", "/etc/deadlight/ca.crt");
    context->ssl->ca_key_file = deadlight_config_get_string(context, "ssl", "ca_key_file", "/etc/deadlight/ca.key");
    context->ssl->cert_cache_dir = deadlight_config_get_string(context, "ssl", "cert_cache_dir", "/tmp/deadlight_certs");
    
    context->ssl->cert_cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    
    context->ssl->server_ctx = create_ssl_context(TRUE, error);
    if (!context->ssl->server_ctx) {
        return FALSE; // Cleanup will be handled by caller
    }
    
    context->ssl->client_ctx = create_ssl_context(FALSE, error);
    if (!context->ssl->client_ctx) {
        SSL_CTX_free(context->ssl->server_ctx);
        return FALSE;
    }
    
    if (context->ssl_intercept_enabled) {
        if (!load_ca_certificate(context->ssl, error)) {
            SSL_CTX_free(context->ssl->server_ctx);
            SSL_CTX_free(context->ssl->client_ctx);
            return FALSE;
        }
        
        if (g_mkdir_with_parents(context->ssl->cert_cache_dir, 0700) != 0) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to create certificate cache directory: %s", context->ssl->cert_cache_dir);
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
        // --- FIXED: Added cleanup for trust store ---
        if (context->ssl->system_trust_db) {
            g_object_unref(context->ssl->system_trust_db);
        }

        // --- FIXED: Removed duplicated if statement ---
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
    
    EVP_cleanup();
    ERR_free_strings();
}

// ... (create_ssl_context, load_ca_certificate, generate_host_certificate, get_host_certificate functions remain unchanged) ...
// The compiler warnings about them being unused are OK for now. They are used by the interception logic we haven't tested yet.

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
    
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    if (!is_server) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    
    SSL_CTX_set_cipher_list(ctx, "DEFAULT:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4");
    
    return ctx;
}

/**
 * Load CA certificate and key
 */
static gboolean load_ca_certificate(DeadlightSSLManager *ssl_mgr, GError **error) {
    FILE *fp;
    
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


// --- THIS FUNCTION IS THE IMPORTANT ONE TO GET RIGHT ---
/**
 * Establish an SSL/TLS connection to an upstream server.
 * This is used by handlers like IMAPS that need to encrypt their upstream connection.
 */
gboolean deadlight_network_establish_upstream_ssl(DeadlightConnection *conn, GError **error) {
    if (!conn->upstream_connection) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Upstream connection is not established; cannot perform TLS handshake.");
        return FALSE;
    }

    // Step 1: Create a GSocketConnectable object representing the server we're connecting to.
    GSocketConnectable *server_identity = g_network_address_new(conn->target_host, conn->target_port);

    // Step 2: Create the client connection object, passing this explicit server identity.
    conn->upstream_tls = g_tls_client_connection_new(
        G_IO_STREAM(conn->upstream_connection),
        server_identity,
        error
    );
    
    g_object_unref(server_identity);
    
    if (!conn->upstream_tls) {
        return FALSE;
    }

    // Step 3: Explicitly set the trust database.
    g_object_set(G_OBJECT(conn->upstream_tls),
                 "database", conn->context->ssl->system_trust_db,
                 NULL);

    // Step 4: Perform the handshake.
    if (!g_tls_connection_handshake(conn->upstream_tls, NULL, error)) {
        g_warning("Upstream TLS handshake failed for conn %lu to host %s: %s", conn->id, conn->target_host, (*error)->message);
        g_object_unref(conn->upstream_tls);
        conn->upstream_tls = NULL;
        return FALSE;
    }
    
    // Step 5: Extract upstream certificate details for mimicry.
    GTlsCertificate *peer_cert = g_tls_connection_get_peer_certificate(conn->upstream_tls);
    if (peer_cert) {
        // Store certificate for later use in forgery (assumes DeadlightConnection has a field for this).
        conn->upstream_peer_cert = g_object_ref(peer_cert);
        g_info("Upstream certificate retrieved for conn %lu to host %s", conn->id, conn->target_host);
    } else {
        g_warning("Could not retrieve upstream certificate for conn %lu to host %s", conn->id, conn->target_host);
        conn->upstream_peer_cert = NULL;
    }
    
    g_info("Upstream TLS connection established for conn %lu to host %s", conn->id, conn->target_host);
    conn->ssl_established = TRUE;
    return TRUE;
}

/**
 * Generate a certificate for the given hostname, signed by our CA
 */
static X509* generate_host_certificate(DeadlightSSLManager *ssl_mgr, 
                                      const gchar *hostname,
                                      EVP_PKEY **out_key,
                                      GError **error,
                                      DeadlightConnection *conn) { // Add conn parameter to access upstream cert
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bn = NULL;
    X509_NAME *name = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    
    // Generate key using modern EVP API
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to create key context");
        goto cleanup;
    }
    
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to initialize key generation");
        goto cleanup;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to set key size");
        goto cleanup;
    }
    
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to generate key");
        goto cleanup;
    }
    
    // Create certificate
    cert = X509_new();
    if (!cert) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to create certificate");
        goto cleanup;
    }
    
    // Set version and serial number
    X509_set_version(cert, 2); // X509v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)g_random_int_range(1000000, 9999999));
    
    // Set validity period (1 year)
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    
    // Set subject (still use hostname for CN and SAN)
    name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"Deadlight Proxy", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)hostname, -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_NAME_free(name);
    
    // Set issuer: Mimic upstream certificate issuer if available
    if (conn->upstream_peer_cert) {
        // Extract issuer details from upstream certificate (requires conversion from GTlsCertificate to X509)
        // Note: This step requires OpenSSL and GLib integration, may need helper function
        g_info("Mimicking issuer from upstream certificate for %s", hostname);
        // Placeholder for now: ideally, extract X509 from GTlsCertificate and copy issuer
        // For simplicity, we'll still use CA for signing but log intent
    } else {
        // Fallback to default CA issuer
        X509_set_issuer_name(cert, X509_get_subject_name(ssl_mgr->ca_cert));
    }
    
    // Set public key
    X509_set_pubkey(cert, pkey);
    
    // Add extensions (mimic upstream if available)
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ssl_mgr->ca_cert, cert, NULL, NULL, 0);
    
    // Subject Alternative Name
    gchar *san = g_strdup_printf("DNS:%s", hostname);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    g_free(san);
    
    // Key usage (mimic upstream if possible, otherwise default)
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "digitalSignature,keyEncipherment");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Extended key usage (add if upstream has it)
    if (conn->upstream_peer_cert) {
        // Placeholder: Extract extended key usage from upstream cert if available
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, "serverAuth,clientAuth");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }
    
    // Sign with CA key (still use our CA for signing)
    if (!X509_sign(cert, ssl_mgr->ca_key, EVP_sha256())) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to sign certificate: %s", ERR_error_string(ERR_get_error(), NULL));
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

static gchar* generate_host_pem(DeadlightSSLManager *ssl_mgr, 
                                const gchar *hostname,
                                DeadlightConnection *conn, // Added parameter
                                GError **error) {
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    BIO *bio = NULL;
    gchar *pem_data = NULL;
    long pem_len;

    // Generate private key
    key = EVP_RSA_gen(2048);
    if (!key) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to generate private key: %s",
                   ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    // Create certificate, passing conn for mimicry
    cert = X509_new();
    if (!cert) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to create certificate: %s",
                   ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    // Set version and serial
    X509_set_version(cert, 2);  // X509v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), g_get_real_time() / 1000000);

    // Set validity (1 year)
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    // Set subject name
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)hostname, -1, -1, 0);

    // Set issuer: Mimic upstream if available
    if (conn && conn->upstream_peer_cert) {
        g_info("Mimicking issuer from upstream certificate for %s", hostname);
        // Placeholder: Extract issuer from conn->upstream_peer_cert and set it
        // For now, fallback to CA issuer
        X509_set_issuer_name(cert, X509_get_subject_name(ssl_mgr->ca_cert));
    } else {
        X509_set_issuer_name(cert, X509_get_subject_name(ssl_mgr->ca_cert));
    }

    // Set public key
    X509_set_pubkey(cert, key);

    // Add extensions (mimic upstream if available)
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, ssl_mgr->ca_cert, NULL, NULL, 0);

    // Subject Alternative Name
    gchar *san = g_strdup_printf("DNS:%s", hostname);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
    g_free(san);
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    // Basic constraints
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    // Key usage
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
                              "digitalSignature,keyEncipherment");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    // Extended key usage
    if (conn && conn->upstream_peer_cert) {
        // Placeholder: Extract extended key usage from upstream cert if available
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage,
                                  "serverAuth,clientAuth");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    // Sign the certificate
    if (!X509_sign(cert, ssl_mgr->ca_key, EVP_sha256())) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to sign certificate: %s",
                   ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    // Write to memory BIO
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to create BIO");
        goto cleanup;
    }

    if (!PEM_write_bio_X509(bio, cert) || !PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to write PEM");
        goto cleanup;
    }

    pem_len = BIO_pending(bio);
    pem_data = g_malloc(pem_len + 1);
    BIO_read(bio, pem_data, pem_len);
    pem_data[pem_len] = '\0';

cleanup:
    if (cert) X509_free(cert);
    if (key) EVP_PKEY_free(key);
    if (bio) BIO_free(bio);
    return pem_data;
}

/**
 * Get or generate certificate for hostname
 */
static gchar* get_host_certificate(DeadlightSSLManager *ssl_mgr, const gchar *hostname, DeadlightConnection *conn, GError **error) {
    g_mutex_lock(&ssl_mgr->cert_mutex);
    gchar *cached_pem = g_hash_table_lookup(ssl_mgr->cert_cache, hostname);
    if (cached_pem) {
        g_debug("Using cached PEM for %s", hostname);
        cached_pem = g_strdup(cached_pem);
        g_mutex_unlock(&ssl_mgr->cert_mutex);
        return cached_pem;
    }

    // Pass the connection object to access upstream certificate for mimicry
    gchar *pem = generate_host_pem(ssl_mgr, hostname, conn, error);
    if (pem) {
        g_hash_table_insert(ssl_mgr->cert_cache, g_strdup(hostname), g_strdup(pem));
    }
    g_mutex_unlock(&ssl_mgr->cert_mutex);
    return pem;
}

/**
 * Intercept SSL connection
 */
gboolean deadlight_ssl_intercept_connection(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->client_connection != NULL, FALSE);
    g_return_val_if_fail(conn->target_host != NULL, FALSE);

    // Step 1: Establish upstream TLS (already using GTlsClientConnection)
    if (!deadlight_network_establish_upstream_ssl(conn, error)) {
        return FALSE;
    }

    // Step 2: Get forged PEM for the host, passing conn for mimicry
    gchar *pem_data = get_host_certificate(conn->context->ssl, conn->target_host, conn, error);
    if (!pem_data) {
        return FALSE;
    }
    
    // Debugging: Save PEM to temporary file for inspection
    g_file_set_contents("/tmp/test.pem", pem_data, -1, NULL);

    // Step 3: Create GTlsCertificate from PEM
    GTlsCertificate *tls_cert = g_tls_certificate_new_from_pem(pem_data, -1, error);
    g_free(pem_data);
    if (!tls_cert) {
        return FALSE;
    }

    // Step 4: Wrap client connection as TLS server
    conn->client_tls = (GTlsConnection *)g_tls_server_connection_new(
        G_IO_STREAM(conn->client_connection),
        tls_cert,
        error
    );
    g_object_unref(tls_cert);
    if (!conn->client_tls) {
        return FALSE;
    }

    // No need for explicit database/validation on server side

    // Step 5: Perform server-side handshake (blocks appropriately in non-async mode)
    if (!g_tls_connection_handshake(conn->client_tls, NULL, error)) {
        g_warning("Client TLS handshake failed for conn %lu to host %s: %s", 
                  conn->id, conn->target_host, (*error)->message);
        g_object_unref(conn->client_tls);
        conn->client_tls = NULL;
        return FALSE;
    }

    g_info("Client TLS interception established for conn %lu to host %s", conn->id, conn->target_host);
    conn->ssl_established = TRUE;
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