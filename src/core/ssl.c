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
    conn->upstream_tls = G_TLS_CONNECTION(g_tls_client_connection_new(
        G_IO_STREAM(conn->upstream_connection),
        server_identity,
        error
    ));
    
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

// Helper to extract X509 from GTlsCertificate
static X509* extract_x509_from_gtls_certificate(GTlsCertificate *gtls_cert) {
    GByteArray *cert_der = NULL;
    const guchar *cert_data;
    X509 *x509 = NULL;
    
    g_object_get(gtls_cert, "certificate", &cert_der, NULL);
    if (!cert_der) return NULL;
    
    cert_data = cert_der->data;
    x509 = d2i_X509(NULL, &cert_data, cert_der->len);
    
    g_byte_array_unref(cert_der);
    return x509;
}

// Copy relevant extensions from upstream certificate
static void copy_relevant_extensions(X509 *cert, X509 *upstream_cert, X509 *ca_cert, const char *hostname) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);
    
    // Always add SAN with the hostname
    gchar *san = g_strdup_printf("DNS:%s", hostname);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    g_free(san);
    
    // Copy key usage if present in upstream
    int ext_loc = X509_get_ext_by_NID(upstream_cert, NID_key_usage, -1);
    if (ext_loc >= 0) {
        X509_EXTENSION *upstream_ext = X509_get_ext(upstream_cert, ext_loc);
        ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(upstream_ext);
        
        // For key usage, we typically want: digitalSignature, keyEncipherment
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "digitalSignature,keyEncipherment");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }
    
    // Copy extended key usage if present
    ext_loc = X509_get_ext_by_NID(upstream_cert, NID_ext_key_usage, -1);
    if (ext_loc >= 0) {
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, "serverAuth,clientAuth");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }
    
    // Basic constraints - always CA:FALSE for end entity
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
}

// Add default extensions when no upstream cert available
static void add_default_extensions(X509 *cert, X509 *ca_cert, const char *hostname) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);
    
    // Subject Alternative Name
    gchar *san = g_strdup_printf("DNS:%s", hostname);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    g_free(san);
    
    // Basic constraints
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Key usage
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "digitalSignature,keyEncipherment");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Extended key usage
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, "serverAuth,clientAuth");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
}

/**
 * Generate a certificate for the given hostname, signed by our CA
 */
static X509* generate_host_certificate(DeadlightSSLManager *ssl_mgr, 
                                      const gchar *hostname,
                                      EVP_PKEY **out_key,
                                      GError **error,
                                      DeadlightConnection *conn) {
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *upstream_x509 = NULL;
    EVP_PKEY_CTX *pctx = NULL;  // Declare pctx here
    
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
    
    // Extract upstream certificate if available
    if (conn && conn->upstream_peer_cert) {
        upstream_x509 = extract_x509_from_gtls_certificate(conn->upstream_peer_cert);
    }
    
    // Create certificate
    cert = X509_new();
    if (!cert) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to create certificate");
        goto cleanup;
    }
    
    X509_set_version(cert, 2);  // X509v3
    
    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(cert), g_get_real_time() / 1000000);
    
    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);  // 1 year
    
    // Set subject
    X509_NAME *subject = X509_NAME_new();
    X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC, (unsigned char *)"Deadlight Proxy", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (unsigned char *)hostname, -1, -1, 0);
    X509_set_subject_name(cert, subject);
    X509_NAME_free(subject);
    
    // Set issuer to our CA
    X509_set_issuer_name(cert, X509_get_subject_name(ssl_mgr->ca_cert));
    
    // Set public key
    X509_set_pubkey(cert, pkey);
    
    // Add extensions
    if (upstream_x509) {
        copy_relevant_extensions(cert, upstream_x509, ssl_mgr->ca_cert, hostname);
    } else {
        add_default_extensions(cert, ssl_mgr->ca_cert, hostname);
    }
    
    // Sign the certificate
    if (!X509_sign(cert, ssl_mgr->ca_key, EVP_sha256())) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, 
                   "Failed to sign certificate: %s", 
                   ERR_error_string(ERR_get_error(), NULL));
        X509_free(cert);
        cert = NULL;
        goto cleanup;
    }
    
    *out_key = pkey;
    pkey = NULL;  // Transfer ownership
    
cleanup:
    if (upstream_x509) X509_free(upstream_x509);
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    
    return cert;
}

// Updated generate_host_pem with certificate mimicry
static gchar* generate_host_pem(DeadlightSSLManager *ssl_mgr, 
                                const gchar *hostname,
                                DeadlightConnection *conn,
                                GError **error) {
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    BIO *bio = NULL;
    gchar *pem_data = NULL;
    X509 *upstream_x509 = NULL;
    long pem_len;
    EVP_PKEY_CTX *pctx = NULL;

    // Generate private key using modern API
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
    
    if (EVP_PKEY_keygen(pctx, &key) <= 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to generate private key: %s",
                   ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    // Extract upstream certificate if available for mimicry
    if (conn && conn->upstream_peer_cert) {
        upstream_x509 = extract_x509_from_gtls_certificate(conn->upstream_peer_cert);
        if (upstream_x509) {
            g_debug("Extracted upstream X509 certificate for mimicry");
        }
    }

    // Create certificate
    cert = X509_new();
    if (!cert) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to create certificate: %s",
                   ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    // Set version
    X509_set_version(cert, 2);  // X509v3

    // Set serial number - if upstream available, generate similar length
    if (upstream_x509) {
        ASN1_INTEGER *upstream_serial = X509_get_serialNumber(upstream_x509);
        int serial_len = ASN1_STRING_length(upstream_serial);
        BIGNUM *bn = BN_new();
        BN_rand(bn, serial_len * 8, -1, 0);
        BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(cert));
        BN_free(bn);
    } else {
        ASN1_INTEGER_set(X509_get_serialNumber(cert), g_get_real_time() / 1000000);
    }

    // Set validity period - mimic upstream if available
    if (upstream_x509) {
        const ASN1_TIME *not_before = X509_get0_notBefore(upstream_x509);
        const ASN1_TIME *not_after = X509_get0_notAfter(upstream_x509);
        X509_set1_notBefore(cert, not_before);
        X509_set1_notAfter(cert, not_after);
    } else {
        // Default: valid from now for 1 year
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    }

    // Set subject name - enhance with upstream info if available
    X509_NAME *subject = X509_NAME_new();
    
    if (upstream_x509) {
        // Copy organization info from upstream if present
        X509_NAME *upstream_subject = X509_get_subject_name(upstream_x509);
        int pos = -1;
        X509_NAME_ENTRY *entry;
        
        // Copy country
        pos = X509_NAME_get_index_by_NID(upstream_subject, NID_countryName, -1);
        if (pos >= 0) {
            entry = X509_NAME_get_entry(upstream_subject, pos);
            X509_NAME_add_entry(subject, entry, -1, 0);
        } else {
            X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
        }
        
        // Copy organization
        pos = X509_NAME_get_index_by_NID(upstream_subject, NID_organizationName, -1);
        if (pos >= 0) {
            entry = X509_NAME_get_entry(upstream_subject, pos);
            X509_NAME_add_entry(subject, entry, -1, 0);
        } else {
            X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC, (unsigned char *)"Deadlight Proxy", -1, -1, 0);
        }
        
        // Copy state/province if present
        pos = X509_NAME_get_index_by_NID(upstream_subject, NID_stateOrProvinceName, -1);
        if (pos >= 0) {
            entry = X509_NAME_get_entry(upstream_subject, pos);
            X509_NAME_add_entry(subject, entry, -1, 0);
        }
        
        // Copy locality if present
        pos = X509_NAME_get_index_by_NID(upstream_subject, NID_localityName, -1);
        if (pos >= 0) {
            entry = X509_NAME_get_entry(upstream_subject, pos);
            X509_NAME_add_entry(subject, entry, -1, 0);
        }
    } else {
        // Default subject info
        X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
        X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC, (unsigned char *)"Deadlight Proxy", -1, -1, 0);
    }
    
    // Always set CN to our hostname
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (unsigned char *)hostname, -1, -1, 0);
    X509_set_subject_name(cert, subject);
    X509_NAME_free(subject);

    // Set issuer: Always our CA (this is what makes it trusted by clients that trust our CA)
    X509_set_issuer_name(cert, X509_get_subject_name(ssl_mgr->ca_cert));

    // Set public key
    X509_set_pubkey(cert, key);

    // Add extensions based on upstream or defaults
    if (upstream_x509) {
        copy_relevant_extensions(cert, upstream_x509, ssl_mgr->ca_cert, hostname);
    } else {
        add_default_extensions(cert, ssl_mgr->ca_cert, hostname);
    }

    // Sign the certificate with our CA key
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

    // Write certificate and key to PEM format
    if (!PEM_write_bio_X509(bio, cert) || 
        !PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to write PEM");
        goto cleanup;
    }

    // Read PEM data from BIO
    pem_len = BIO_pending(bio);
    pem_data = g_malloc(pem_len + 1);
    BIO_read(bio, pem_data, pem_len);
    pem_data[pem_len] = '\0';

    g_info("Generated certificate for %s %s upstream mimicry", 
           hostname, upstream_x509 ? "with" : "without");

cleanup:
    if (upstream_x509) X509_free(upstream_x509);
    if (cert) X509_free(cert);
    if (key) EVP_PKEY_free(key);
    if (bio) BIO_free(bio);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    
    return pem_data;
}

/**
 * Get or generate certificate for hostname
 */
typedef struct {
    gchar *pem_data;
    gint64 expiry_time;
} CertCacheEntry;

static gchar* get_host_certificate(DeadlightSSLManager *ssl_mgr, const gchar *hostname, DeadlightConnection *conn, GError **error) {
    g_mutex_lock(&ssl_mgr->cert_mutex);
    
    // Check cache with expiration
    CertCacheEntry *entry = g_hash_table_lookup(ssl_mgr->cert_cache, hostname);
    gint64 now = g_get_real_time() / G_USEC_PER_SEC;
    
    if (entry && entry->expiry_time > now) {
        g_debug("Using cached PEM for %s", hostname);
        gchar *cached_pem = g_strdup(entry->pem_data);
        g_mutex_unlock(&ssl_mgr->cert_mutex);
        return cached_pem;
    }
    
    // Generate new certificate
    gchar *pem = generate_host_pem(ssl_mgr, hostname, conn, error);
    if (pem) {
        CertCacheEntry *new_entry = g_new0(CertCacheEntry, 1);
        new_entry->pem_data = g_strdup(pem);
        new_entry->expiry_time = now + (24 * 60 * 60); // 24 hour cache
        g_hash_table_insert(ssl_mgr->cert_cache, g_strdup(hostname), new_entry);
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
    // Set ALPN protocols for better compatibility
    const gchar *alpn_protos[] = {"h2", "http/1.1", NULL};
    g_object_set(conn->client_tls,
                "advertised-protocols", alpn_protos,
                NULL);

    // Also check what the client wants
    gchar **client_protos = NULL;
    g_object_get(conn->client_tls,
                "advertised-protocols", &client_protos,
                NULL);
    if (client_protos) {
        for (int i = 0; client_protos[i]; i++) {
            g_debug("Client advertised protocol: %s", client_protos[i]);
        }
        g_strfreev(client_protos);
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