/**
 * Deadlight Proxy v4.0 - SSL Interception Module
 */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include "deadlight.h"

typedef struct {
    X509 *ca_cert;
    EVP_PKEY *ca_key;
    GHashTable *cert_cache; // hostname -> X509*
    GMutex mutex;
} SSLInterceptor;

static SSLInterceptor *interceptor = NULL;

// Initialize SSL interception
gboolean deadlight_ssl_intercept_init(DeadlightContext *context, GError **error) {
    interceptor = g_new0(SSLInterceptor, 1);
    g_mutex_init(&interceptor->mutex);
    interceptor->cert_cache = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                   g_free, (GDestroyNotify)X509_free);
    
    // Load CA certificate and key
    const gchar *ca_cert_file = deadlight_config_get_string(context, "ssl", 
                                                           "ca_cert", NULL);
    const gchar *ca_key_file = deadlight_config_get_string(context, "ssl", 
                                                          "ca_key", NULL);
    
    if (!ca_cert_file || !ca_key_file) {
        // Generate CA if not provided
        if (!generate_ca_certificate(context, error)) {
            return FALSE;
        }
    } else {
        // Load existing CA
        FILE *fp = fopen(ca_cert_file, "r");
        if (!fp) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                       "Cannot open CA cert file: %s", ca_cert_file);
            return FALSE;
        }
        interceptor->ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);
        
        fp = fopen(ca_key_file, "r");
        if (!fp) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                       "Cannot open CA key file: %s", ca_key_file);
            return FALSE;
        }
        interceptor->ca_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
    }
    
    return TRUE;
