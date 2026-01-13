#include "deadlight.h"
#include "utils.h"
#include <gio/gio.h>
#include <string.h>
#include <glib.h>
#include <openssl/hmac.h>

gboolean validate_hmac_bytes(const gchar *auth_header,
                             const guint8 *payload,
                             gsize payload_len,
                             const gchar *secret)
{
    if (!auth_header || !payload || !secret)
        return FALSE;

    const gchar *received = NULL;
    gsize prefix_len = 0;

    /* Accept Bearer (standard name) or HMAC (legacy) */
    if (g_str_has_prefix(auth_header, "Bearer ")) {
        prefix_len = 7;
    } else if (g_str_has_prefix(auth_header, "HMAC ")) {
        prefix_len = 5;
    } else {
        g_info("HMAC invalid prefix: '%s'", auth_header);
        return FALSE;
    }

    received = auth_header + prefix_len;

    /* Trim leading whitespace */
    while (*received && g_ascii_isspace(*received)) {
        received++;
    }

    /* Copy & trim trailing whitespace (\r\n from headers) */
    gchar *received_clean = g_strchomp(g_strdup(received));

    /* Compute HMAC-SHA256(secret, payload[bytes]) */
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int md_len = 0;

    HMAC(EVP_sha256(),
         secret,
         strlen(secret),
         payload,
         payload_len,
         md,
         &md_len);

    /* Convert digest to lowercase hex */
    gchar computed[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        g_snprintf(computed + (i * 2), 3, "%02x", md[i]);
    }
    computed[64] = '\0';

    gboolean valid = (g_strcmp0(computed, received_clean) == 0);

    if (!valid && g_getenv("DEADLIGHT_VERBOSE")) {
        g_info("HMAC mismatch — expected: %s  received: %s",
               computed, received_clean);
    } else if (valid) {
        g_info("HMAC validated successfully");
    }

    g_free(received_clean);
    return valid;
}

gboolean validate_hmac(const gchar *auth_header,
                       const gchar *payload,
                       const gchar *secret)
{
    if (!payload)
        return FALSE;

    return validate_hmac_bytes(auth_header,
                               (const guint8 *)payload,
                               strlen(payload),
                               secret);
}


gchar *get_external_ip(void) {
    GError *error = NULL;
    GSocketClient *client = g_socket_client_new();
    GSocketConnection *connection = NULL;
    gchar *result = NULL;
    
    // connect to a simple IP checking service
    connection = g_socket_client_connect_to_host(client, 
                                                  "api.ipify.org", 80, 
                                                  NULL, &error);
    
    if (connection) {
        GOutputStream *output = g_io_stream_get_output_stream(G_IO_STREAM(connection));
        GInputStream *input = g_io_stream_get_input_stream(G_IO_STREAM(connection));
        
        const gchar *request = "GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n";
        
        if (g_output_stream_write_all(output, request, strlen(request), NULL, NULL, &error)) {
            gchar buffer[1024];
            gssize bytes_read = g_input_stream_read(input, buffer, sizeof(buffer) - 1, NULL, &error);
            
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                // Find the IP address after the headers
                gchar *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4; // Skip the \r\n\r\n
                    result = g_strdup(g_strstrip(body));
                }
            }
        }
        
        g_object_unref(connection);
    }
    
    g_object_unref(client);
    
    if (error) {
        g_warning("Failed to get external IP: %s", error->message);
        g_error_free(error);
    }
    
    // Return localhost if we couldn't get external IP
    return result ? result : g_strdup("127.0.0.1");
}

gboolean deadlight_test_module(const gchar *module_name) {
    (void)module_name; // Mark as unused for now
    g_print("Testing module system...NOT IMPLEMENTED\n");
    // ... implementation ...
    return TRUE;
}

gchar *deadlight_format_bytes(guint64 bytes) {
    if (bytes < 1024) {
        return g_strdup_printf("%lu B", bytes);
    } else if (bytes < 1024 * 1024) {
        return g_strdup_printf("%.2f KB", bytes / 1024.0);
    } else if (bytes < 1024 * 1024 * 1024) {
        return g_strdup_printf("%.2f MB", bytes / (1024.0 * 1024.0));
    } else {
        return g_strdup_printf("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

gchar *deadlight_format_duration(gint64 seconds) {
    if (seconds < 60) {
        return g_strdup_printf("%.1ld seconds", seconds);
    } else if (seconds < 3600) {
        return g_strdup_printf("%.1f minutes", seconds / 60.0);
    } else if (seconds < 86400) {
        return g_strdup_printf("%.1f hours", seconds / 3600.0);
    } else {
        return g_strdup_printf("%.1f days", seconds / 86400.0);
    }
}

gboolean deadlight_parse_host_port(const gchar *host_port, gchar **host, guint16 *port) {
    if (!host_port || !host || !port) return FALSE;

    *host = NULL;

    if (host_port[0] == '[') { 
        const gchar *end = strchr(host_port, ']');
        if (!end) return FALSE; 

        *host = g_strndup(host_port + 1, end - (host_port + 1));

        if (*(end + 1) == ':') {
            gulong p = strtoul(end + 2, NULL, 10);
            if (p > 0 && p <= 65535) {
                *port = (guint16)p;
            } else {
                g_free(*host);
                *host = NULL;
            }
        }

    } else { 
        const gchar *colon = strrchr(host_port, ':');
        if (colon) { 
            *host = g_strndup(host_port, colon - host_port);

            gulong p = strtoul(colon + 1, NULL, 10);
            if (p > 0 && p <= 65535) {
                *port = (guint16)p;
            } else {
                g_free(*host);
                *host = NULL;
            }
        } else {
            *host = g_strdup(host_port);
        }
    }

    return (*host != NULL && strlen(*host) > 0);
}