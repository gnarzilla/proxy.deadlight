#include "deadlight.h"
#include <gio/gio.h>
#include <string.h>

gchar *get_external_ip(void) {
    GError *error = NULL;
    GSocketClient *client = g_socket_client_new();
    GSocketConnection *connection = NULL;
    gchar *result = NULL;
    
    // Try to connect to a simple IP checking service
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
    g_return_val_if_fail(module_name != NULL, FALSE);
    
    g_print("Testing module: %s\n", module_name);
    
    // TODO: Implement module testing
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

gchar *deadlight_format_duration(gdouble seconds) {
    if (seconds < 60) {
        return g_strdup_printf("%.1f seconds", seconds);
    } else if (seconds < 3600) {
        return g_strdup_printf("%.1f minutes", seconds / 60.0);
    } else if (seconds < 86400) {
        return g_strdup_printf("%.1f hours", seconds / 3600.0);
    } else {
        return g_strdup_printf("%.1f days", seconds / 86400.0);
    }
}
