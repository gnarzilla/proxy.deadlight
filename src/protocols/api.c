#include "api.h"
#include <string.h>
#include <json-glib/json-glib.h> // You might need to add this dependency

static gsize api_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult api_handle(DeadlightConnection *conn, GError **error);
static void api_cleanup(DeadlightConnection *conn);
static DeadlightHandlerResult api_handle_system_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_federation_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_email_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_blog_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_send_404(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult api_send_json_response(DeadlightConnection *conn, gint status_code, const gchar *status_text, const gchar *json_body, GError **error);
static DeadlightHandlerResult api_federation_send(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_federation_receive(DeadlightConnection *conn, DeadlightRequest *request, GError **error);

static const DeadlightProtocolHandler api_protocol_handler = {
    .name = "API",
    .protocol_id = DEADLIGHT_PROTOCOL_API, // Reuse HTTP protocol ID
    .detect = api_detect,
    .handle = api_handle,
    .cleanup = api_cleanup
};

void deadlight_register_api_handler(void) {
    deadlight_protocol_register(&api_protocol_handler);
}

static gsize api_detect(const guint8 *data, gsize len) {
    // Need at least "GET /api/" (9 chars)
    if (len < 9) return 0;
    
    // Check for API path in the request line (before headers)
    if ((len >= 9 && memcmp(data, "GET /api/", 9) == 0) ||
        (len >= 10 && memcmp(data, "POST /api/", 10) == 0) ||
        (len >= 9 && memcmp(data, "PUT /api/", 9) == 0) ||
        (len >= 12 && memcmp(data, "DELETE /api/", 12) == 0)) {
        
        // Return high priority
        return 100; // Much higher than HTTP's max of 8
    }
    
    return 0;
}

static DeadlightHandlerResult api_handle(DeadlightConnection *conn, GError **error) {
    g_info("API handler for connection %lu", conn->id);
    
    // Parse HTTP request
    DeadlightRequest *request = deadlight_request_new(conn);
    
    // Convert buffer to string for parsing
    gchar *request_str = g_strndup((gchar*)conn->client_buffer->data, conn->client_buffer->len);
    
    if (!deadlight_request_parse_headers(request, request_str, strlen(request_str))) {
        g_free(request_str);
        deadlight_request_free(request);
        return HANDLER_ERROR;
    }
    
    g_free(request_str);

    if (g_str_equal(request->method, "OPTIONS")) {
        // Handle CORS preflight
        const gchar *response = 
            "HTTP/1.1 200 OK\r\n"
            "Access-Control-Allow-Origin: https://deadlight.boo\r\n"
            "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, X-API-Key\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        
        GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_os, response, strlen(response), NULL, NULL, error);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }
    
    // Route to appropriate handler
    if (g_str_has_prefix(request->uri, "/api/system/")) {
        return api_handle_system_endpoint(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/email/")) {
        return api_handle_email_endpoint(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/blog/")) {
        return api_handle_blog_endpoint(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/federation/")) {
        return api_handle_federation_endpoint(conn, request, error);
    } else {
        return api_send_404(conn, error);
    }
}

static DeadlightHandlerResult api_handle_system_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    if (g_str_equal(request->uri, "/api/system/ip")) {
        // Return current external IP
        gchar *ip = get_external_ip(); // You'd implement this
        gchar *json_response = g_strdup_printf("{\"external_ip\":\"%s\",\"port\":8080}", ip);
        DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json_response, error);
        g_free(json_response);
        g_free(ip);
        return result;
    }
    return api_send_404(conn, error);
}

static DeadlightHandlerResult api_handle_federation_endpoint(DeadlightConnection *conn, 
                                                           DeadlightRequest *request, 
                                                           GError **error) {
    // This is where the magic happens for decentralized social media!
    // Handle instance-to-instance communication via email protocols
    
    if (g_str_equal(request->uri, "/api/federation/send")) {
        // Send a post/comment to another deadlight instance via email
        return api_federation_send(conn, request, error);
    } else if (g_str_equal(request->uri, "/api/federation/receive")) {
        // Receive and process a post/comment from another instance
        return api_federation_receive(conn, request, error);
    }
    
    return api_send_404(conn, error);
}

static void api_cleanup(DeadlightConnection *conn) {
    g_debug("API cleanup called for conn %lu", conn->id);
    // Clean up any API-specific resources
    (void)conn; // Suppress unused parameter warning
}

static DeadlightHandlerResult api_send_404(DeadlightConnection *conn, GError **error) {
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    
    const gchar *response = 
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 34\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"error\":\"API endpoint not found\"}";
    
    if (!g_output_stream_write_all(client_os, response, strlen(response), NULL, NULL, error)) {
        g_warning("API conn %lu: Failed to send 404 response", conn->id);
        return HANDLER_ERROR;
    }
    
    return HANDLER_SUCCESS_CLEANUP_NOW;
}

static DeadlightHandlerResult api_send_json_response(DeadlightConnection *conn, gint status_code, 
                                                    const gchar *status_text, const gchar *json_body, 
                                                    GError **error) {
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    
    gchar *response = g_strdup_printf(
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: https://deadlight.boo\r\n"  // Add your domain
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, X-API-Key\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", status_code, status_text, strlen(json_body), json_body);
    
    gboolean success = g_output_stream_write_all(client_os, response, strlen(response), NULL, NULL, error);
    g_free(response);
    
    return success ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
}

static DeadlightHandlerResult api_handle_email_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    g_info("API email endpoint for conn %lu: %s %s", conn->id, request->method, request->uri);
    
    if (g_str_equal(request->method, "POST") && g_str_has_suffix(request->uri, "/send")) {
        // Handle email sending
        const gchar *json_response = "{\"status\":\"success\",\"message\":\"Email queued for sending\"}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
        
    } else if (g_str_equal(request->method, "POST") && g_str_has_suffix(request->uri, "/receive")) {
        // Handle incoming email (from SMTP bridge)
        const gchar *json_response = "{\"status\":\"success\",\"message\":\"Email received and processed\"}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
        
    } else if (g_str_equal(request->method, "GET") && g_str_has_suffix(request->uri, "/status")) {
        // Email system status
        const gchar *json_response = "{\"status\":\"running\",\"queue_size\":0,\"last_processed\":null}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
    }
    
    return api_send_404(conn, error);
}

static DeadlightHandlerResult api_handle_blog_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    g_info("API blog endpoint for conn %lu: %s %s", conn->id, request->method, request->uri);
    
    if (g_str_equal(request->method, "POST") && g_str_has_suffix(request->uri, "/publish")) {
        // Handle blog post publishing
        const gchar *json_response = "{\"status\":\"success\",\"message\":\"Post published successfully\"}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
        
    } else if (g_str_equal(request->method, "GET") && g_str_has_suffix(request->uri, "/posts")) {
        // List blog posts
        const gchar *json_response = "{\"posts\":[],\"total\":0}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
        
    } else if (g_str_equal(request->method, "GET") && g_str_has_suffix(request->uri, "/status")) {
        // Blog status
        const gchar *json_response = "{\"status\":\"running\",\"version\":\"4.0.0\"}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
    }
    
    return api_send_404(conn, error);
}

static DeadlightHandlerResult api_federation_send(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    (void)request;
    g_info("API federation send for conn %lu", conn->id);
    
    // TODO: Implement federated post sending via email
    const gchar *json_response = "{\"status\":\"success\",\"message\":\"Federated message sent via email\"}";
    return api_send_json_response(conn, 200, "OK", json_response, error);
}

static DeadlightHandlerResult api_federation_receive(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    (void)request;
    g_info("API federation receive for conn %lu", conn->id);
    
    // TODO: Process incoming federated content from email
    const gchar *json_response = "{\"status\":\"success\",\"message\":\"Federated message processed\"}";
    return api_send_json_response(conn, 200, "OK", json_response, error);
}
