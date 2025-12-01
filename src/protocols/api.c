#include "api.h"
#include <string.h>
#include <json-glib/json-glib.h>
#include <time.h>
#include "core/utils.h"
#include "smtp.h"

static gsize api_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult api_handle(DeadlightConnection *conn, GError **error);
static void api_cleanup(DeadlightConnection *conn);
static DeadlightHandlerResult api_handle_system_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_federation_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_email_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_blog_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_outbound_email(DeadlightConnection *conn,
                                                        DeadlightRequest *request,
                                                        GError **error);
static DeadlightHandlerResult api_send_404(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult api_send_json_response(DeadlightConnection *conn, gint status_code, const gchar *status_text, const gchar *json_body, GError **error);
static DeadlightHandlerResult api_federation_send(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_federation_receive(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_metrics_endpoint(DeadlightConnection *conn, GError **error);
static gboolean email_send_via_mailchannels(const gchar *from, const gchar *to,
                                            const gchar *subject, const gchar *body,
                                            GError **error);

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
    g_debug("API detect called with %zu bytes: %.20s", len, (char*)data);

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
    
    // Debug: Show the raw request
    gchar *request_preview = g_strndup((gchar*)conn->client_buffer->data, 
                                       MIN(conn->client_buffer->len, 200));
    g_debug("API conn %lu: Raw request preview: %s", conn->id, request_preview);
    g_free(request_preview);

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

    DeadlightHandlerResult result = HANDLER_ERROR;

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
        result = HANDLER_SUCCESS_CLEANUP_NOW;
    } else if (g_str_equal(request->uri, "/api/health")) {
        g_info("API health check for conn %lu", conn->id);
        
        // Simple health check response
        gchar *json_response = g_strdup_printf(
            "{\"status\":\"ok\",\"version\":\"%s\",\"timestamp\":%ld,\"proxy\":\"deadlight\"}",
            DEADLIGHT_VERSION_STRING,
            time(NULL)
        );
        
        result = api_send_json_response(conn, 200, "OK", json_response, error);
        g_free(json_response);
    } else if (g_str_has_prefix(request->uri, "/api/system/")) {
        result = api_handle_system_endpoint(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/email/")) {
        result = api_handle_email_endpoint(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/outbound/email")) {
        result = api_handle_outbound_email(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/blog/")) {
        result = api_handle_blog_endpoint(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/federation/")) {
        result = api_handle_federation_endpoint(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/metrics")) {
        result = api_handle_metrics_endpoint(conn, error);
    } else {
        result = api_send_404(conn, error);
    }
    
    deadlight_request_free(request);
    return result;
}

static DeadlightHandlerResult api_handle_system_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    if (g_str_equal(request->uri, "/api/system/ip")) {
        // Return current external IP
        gchar *ip = get_external_ip(); // Can implement this
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
    } else if (g_str_has_prefix(request->uri, "/api/federation/test/")) {
        // Domain testing endpoint - extract the domain name
        const gchar *domain = request->uri + strlen("/api/federation/test/");
        g_info("API federation domain test for: %s", domain);
        
        // For now, simulate a successful test
        // TODO: Implement actual domain connectivity testing
        gchar *json_response = g_strdup_printf(
            "{\"domain\":\"%s\",\"status\":\"verified\",\"trust_level\":\"verified\",\"test_time\":\"%ld\",\"active\":true}", 
            domain, time(NULL));
        
        DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json_response, error);
        g_free(json_response);
        return result;
    } else if (g_str_equal(request->uri, "/api/federation/status")) {
        // Federation system status
        const gchar *json_response = 
            "{"
            "\"status\":\"online\","
            "\"connected_domains\":1,"
            "\"posts_sent\":0,"
            "\"posts_received\":0,"
            "\"comments_synced\":0"
            "}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
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
        "Access-Control-Allow-Origin: https://deadlight.boo\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, X-API-Key\r\n"
        "Content-Encoding: identity\r\n"  // Explicitly disable compression
        "Cache-Control: no-cache\r\n"     // Prevent caching issues
        "Connection: close\r\n"
        "\r\n"
        "%s", status_code, status_text, strlen(json_body), json_body);

    // Add this debug logging
    g_debug("API conn %lu: Sending response (%zu bytes):\n%s", 
            conn->id, strlen(response), response);
    
    gboolean success = g_output_stream_write_all(client_os, response, strlen(response), NULL, NULL, error);
    if (!success) {
        g_warning("API conn %lu: Failed to write response: %s", 
                  conn->id, error && *error ? (*error)->message : "unknown error");
    }
    
    g_free(response);
    return success ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
}

static DeadlightHandlerResult api_handle_email_endpoint(DeadlightConnection *conn, 
                                                       DeadlightRequest *request, 
                                                       GError **error) {
    if (g_str_equal(request->method, "POST") && g_str_has_suffix(request->uri, "/send")) {
        // Parse JSON body (existing code)
        const gchar *body_start = strstr((gchar*)conn->client_buffer->data, "\r\n\r\n");
        if (!body_start) {
            return api_send_json_response(conn, 400, "Bad Request", 
                                         "{\"error\":\"No request body\"}", error);
        }
        body_start += 4;
        
        JsonParser *parser = json_parser_new();
        if (!json_parser_load_from_data(parser, body_start, -1, error)) {
            g_object_unref(parser);
            return api_send_json_response(conn, 400, "Bad Request", 
                                         "{\"error\":\"Invalid JSON\"}", error);
        }
        
        JsonNode *root = json_parser_get_root(parser);
        JsonObject *obj = json_node_get_object(root);
        
        const gchar *to = json_object_get_string_member(obj, "to");
        const gchar *from = json_object_has_member(obj, "from") ? 
                           json_object_get_string_member(obj, "from") : 
                           "noreply@deadlight.boo";
        const gchar *subject = json_object_has_member(obj, "subject") ? 
                              json_object_get_string_member(obj, "subject") : 
                              "Message from Deadlight";
        const gchar *body = json_object_get_string_member(obj, "body");
        
        // Send via MailChannels API (port 443 HTTPS - never blocked!)
        GError *send_error = NULL;
        if (email_send_via_mailchannels(from, to, subject, body, &send_error)) {
            g_object_unref(parser);
            return api_send_json_response(conn, 200, "OK", 
                "{\"status\":\"success\",\"message\":\"Email sent via MailChannels\"}", 
                error);
        } else {
            gchar *err_json = g_strdup_printf(
                "{\"status\":\"error\",\"message\":\"Email send failed: %s\"}", 
                send_error ? send_error->message : "unknown error");
            
            if (send_error) g_error_free(send_error);
            g_object_unref(parser);
            
            DeadlightHandlerResult result = api_send_json_response(conn, 500, 
                "Internal Server Error", err_json, error);
            g_free(err_json);
            return result;
        }
    }
    
    return api_send_404(conn, error);
}

static DeadlightHandlerResult api_handle_outbound_email(DeadlightConnection *conn,
                                                        DeadlightRequest *request,
                                                        GError **error)
{
    if (!g_str_equal(request->method, "POST")) {
        return api_send_json_response(conn, 405, "Method Not Allowed",
                                      "{\"error\":\"POST required\"}", error);
    }

    g_info("API: Outbound email request from %s", conn->client_address);

    // Extract body (use request->body if populated, else fallback)
    gchar *body_str = NULL;
    if (request->body && request->body->len > 0) {
        body_str = g_strndup((gchar*)request->body->data, request->body->len);
    } else {
        // Fallback: find \r\n\r\n manually
        const gchar *buf = (const gchar*)conn->client_buffer->data;
        gsize len = conn->client_buffer->len;
        const gchar *body_start = g_strstr_len(buf, len, "\r\n\r\n");
        if (!body_start) {
            return api_send_json_response(conn, 400, "Bad Request",
                                          "{\"error\":\"No body found\"}", error);
        }
        gsize offset = (body_start - buf) + 4;
        body_str = g_strndup(buf + offset, len - offset);
    }

    // Parse JSON
    JsonParser *parser = json_parser_new();
    if (!json_parser_load_from_data(parser, body_str, -1, error)) {
        g_free(body_str);
        g_object_unref(parser);
        return api_send_json_response(conn, 400, "Bad Request",
                                      "{\"error\":\"Invalid JSON\"}", error);
    }

    JsonNode *root = json_parser_get_root(parser);
    if (!JSON_NODE_HOLDS_OBJECT(root)) {
        g_free(body_str);
        g_object_unref(parser);
        return api_send_json_response(conn, 400, "Bad Request",
                                      "{\"error\":\"JSON root must be object\"}", error);
    }

    JsonObject *obj = json_node_get_object(root);
    const gchar *from = json_object_get_string_member(obj, "from");
    const gchar *to = json_object_get_string_member(obj, "to");
    const gchar *subject = json_object_get_string_member(obj, "subject");
    const gchar *body = json_object_get_string_member(obj, "body");

    if (!from || !to || !subject || !body || strlen(to) == 0) {
        g_free(body_str);
        g_object_unref(parser);
        return api_send_json_response(conn, 400, "Bad Request",
                                      "{\"error\":\"Missing required fields: from, to, subject, body\"}", error);
    }

    // ─── CRITICAL FIX: Populate request->body so HMAC uses real payload ──────
    if (!request->body || request->body->len == 0) {
        // We already have the exact body in body_str (null-terminated)
        // But we need the raw bytes without trailing null for HMAC
        gsize real_len = strlen(body_str);  // this is correct — body_str has no trailing junk
        request->body = g_byte_array_sized_new(real_len);
        g_byte_array_append(request->body, (const guint8*)body_str, real_len);
        g_info("Fixed empty request->body — restored %zu bytes for HMAC", real_len);
    }

    // ─── FINAL WORKING HMAC AUTH (NO MORE EXCUSES) ─────────────────────────────
    const gchar *auth_header = deadlight_request_get_header(request, "Authorization");

    // Use the body we already extracted and KNOW is correct
    const gchar *payload_for_hmac = body_str;
    gsize payload_len = strlen(body_str);  // body_str is already null-terminated and exact

    if (!auth_header || !validate_hmac(auth_header, payload_for_hmac, payload_len, conn->context->auth_secret)) {
        g_info("HMAC validation failed");
        g_info("  → Received: %s", auth_header ? auth_header : "missing");
        g_info("  → Payload (%zu bytes): %s", payload_len, payload_for_hmac);
        g_free(body_str);
        g_object_unref(parser);
        return api_send_json_response(conn, 401, "Unauthorized",
                                      "{\"error\":\"Invalid credentials\"}", error);
    }

    g_info("HMAC validated successfully — sending email");
    // ─────────────────────────────────────────────────────────────────────────────
    // Send email
    gboolean sent = email_send_via_mailchannels(from, to, subject, body, error);
    g_free(body_str);
    g_object_unref(parser);

    if (!sent) {
        g_warning("API: Failed to send email via MailChannels: %s", error && *error ? (*error)->message : "unknown");
        return api_send_json_response(conn, 502, "Bad Gateway",
                                      "{\"error\":\"Email provider failed\"}", error);
    }

    g_info("API: Email sent successfully to %s", to);
    return api_send_json_response(conn, 202, "Accepted",
                                  "{\"status\":\"sent\",\"provider\":\"mailchannels\"}", error);
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

static gboolean email_send_via_mailchannels(const gchar *from, const gchar *to,
                                            const gchar *subject, const gchar *body,
                                            GError **error) {
    
    g_info("Email: Sending via MailChannels API to %s", to);
    
    // Build JSON payload
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    
    // Personalizations
    json_builder_set_member_name(builder, "personalizations");
    json_builder_begin_array(builder);
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "to");
    json_builder_begin_array(builder);
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "email");
    json_builder_add_string_value(builder, to);
    json_builder_end_object(builder);
    json_builder_end_array(builder);
    json_builder_end_object(builder);
    json_builder_end_array(builder);
    
    // From
    json_builder_set_member_name(builder, "from");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "email");
    json_builder_add_string_value(builder, from);
    json_builder_set_member_name(builder, "name");
    json_builder_add_string_value(builder, "Deadlight Blog");
    json_builder_end_object(builder);
    
    // Subject
    json_builder_set_member_name(builder, "subject");
    json_builder_add_string_value(builder, subject);
    
    // Content
    json_builder_set_member_name(builder, "content");
    json_builder_begin_array(builder);
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "type");
    json_builder_add_string_value(builder, "text/plain");
    json_builder_set_member_name(builder, "value");
    json_builder_add_string_value(builder, body);
    json_builder_end_object(builder);
    json_builder_end_array(builder);
    
    json_builder_end_object(builder);
    
    // Generate JSON
    JsonGenerator *gen = json_generator_new();
    JsonNode *root_node = json_builder_get_root(builder);
    json_generator_set_root(gen, root_node);
    gchar *json_payload = json_generator_to_data(gen, NULL);
    
    // Connect to MailChannels API (HTTPS - port 443)
    GSocketClient *client = g_socket_client_new();
    g_socket_client_set_tls(client, TRUE);
    g_socket_client_set_timeout(client, 30);
    
    GSocketConnection *connection = g_socket_client_connect_to_host(
        client, "api.mailchannels.net", 443, NULL, error);
    
    if (!connection) {
        g_free(json_payload);
        json_node_unref(root_node);
        g_object_unref(gen);
        g_object_unref(builder);
        g_object_unref(client);
        return FALSE;
    }
    
    GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(connection));
    GInputStream *in = g_io_stream_get_input_stream(G_IO_STREAM(connection));
    
    // Build HTTP request
    GString *request = g_string_new("");
    g_string_printf(request,
        "POST /tx/v1/send HTTP/1.1\r\n"
        "Host: api.mailchannels.net\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "User-Agent: Deadlight-Proxy/1.0\r\n"
        "X-Auth-Domain: deadlight.boo\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        strlen(json_payload), json_payload);
    
    // Send request
    gboolean success = g_output_stream_write_all(out, request->str, request->len, 
                                                 NULL, NULL, error);
    
    if (success) {
        // Read response
        gchar response[4096];
        gssize bytes_read = g_input_stream_read(in, response, sizeof(response) - 1, 
                                                NULL, error);
        
        if (bytes_read > 0) {
            response[bytes_read] = '\0';
            
            // Check for HTTP 202 Accepted
            if (strstr(response, "HTTP/1.1 202") || strstr(response, "HTTP/1.1 200")) {
                g_info("Email: Successfully sent via MailChannels");
                success = TRUE;
            } else {
                g_warning("Email: MailChannels API error: %s", response);
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "MailChannels API rejected request");
                success = FALSE;
            }
        }
    }
    
    // Cleanup
    g_string_free(request, TRUE);
    g_free(json_payload);
    json_node_unref(root_node);
    g_object_unref(gen);
    g_object_unref(builder);
    g_object_unref(connection);
    g_object_unref(client);
    
    return success;
}

static DeadlightHandlerResult api_handle_metrics_endpoint(DeadlightConnection *conn, GError **error) {
    DeadlightContext *ctx = conn->context;
    g_info("API metrics endpoint for conn %lu", conn->id);
    
    // Build JSON response with actual metrics
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    
    // Basic metrics
    json_builder_set_member_name(builder, "active_connections");
    json_builder_add_int_value(builder, ctx->active_connections);
    
    json_builder_set_member_name(builder, "total_connections");
    json_builder_add_int_value(builder, ctx->total_connections);
    
    json_builder_set_member_name(builder, "bytes_transferred");
    json_builder_add_int_value(builder, ctx->bytes_transferred);
    
    json_builder_set_member_name(builder, "uptime");
    json_builder_add_double_value(builder, g_timer_elapsed(ctx->uptime_timer, NULL));
    
    // Protocol breakdown - count connections by protocol
    json_builder_set_member_name(builder, "protocols");
    json_builder_begin_object(builder);
    
    // Initialize protocol counters
    GHashTable *protocol_stats = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    
    // Count active connections by protocol
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, ctx->connections);
    
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        DeadlightConnection *active_conn = (DeadlightConnection*)value;
        const gchar *protocol_name = deadlight_protocol_to_string(active_conn->protocol);
        
        // Get or create stats for this protocol
        gpointer stats_ptr = g_hash_table_lookup(protocol_stats, protocol_name);
        gint active_count = stats_ptr ? GPOINTER_TO_INT(stats_ptr) : 0;
        g_hash_table_insert(protocol_stats, g_strdup(protocol_name), GINT_TO_POINTER(active_count + 1));
    }
    
    // Add protocol stats to JSON
    const gchar *protocols[] = {"HTTP", "HTTPS", "WebSocket", "SOCKS", "SMTP", "IMAP", "FTP", "API"};
    for (size_t i = 0; i < G_N_ELEMENTS(protocols); i++) {
        gpointer active_ptr = g_hash_table_lookup(protocol_stats, protocols[i]);
        gint active = active_ptr ? GPOINTER_TO_INT(active_ptr) : 0;
        
        json_builder_set_member_name(builder, protocols[i]);
        json_builder_begin_object(builder);
        
        json_builder_set_member_name(builder, "active");
        json_builder_add_int_value(builder, active);
        
        // TODO: Add total connections and bytes per protocol
        // This would require tracking in the connection structure
        json_builder_set_member_name(builder, "total");
        json_builder_add_int_value(builder, 0); // Placeholder
        
        json_builder_set_member_name(builder, "bytes");
        json_builder_add_int_value(builder, 0); // Placeholder
        
        json_builder_end_object(builder);
    }
    
    json_builder_end_object(builder); // End protocols
    
    // Server info
    json_builder_set_member_name(builder, "server_info");
    json_builder_begin_object(builder);
    
    json_builder_set_member_name(builder, "version");
    json_builder_add_string_value(builder, DEADLIGHT_VERSION_STRING);
    
    json_builder_set_member_name(builder, "port");
    json_builder_add_int_value(builder, ctx->listen_port);
    
    json_builder_set_member_name(builder, "ssl_intercept");
    json_builder_add_boolean_value(builder, ctx->ssl_intercept_enabled);
    
    json_builder_set_member_name(builder, "max_connections");
    json_builder_add_int_value(builder, ctx->max_connections);
    
    json_builder_end_object(builder); // End server_info
    
    json_builder_end_object(builder); // End root
    
    // Generate JSON string
    JsonGenerator *gen = json_generator_new();
    JsonNode *root = json_builder_get_root(builder);
    json_generator_set_root(gen, root);
    
    gchar *json_str = json_generator_to_data(gen, NULL);
    
    // Send response
    DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json_str, error);
    
    // Cleanup
    g_free(json_str);
    g_object_unref(gen);
    json_node_unref(root);
    g_object_unref(builder);
    g_hash_table_destroy(protocol_stats);
    
    return result;
}