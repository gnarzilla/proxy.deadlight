#include "api.h"
#include <string.h>
#include <json-glib/json-glib.h>
#include <time.h>
#include "core/utils.h"
#include "smtp.h"

// ═══════════════════════════════════════════════════════════════════════════
// FORWARD DECLARATIONS
// ═══════════════════════════════════════════════════════════════════════════
static gsize api_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult api_handle(DeadlightConnection *conn, GError **error);
static void api_cleanup(DeadlightConnection *conn);
static DeadlightHandlerResult api_handle_system_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_federation_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_email_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_blog_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_outbound_email(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_metrics_endpoint(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult api_send_404(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult api_send_json_response(DeadlightConnection *conn, gint status_code, const gchar *status_text, const gchar *json_body, GError **error);
static DeadlightHandlerResult api_federation_send(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_federation_receive(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_federation_test_domain(DeadlightConnection *conn, const gchar *domain, GError **error);
static gboolean email_send_via_mailchannels(DeadlightConnection *conn, const gchar *from, const gchar *to, const gchar *subject, const gchar *body, GError **error);

// Helper functions
static JsonObject* parse_request_body(DeadlightConnection *conn, GError **error);
static gboolean validate_json_fields(JsonObject *obj, const gchar **required_fields, gsize num_fields, GError **error);

// ═══════════════════════════════════════════════════════════════════════════
// PROTOCOL HANDLER REGISTRATION
// ═══════════════════════════════════════════════════════════════════════════
static const DeadlightProtocolHandler api_protocol_handler = {
    .name = "API",
    .protocol_id = DEADLIGHT_PROTOCOL_API,
    .detect = api_detect,
    .handle = api_handle,
    .cleanup = api_cleanup
};

void deadlight_register_api_handler(void) {
    deadlight_protocol_register(&api_protocol_handler);
}

// ═══════════════════════════════════════════════════════════════════════════
// PROTOCOL DETECTION
// ═══════════════════════════════════════════════════════════════════════════
static gsize api_detect(const guint8 *data, gsize len) {
    if (len < 9) return 0;

    // Fast path: Check standard origin form
    if ((len >= 9 && memcmp(data, "GET /api/", 9) == 0) ||
        (len >= 10 && memcmp(data, "POST /api/", 10) == 0) ||
        (len >= 9 && memcmp(data, "PUT /api/", 9) == 0) ||
        (len >= 12 && memcmp(data, "DELETE /api/", 12) == 0) ||
        (len >= 12 && memcmp(data, "OPTIONS /api/", 13) == 0)) {
        return 100;
    }

    // Slow path: Check for /api/ anywhere in first line (absolute URI)
    const guint8 *ptr = data;
    const guint8 *end = data + MIN(len, 512);

    while (ptr < end && *ptr != '\r' && *ptr != '\n') {
        if (ptr + 5 < end && memcmp(ptr, "/api/", 5) == 0) {
            g_debug("API Detect: Found absolute URI match");
            return 100;
        }
        ptr++;
    }

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Parse JSON request body from connection buffer
 * Caller must unref the returned JsonObject
 */
static JsonObject* parse_request_body(DeadlightConnection *conn, GError **error) {
    const gchar *body_start = NULL;
    gsize body_len = 0;
    
    // Try to use parsed request body first
    if (conn->current_request && conn->current_request->body && 
        conn->current_request->body->len > 0) {
        body_start = (const gchar*)conn->current_request->body->data;
        body_len = conn->current_request->body->len;
        
        g_debug("API: Using parsed request body (%zu bytes)", body_len);
    } else {
        // Fallback: find \r\n\r\n manually
        const gchar *buffer = (const gchar*)conn->client_buffer->data;
        gsize buffer_len = conn->client_buffer->len;
        
        body_start = g_strstr_len(buffer, buffer_len, "\r\n\r\n");
        if (!body_start) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "No request body");
            return NULL;
        }
        body_start += 4;
        body_len = buffer_len - (body_start - buffer);
        
        g_debug("API: Extracted body from buffer (%zu bytes)", body_len);
    }

    // Ensure we have actual data
    if (body_len == 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Empty request body");
        return NULL;
    }

    // Create a null-terminated copy for JSON parser
    gchar *body_copy = g_strndup(body_start, body_len);
    
    // Debug: log first 100 chars of body
    gchar *preview = g_strndup(body_copy, MIN(100, body_len));
    g_debug("API: JSON body preview: %s", preview);
    g_free(preview);

    JsonParser *parser = json_parser_new();
    gboolean parse_success = json_parser_load_from_data(parser, body_copy, body_len, error);
    
    if (!parse_success) {
        g_prefix_error(error, "JSON parse failed: ");
        g_free(body_copy);
        g_object_unref(parser);
        return NULL;
    }

    JsonNode *root = json_parser_get_root(parser);
    if (!JSON_NODE_HOLDS_OBJECT(root)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "JSON root must be object");
        g_free(body_copy);
        g_object_unref(parser);
        return NULL;
    }

    JsonObject *obj = json_node_get_object(root);
    json_object_ref(obj);
    g_object_unref(parser);
    g_free(body_copy);
    
    return obj;
}

/**
 * Validate that all required fields exist in JSON object
 */
static gboolean validate_json_fields(JsonObject *obj, const gchar **required_fields, 
                                     gsize num_fields, GError **error) {
    for (gsize i = 0; i < num_fields; i++) {
        if (!json_object_has_member(obj, required_fields[i])) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                       "Missing required field: %s", required_fields[i]);
            return FALSE;
        }
    }
    return TRUE;
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN HANDLER
// ═══════════════════════════════════════════════════════════════════════════
static DeadlightHandlerResult api_handle(DeadlightConnection *conn, GError **error) {
    g_info("API handler for connection %lu", conn->id);
    
    // Debug: Show raw request
    gchar *request_preview = g_strndup((gchar*)conn->client_buffer->data, 
                                       MIN(conn->client_buffer->len, 500));
    g_debug("API conn %lu: Raw request (%zu bytes):\n%s", 
            conn->id, conn->client_buffer->len, request_preview);
    g_free(request_preview);

    // Parse HTTP request
    DeadlightRequest *request = deadlight_request_new(conn);
    gchar *request_str = g_strndup((gchar*)conn->client_buffer->data, conn->client_buffer->len);

    if (!deadlight_request_parse_headers(request, request_str, strlen(request_str))) {
        g_warning("API conn %lu: Failed to parse request headers", conn->id);
        g_free(request_str);
        deadlight_request_free(request);
        return HANDLER_ERROR;
    }
    
    g_debug("API conn %lu: Parsed - Method: '%s', URI: '%s', Body length: %zu", 
            conn->id, request->method, request->uri, 
            request->body ? request->body->len : 0);
    
    g_free(request_str);

    DeadlightHandlerResult result = HANDLER_ERROR;

    // Handle CORS preflight
    if (g_str_equal(request->method, "OPTIONS")) {
        const gchar *response = 
            "HTTP/1.1 200 OK\r\n"
            "Access-Control-Allow-Origin: https://deadlight.boo\r\n"
            "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, X-API-Key, Authorization\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        
        GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_os, response, strlen(response), NULL, NULL, error);
        result = HANDLER_SUCCESS_CLEANUP_NOW;
    }
    // Route to appropriate handler
    else if (g_str_equal(request->uri, "/api/health")) {
        gchar *json_response = g_strdup_printf(
            "{\"status\":\"ok\",\"version\":\"%s\",\"timestamp\":%ld,\"proxy\":\"deadlight\"}",
            DEADLIGHT_VERSION_STRING,
            time(NULL)
        );
        result = api_send_json_response(conn, 200, "OK", json_response, error);
        g_free(json_response);
    }
    else if (g_str_has_prefix(request->uri, "/api/system/")) {
        result = api_handle_system_endpoint(conn, request, error);
    }
    else if (g_str_has_prefix(request->uri, "/api/email/")) {
        result = api_handle_email_endpoint(conn, request, error);
    }
    else if (g_str_has_prefix(request->uri, "/api/outbound/email")) {
        result = api_handle_outbound_email(conn, request, error);
    }
    else if (g_str_has_prefix(request->uri, "/api/blog/")) {
        result = api_handle_blog_endpoint(conn, request, error);
    }
    else if (g_str_has_prefix(request->uri, "/api/federation/")) {
        result = api_handle_federation_endpoint(conn, request, error);
    }
    else if (g_str_has_prefix(request->uri, "/api/metrics")) {
        result = api_handle_metrics_endpoint(conn, error);
    }
    else {
        g_debug("API handler: No route matched for URI: %s", request->uri);
        result = api_send_404(conn, error);
    }
    
    deadlight_request_free(request);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// ENDPOINT HANDLERS
// ═══════════════════════════════════════════════════════════════════════════

static DeadlightHandlerResult api_handle_system_endpoint(DeadlightConnection *conn, 
                                                         DeadlightRequest *request, 
                                                         GError **error) {
    if (g_str_equal(request->uri, "/api/system/ip")) {
        gchar *ip = get_external_ip();
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
    if (g_str_equal(request->uri, "/api/federation/send")) {
        return api_federation_send(conn, request, error);
    }
    else if (g_str_equal(request->uri, "/api/federation/receive")) {
        return api_federation_receive(conn, request, error);
    }
    else if (g_str_equal(request->uri, "/api/federation/posts")) {
        // List stored federated posts
        const gchar *storage_dir = "/var/lib/deadlight/federation";
        GDir *dir = g_dir_open(storage_dir, 0, error);
        
        if (!dir) {
            return api_send_json_response(conn, 200, "OK", 
                "{\"posts\":[],\"total\":0,\"note\":\"No posts yet\"}", error);
        }
        
        JsonBuilder *builder = json_builder_new();
        json_builder_begin_object(builder);
        json_builder_set_member_name(builder, "posts");
        json_builder_begin_array(builder);
        
        gint count = 0;
        const gchar *filename;
        while ((filename = g_dir_read_name(dir)) != NULL) {
            if (g_str_has_prefix(filename, "post_") && g_str_has_suffix(filename, ".json")) {
                gchar *filepath = g_build_filename(storage_dir, filename, NULL);
                
                // Read and parse the stored post
                JsonParser *parser = json_parser_new();
                if (json_parser_load_from_file(parser, filepath, NULL)) {
                    JsonNode *node = json_parser_get_root(parser);
                    json_builder_add_value(builder, json_node_copy(node));
                    count++;
                }
                g_object_unref(parser);
                g_free(filepath);
            }
        }
        g_dir_close(dir);
        
        json_builder_end_array(builder);
        json_builder_set_member_name(builder, "total");
        json_builder_add_int_value(builder, count);
        json_builder_end_object(builder);
        
        JsonGenerator *gen = json_generator_new();
        JsonNode *root = json_builder_get_root(builder);
        json_generator_set_root(gen, root);
        gchar *json_str = json_generator_to_data(gen, NULL);
        
        DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json_str, error);
        
        g_free(json_str);
        json_node_unref(root);
        g_object_unref(gen);
        g_object_unref(builder);
        
        return result;
    }
    else if (g_str_has_prefix(request->uri, "/api/federation/test/")) {
        const gchar *domain = request->uri + strlen("/api/federation/test/");
        return api_federation_test_domain(conn, domain, error);
    }
    else if (g_str_equal(request->uri, "/api/federation/status")) {
        // Count stored posts
        const gchar *storage_dir = "/var/lib/deadlight/federation";
        GDir *dir = g_dir_open(storage_dir, 0, NULL);
        gint post_count = 0;
        
        if (dir) {
            const gchar *filename;
            while ((filename = g_dir_read_name(dir)) != NULL) {
                if (g_str_has_prefix(filename, "post_")) {
                    post_count++;
                }
            }
            g_dir_close(dir);
        }
        
        gchar *json_response = g_strdup_printf(
            "{"
            "\"status\":\"online\","
            "\"connected_domains\":0,"
            "\"posts_sent\":0,"
            "\"posts_received\":%d,"
            "\"comments_synced\":0"
            "}", post_count);
        
        DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json_response, error);
        g_free(json_response);
        return result;
    }
    
    return api_send_404(conn, error);
}

static DeadlightHandlerResult api_handle_email_endpoint(DeadlightConnection *conn,
                                                        DeadlightRequest *request,
                                                        GError **error) {
    if (!g_str_equal(request->method, "POST") || !g_str_has_suffix(request->uri, "/send")) {
        return api_send_404(conn, error);
    }

    GError *parse_error = NULL;
    JsonObject *obj = parse_request_body(conn, &parse_error);
    if (!obj) {
        gchar *err_msg = g_strdup_printf("{\"error\":\"%s\"}", 
                                         parse_error ? parse_error->message : "Invalid JSON");
        DeadlightHandlerResult result = api_send_json_response(conn, 400, "Bad Request", err_msg, error);
        g_free(err_msg);
        if (parse_error) g_error_free(parse_error);
        return result;
    }

    // Validate required fields
    const gchar *required[] = {"to", "body"};
    if (!validate_json_fields(obj, required, 2, &parse_error)) {
        gchar *err_msg = g_strdup_printf("{\"error\":\"%s\"}", parse_error->message);
        DeadlightHandlerResult result = api_send_json_response(conn, 400, "Bad Request", err_msg, error);
        g_free(err_msg);
        g_error_free(parse_error);
        json_object_unref(obj);
        return result;
    }

    const gchar *to = json_object_get_string_member(obj, "to");
    const gchar *from = json_object_has_member(obj, "from") 
                      ? json_object_get_string_member(obj, "from")
                      : "noreply@deadlight.boo";
    const gchar *subject = json_object_has_member(obj, "subject")
                         ? json_object_get_string_member(obj, "subject")
                         : "Message from Deadlight";
    const gchar *body = json_object_get_string_member(obj, "body");

    GError *send_error = NULL;
    gboolean sent = email_send_via_mailchannels(conn, from, to, subject, body, &send_error);
    
    DeadlightHandlerResult result;
    if (sent) {
        result = api_send_json_response(conn, 200, "OK",
            "{\"status\":\"sent\",\"provider\":\"mailchannels\"}", error);
    } else {
        gchar *err_json = g_strdup_printf(
            "{\"error\":\"Failed to send email: %s\"}",
            send_error ? send_error->message : "unknown error");
        result = api_send_json_response(conn, 502, "Bad Gateway", err_json, error);
        g_free(err_json);
    }

    if (send_error) g_error_free(send_error);
    json_object_unref(obj);
    return result;
}

static DeadlightHandlerResult api_handle_outbound_email(DeadlightConnection *conn,
                                                        DeadlightRequest *request,
                                                        GError **error) {
    if (!g_str_equal(request->method, "POST")) {
        return api_send_json_response(conn, 405, "Method Not Allowed",
                                     "{\"error\":\"POST required\"}", error);
    }

    g_info("API: Outbound email request from %s", conn->client_address);

    // Parse JSON body
    GError *parse_error = NULL;
    JsonObject *obj = parse_request_body(conn, &parse_error);
    if (!obj) {
        gchar *err_msg = g_strdup_printf("{\"error\":\"%s\"}", 
                                         parse_error ? parse_error->message : "Invalid JSON");
        DeadlightHandlerResult result = api_send_json_response(conn, 400, "Bad Request", err_msg, error);
        g_free(err_msg);
        if (parse_error) g_error_free(parse_error);
        return result;
    }

    // Validate required fields
    const gchar *required[] = {"from", "to", "subject", "body"};
    if (!validate_json_fields(obj, required, 4, &parse_error)) {
        gchar *err_msg = g_strdup_printf("{\"error\":\"%s\"}", parse_error->message);
        DeadlightHandlerResult result = api_send_json_response(conn, 400, "Bad Request", err_msg, error);
        g_free(err_msg);
        g_error_free(parse_error);
        json_object_unref(obj);
        return result;
    }

    const gchar *from = json_object_get_string_member(obj, "from");
    const gchar *to = json_object_get_string_member(obj, "to");
    const gchar *subject = json_object_get_string_member(obj, "subject");
    const gchar *body = json_object_get_string_member(obj, "body");

    // Additional validation
    if (strlen(to) == 0) {
        json_object_unref(obj);
        return api_send_json_response(conn, 400, "Bad Request",
                                     "{\"error\":\"'to' field cannot be empty\"}", error);
    }

    // Ensure request->body is populated for HMAC validation
    if (!request->body || request->body->len == 0) {
        const gchar *body_start = strstr((gchar*)conn->client_buffer->data, "\r\n\r\n");
        if (body_start) {
            body_start += 4;
            gsize body_len = conn->client_buffer->len - (body_start - (gchar*)conn->client_buffer->data);
            request->body = g_byte_array_sized_new(body_len);
            g_byte_array_append(request->body, (const guint8*)body_start, body_len);
        }
    }

    // HMAC authentication
    const gchar *auth_header = deadlight_request_get_header(request, "Authorization");
    
    // Debug HMAC validation
    if (g_getenv("DEADLIGHT_DEBUG_HMAC")) {
        g_info("HMAC Debug Info:");
        g_info("  Auth header: %s", auth_header ? auth_header : "NULL");
        g_info("  Body length: %zu bytes", request->body->len);
        g_info("  Secret length: %zu bytes", strlen(conn->context->auth_secret));
        
        // Show first 50 bytes of body
        gchar *body_preview = g_strndup((gchar*)request->body->data, MIN(50, request->body->len));
        g_info("  Body preview: %s", body_preview);
        g_free(body_preview);
    }
    
    if (!auth_header || !validate_hmac_bytes(auth_header, request->body->data, 
                                             request->body->len, conn->context->auth_secret)) {
        g_warning("HMAC validation failed for outbound email");
        g_warning("  Received header: %s", auth_header ? auth_header : "missing");
        g_warning("  Expected: Check payload matches exactly (no whitespace changes)");
        json_object_unref(obj);
        return api_send_json_response(conn, 401, "Unauthorized",
                                     "{\"error\":\"Invalid credentials\"}", error);
    }

    g_info("HMAC validated successfully - sending email");

    // Send email
    GError *send_error = NULL;
    gboolean sent = email_send_via_mailchannels(conn, from, to, subject, body, &send_error);
    
    DeadlightHandlerResult result;
    if (sent) {
        g_info("API: Email sent successfully to %s", to);
        result = api_send_json_response(conn, 202, "Accepted",
                                       "{\"status\":\"sent\",\"provider\":\"mailchannels\"}", error);
    } else {
        g_warning("API: Failed to send email via MailChannels: %s", 
                  send_error ? send_error->message : "unknown");
        result = api_send_json_response(conn, 502, "Bad Gateway",
                                       "{\"error\":\"Email provider failed\"}", error);
    }

    if (send_error) g_error_free(send_error);
    json_object_unref(obj);
    return result;
}

static DeadlightHandlerResult api_handle_blog_endpoint(DeadlightConnection *conn, 
                                                       DeadlightRequest *request, 
                                                       GError **error) {
    g_info("API blog endpoint for conn %lu: %s %s", conn->id, request->method, request->uri);
    
    // TODO: Integrate with blog.deadlight Cloudflare Workers backend
    // TODO: Add authentication for write operations
    
    if (g_str_equal(request->method, "POST") && g_str_has_suffix(request->uri, "/publish")) {
        const gchar *json_response = 
            "{\"status\":\"success\",\"message\":\"Post published successfully\","
            "\"note\":\"Blog integration not yet implemented\"}";
        return api_send_json_response(conn, 501, "Not Implemented", json_response, error);
    }
    else if (g_str_equal(request->method, "GET") && g_str_has_suffix(request->uri, "/posts")) {
        const gchar *json_response = "{\"posts\":[],\"total\":0}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
    }
    else if (g_str_equal(request->method, "GET") && g_str_has_suffix(request->uri, "/status")) {
        const gchar *json_response = 
            "{\"status\":\"running\",\"version\":\"4.0.0\",\"backend\":\"not_connected\"}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
    }
    
    return api_send_404(conn, error);
}

static DeadlightHandlerResult api_handle_metrics_endpoint(DeadlightConnection *conn, 
                                                          GError **error) {
    DeadlightContext *ctx = conn->context;
    g_info("API metrics endpoint for conn %lu", conn->id);

    if (!ctx) {
        return api_send_json_response(conn, 500, "Internal Server Error",
                                     "{\"error\":\"NULL context\"}", error);
    }

    // Count active connections by protocol
    gint protocol_counts[13] = {0}; // Array indexed by DeadlightProtocol enum
    
    if (ctx->connections) {
        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, ctx->connections);
        
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            DeadlightConnection *active_conn = (DeadlightConnection*)value;
            if (active_conn && active_conn->protocol < 13) {
                protocol_counts[active_conn->protocol]++;
            }
        }
    }

    GString *json = g_string_new(NULL);
    g_string_append(json, "{");

    // Basic metrics
    g_string_append_printf(json,
        "\"active_connections\":%d,"
        "\"total_connections\":%d,"
        "\"bytes_transferred\":%ld,",
        ctx->active_connections,
        ctx->total_connections,
        ctx->bytes_transferred
    );

    // Uptime
    double uptime = 0.0;
    if (ctx->uptime_timer) {
        uptime = g_timer_elapsed(ctx->uptime_timer, NULL);
    }
    g_string_append_printf(json, "\"uptime\":%.2f,", uptime);

    // Connection pool stats
    if (ctx->conn_pool) {
        guint idle, active;
        guint64 total_gets, hits, evicted, failed;
        gdouble hit_rate;
        
        connection_pool_get_stats(ctx->conn_pool, &idle, &active, 
                                 &total_gets, &hits, &hit_rate, &evicted, &failed);
        
        g_string_append(json, "\"connection_pool\":{");
        g_string_append_printf(json, "\"idle\":%u,", idle);
        g_string_append_printf(json, "\"active\":%u,", active);
        g_string_append_printf(json, "\"total_requests\":%lu,", total_gets);
        g_string_append_printf(json, "\"cache_hits\":%lu,", hits);
        g_string_append_printf(json, "\"hit_rate\":%.2f,", hit_rate * 100);
        g_string_append_printf(json, "\"evicted\":%lu,", evicted);
        g_string_append_printf(json, "\"failed\":%lu", failed);
        g_string_append(json, "},");
    }

    // Protocol summary with real counts
    g_string_append(json, "\"protocols\":{");
    g_string_append_printf(json, "\"HTTP\":{\"active\":%d},", 
                          protocol_counts[DEADLIGHT_PROTOCOL_HTTP]);
    g_string_append_printf(json, "\"HTTPS\":{\"active\":%d},", 
                          protocol_counts[DEADLIGHT_PROTOCOL_HTTPS]);
    g_string_append_printf(json, "\"WebSocket\":{\"active\":%d},", 
                          protocol_counts[DEADLIGHT_PROTOCOL_WEBSOCKET]);
    g_string_append_printf(json, "\"SOCKS\":{\"active\":%d},", 
                          protocol_counts[DEADLIGHT_PROTOCOL_SOCKS]);
    g_string_append_printf(json, "\"SMTP\":{\"active\":%d},", 
                          protocol_counts[DEADLIGHT_PROTOCOL_SMTP]);
    g_string_append_printf(json, "\"IMAP\":{\"active\":%d},", 
                          protocol_counts[DEADLIGHT_PROTOCOL_IMAP]);
    g_string_append_printf(json, "\"FTP\":{\"active\":%d},", 
                          protocol_counts[DEADLIGHT_PROTOCOL_FTP]);
    g_string_append_printf(json, "\"API\":{\"active\":%d}", 
                          protocol_counts[DEADLIGHT_PROTOCOL_API]);
    g_string_append(json, "},");

    // Server info
    g_string_append(json, "\"server_info\":{");
    g_string_append_printf(json, "\"version\":\"%s\",", DEADLIGHT_VERSION_STRING);
    g_string_append_printf(json, "\"port\":%d,", ctx->listen_port);
    g_string_append_printf(json, "\"ssl_intercept\":%s,", 
                          ctx->ssl_intercept_enabled ? "true" : "false");
    g_string_append_printf(json, "\"max_connections\":%d", ctx->max_connections);
    g_string_append(json, "}");

    g_string_append(json, "}");

    DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json->str, error);
    g_string_free(json, TRUE);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// FEDERATION IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════

static DeadlightHandlerResult api_federation_send(DeadlightConnection *conn, 
                                                  DeadlightRequest *request, 
                                                  GError **error) {
    g_info("API federation send for conn %lu", conn->id);

    GError *parse_error = NULL;
    JsonObject *obj = parse_request_body(conn, &parse_error);
    if (!obj) {
        gchar *err_msg = g_strdup_printf("{\"error\":\"%s\"}", 
                                         parse_error ? parse_error->message : "Invalid JSON");
        DeadlightHandlerResult result = api_send_json_response(conn, 400, "Bad Request", err_msg, error);
        g_free(err_msg);
        if (parse_error) g_error_free(parse_error);
        return result;
    }

    // Validate required fields
    const gchar *required[] = {"target_domain", "content", "author"};
    if (!validate_json_fields(obj, required, 3, &parse_error)) {
        gchar *err_msg = g_strdup_printf("{\"error\":\"%s\"}", parse_error->message);
        DeadlightHandlerResult result = api_send_json_response(conn, 400, "Bad Request", err_msg, error);
        g_free(err_msg);
        g_error_free(parse_error);
        json_object_unref(obj);
        return result;
    }

    const gchar *target_domain = json_object_get_string_member(obj, "target_domain");
    const gchar *content = json_object_get_string_member(obj, "content");
    const gchar *author = json_object_get_string_member(obj, "author");

    // Construct federation email
    gchar *subject = g_strdup_printf("[Federation] Post from %s", author);
    gchar *to_address = g_strdup_printf("federation@%s", target_domain);
    
    // Send via email transport
    GError *send_error = NULL;
    gboolean sent = email_send_via_mailchannels(conn, "federation@deadlight.boo",
                                                to_address, subject, content, &send_error);
    
    DeadlightHandlerResult result;
    if (sent) {
        g_info("Federation: Sent post to %s", target_domain);
        result = api_send_json_response(conn, 200, "OK",
            "{\"status\":\"sent\",\"transport\":\"email\"}", error);
    } else {
        g_warning("Federation: Failed to send to %s: %s", target_domain,
                  send_error ? send_error->message : "unknown");
        gchar *err_json = g_strdup_printf(
            "{\"error\":\"Federation send failed: %s\"}",
            send_error ? send_error->message : "unknown");
        result = api_send_json_response(conn, 502, "Bad Gateway", err_json, error);
        g_free(err_json);
    }

    g_free(subject);
    g_free(to_address);
    if (send_error) g_error_free(send_error);
    json_object_unref(obj);
    return result;
}

static DeadlightHandlerResult api_federation_receive(DeadlightConnection *conn, 
                                                     DeadlightRequest *request, 
                                                     GError **error) {
    g_info("API federation receive for conn %lu", conn->id);
    
    const gchar *from_header = deadlight_request_get_header(request, "From");
    if (from_header) {
        g_info("Federation: Received content from %s", from_header);
    }
    
    // Parse the incoming federated content
    GError *parse_error = NULL;
    JsonObject *obj = parse_request_body(conn, &parse_error);
    if (!obj) {
        gchar *err_msg = g_strdup_printf("{\"error\":\"%s\"}", 
                                         parse_error ? parse_error->message : "Invalid JSON");
        DeadlightHandlerResult result = api_send_json_response(conn, 400, "Bad Request", err_msg, error);
        g_free(err_msg);
        if (parse_error) g_error_free(parse_error);
        return result;
    }
    
    // Extract content and author
    const gchar *content = json_object_has_member(obj, "content") 
                         ? json_object_get_string_member(obj, "content") : "";
    const gchar *author = json_object_has_member(obj, "author")
                        ? json_object_get_string_member(obj, "author") : "unknown";
    
    // Store federated content to file
    const gchar *storage_dir = "/var/lib/deadlight/federation";
    g_mkdir_with_parents(storage_dir, 0755);
    
    // Create timestamped filename
    time_t now = time(NULL);
    gchar *filename = g_strdup_printf("%s/post_%ld_%s.json", 
                                      storage_dir, now, author);
    
    // Build storage object with metadata
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "timestamp");
    json_builder_add_int_value(builder, now);
    json_builder_set_member_name(builder, "from");
    json_builder_add_string_value(builder, from_header ? from_header : "unknown");
    json_builder_set_member_name(builder, "author");
    json_builder_add_string_value(builder, author);
    json_builder_set_member_name(builder, "content");
    json_builder_add_string_value(builder, content);
    json_builder_end_object(builder);
    
    JsonGenerator *gen = json_generator_new();
    json_generator_set_pretty(gen, TRUE);
    JsonNode *root = json_builder_get_root(builder);
    json_generator_set_root(gen, root);
    
    GError *write_error = NULL;
    gboolean stored = json_generator_to_file(gen, filename, &write_error);
    
    gchar *response_json;
    gint status_code;
    
    if (stored) {
        g_info("Federation: Stored post from %s to %s", author, filename);
        response_json = g_strdup_printf(
            "{\"status\":\"received\",\"queued\":true,\"stored\":\"%s\",\"from\":\"%s\"}",
            filename, from_header ? from_header : "unknown");
        status_code = 200;
    } else {
        g_warning("Federation: Failed to store post: %s", 
                  write_error ? write_error->message : "unknown");
        response_json = g_strdup(
            "{\"status\":\"received\",\"queued\":false,\"error\":\"Storage failed\"}");
        status_code = 500;
    }
    
    DeadlightHandlerResult result = api_send_json_response(conn, status_code, 
        status_code == 200 ? "OK" : "Internal Server Error", response_json, error);
    
    g_free(response_json);
    g_free(filename);
    if (write_error) g_error_free(write_error);
    json_node_unref(root);
    g_object_unref(gen);
    g_object_unref(builder);
    json_object_unref(obj);
    
    return result;
}

static DeadlightHandlerResult api_federation_test_domain(DeadlightConnection *conn, 
                                                         const gchar *domain, 
                                                         GError **error) {
    g_info("API federation domain test for: %s", domain);
    
    // Test connectivity via DNS + TCP probe
    GResolver *resolver = g_resolver_get_default();
    GError *lookup_error = NULL;
    GList *addresses = g_resolver_lookup_by_name(resolver, domain, NULL, &lookup_error);
    
    gboolean reachable = FALSE;
    const gchar *status = "unknown";
    
    if (addresses) {
        // Try to connect to SMTP port (587 or 25)
        GSocketClient *client = g_socket_client_new();
        g_socket_client_set_timeout(client, 5); // 5 second timeout
        
        GError *connect_error = NULL;
        GSocketConnection *test_conn = g_socket_client_connect_to_host(
            client, domain, 587, NULL, &connect_error);
        
        if (test_conn) {
            reachable = TRUE;
            status = "verified";
            g_object_unref(test_conn);
        } else {
            // Try port 25 as fallback
            g_clear_error(&connect_error);
            test_conn = g_socket_client_connect_to_host(client, domain, 25, NULL, &connect_error);
            if (test_conn) {
                reachable = TRUE;
                status = "verified";
                g_object_unref(test_conn);
            } else {
                status = "unreachable";
            }
        }
        
        if (connect_error) g_error_free(connect_error);
        g_object_unref(client);
        g_list_free_full(addresses, g_object_unref);
    } else {
        status = "dns_failed";
        g_info("Federation test: DNS lookup failed for %s: %s", 
               domain, lookup_error ? lookup_error->message : "unknown");
    }
    
    if (lookup_error) g_error_free(lookup_error);
    g_object_unref(resolver);
    
    gchar *json_response = g_strdup_printf(
        "{\"domain\":\"%s\",\"status\":\"%s\",\"trust_level\":\"%s\","
        "\"test_time\":%ld,\"active\":%s}", 
        domain, status, reachable ? "verified" : "unverified",
        time(NULL), reachable ? "true" : "false");
    
    DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json_response, error);
    g_free(json_response);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// EMAIL SENDING VIA MAILCHANNELS
// ═══════════════════════════════════════════════════════════════════════════

static gboolean
email_send_via_mailchannels(DeadlightConnection *conn,
                            const gchar *from,
                            const gchar *to,
                            const gchar *subject,
                            const gchar *body,
                            GError **error)
{
    g_info("Email: Sending via MailChannels API to %s", to);

    const gchar *api_key = deadlight_config_get_string(conn->context, "smtp", 
                                                       "mailchannels_api_key", NULL);
    if (!api_key || api_key[0] == '\0') {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Missing mailchannels_api_key in [smtp] section");
        return FALSE;
    }

    // Create a minimal temporary connection object for the MailChannels request
    // We do NOT reuse the client connection to avoid state pollution
    DeadlightConnection *mc_conn = g_new0(DeadlightConnection, 1);
    mc_conn->context = conn->context;
    mc_conn->target_host = g_strdup("api.mailchannels.net");
    mc_conn->target_port = 443;
    mc_conn->will_use_ssl = TRUE;
    mc_conn->id = conn->id; // Inherit ID for logging
    
    // Connect (uses the connection pool automatically)
    if (!deadlight_network_connect_upstream(mc_conn, error)) {
        g_prefix_error(error, "Failed to connect to MailChannels: ");
        g_free(mc_conn->target_host);
        g_free(mc_conn);
        return FALSE;
    }

    // Verify TLS was established
    if (!mc_conn->upstream_tls) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "TLS not established for MailChannels HTTPS");
        g_free(mc_conn->target_host);
        g_free(mc_conn);
        return FALSE;
    }

    GIOStream *upstream_io = G_IO_STREAM(mc_conn->upstream_tls);
    GOutputStream *out = g_io_stream_get_output_stream(upstream_io);
    GInputStream *in = g_io_stream_get_input_stream(upstream_io);

    // Build JSON payload
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);

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

    json_builder_set_member_name(builder, "from");
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "email");
    json_builder_add_string_value(builder, from);
    json_builder_set_member_name(builder, "name");
    json_builder_add_string_value(builder, "Deadlight");
    json_builder_end_object(builder);

    json_builder_set_member_name(builder, "subject");
    json_builder_add_string_value(builder, subject);

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

    JsonGenerator *gen = json_generator_new();
    JsonNode *root = json_builder_get_root(builder);
    json_generator_set_root(gen, root);
    gchar *json_payload = json_generator_to_data(gen, NULL);

    // Build HTTP request
    GString *request = g_string_new(NULL);
    g_string_append(request, "POST /tx/v1/send HTTP/1.1\r\n");
    g_string_append(request, "Host: api.mailchannels.net\r\n");
    g_string_append(request, "Content-Type: application/json\r\n");
    g_string_append_printf(request, "Content-Length: %zu\r\n", strlen(json_payload));
    g_string_append_printf(request, "X-API-Key: %s\r\n", api_key);
    g_string_append(request, "Connection: keep-alive\r\n");
    g_string_append(request, "\r\n");
    g_string_append(request, json_payload);

    g_info("Email: Sending %zu bytes to MailChannels (pool-aware)", request->len);

    gboolean success = FALSE;
    gsize written;
    
    // Send request
    if (!g_output_stream_write_all(out, request->str, request->len, &written, NULL, error)) {
        g_prefix_error(error, "Failed to write to MailChannels: ");
        goto cleanup;
    }

    // Read response
    gchar buf[8192] = {0};
    gssize read_len = g_input_stream_read(in, buf, sizeof(buf)-1, NULL, error);
    
    if (read_len > 0) {
        buf[read_len] = '\0';
        
        if (strstr(buf, "202 Accepted") || strstr(buf, "200 OK")) {
            g_info("Email: Successfully sent via MailChannels");
            success = TRUE;
            
            // Release connection back to pool for reuse
            mc_conn->state = DEADLIGHT_STATE_CONNECTED;
            deadlight_network_release_to_pool(mc_conn, "MailChannels email sent");
        } else {
            g_warning("Email: MailChannels rejected request:\n%s", buf);
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, 
                       "MailChannels rejected the email");
        }
    } else {
        g_prefix_error(error, "Failed to read MailChannels response: ");
    }

cleanup:
    g_string_free(request, TRUE);
    g_free(json_payload);
    json_node_unref(root);
    g_object_unref(gen);
    g_object_unref(builder);
    
    // Cleanup temporary connection struct
    // Note: upstream_connection is either pooled or will be cleaned up by network layer
    g_free(mc_conn->target_host);
    g_free(mc_conn);

    return success;
}

// ═══════════════════════════════════════════════════════════════════════════
// RESPONSE HELPERS
// ═══════════════════════════════════════════════════════════════════════════

static DeadlightHandlerResult api_send_404(DeadlightConnection *conn, GError **error) {
    const gchar *response = 
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 34\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"error\":\"API endpoint not found\"}";
    
    GOutputStream *client_os = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->client_connection));
    
    if (!g_output_stream_write_all(client_os, response, strlen(response), NULL, NULL, error)) {
        g_warning("API conn %lu: Failed to send 404 response", conn->id);
        return HANDLER_ERROR;
    }
    
    return HANDLER_SUCCESS_CLEANUP_NOW;
}

static DeadlightHandlerResult api_send_json_response(DeadlightConnection *conn, 
                                                     gint status_code, 
                                                     const gchar *status_text, 
                                                     const gchar *json_body, 
                                                     GError **error) {
    GOutputStream *client_os = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->client_connection));
    
    gchar *response = g_strdup_printf(
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: https://deadlight.boo\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, X-API-Key, Authorization\r\n"
        "Content-Encoding: identity\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", 
        status_code, status_text, strlen(json_body), json_body);

    g_debug("API conn %lu: Sending response (%zu bytes)", conn->id, strlen(response));
    
    gboolean write_success = g_output_stream_write_all(client_os, response, 
                                                        strlen(response), NULL, NULL, error);
    if (!write_success) {
        g_warning("API conn %lu: Failed to write response: %s", 
                  conn->id, error && *error ? (*error)->message : "unknown error");
    }
    
    g_free(response);
    return write_success ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
}

// ═══════════════════════════════════════════════════════════════════════════
// CLEANUP
// ═══════════════════════════════════════════════════════════════════════════

static void api_cleanup(DeadlightConnection *conn) {
    g_debug("API cleanup called for conn %lu", conn->id);
    // Clean up any API-specific resources if needed
    (void)conn; // Suppress unused parameter warning
}