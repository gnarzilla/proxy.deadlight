#include "api.h"
#include <string.h>
#include <json-glib/json-glib.h>
#include <time.h>
#include <sys/stat.h>  
#include "smtp.h"
#include "plugins/ratelimiter.h"
#include "core/utils.h"   
#include "core/logging.h"

typedef struct {
    gchar *domain;
    gchar *federation_endpoint;
    gchar *public_key;
    gboolean supports_https;
} FederationDiscovery;

// SSE Stream State
#define SSE_STREAM_MAGIC 0x53534500u

typedef struct {
    guint32 magic;                   // Must be SSE_STREAM_MAGIC
    DeadlightConnection *conn;
    GOutputStream *output;
    GSource *update_timer;
    guint64 last_total_connections;
    guint64 last_bytes_transferred;
    gboolean closed;
} SSEStreamState;

// Forward declarations
// Protocol handler
static gsize api_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult api_handle(DeadlightConnection *conn, GError **error);
static void api_cleanup(DeadlightConnection *conn);

// Endpoint handlers
static DeadlightHandlerResult api_handle_system_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_federation_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_email_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_blog_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_outbound_email(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_metrics_endpoint(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult api_handle_logs_endpoint(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult api_handle_dashboard_endpoint(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult api_handle_stream_endpoint(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult api_handle_wellknown_deadlight(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult api_handle_connections_endpoint(DeadlightConnection *conn, GError **error);

// Federation
static DeadlightHandlerResult api_federation_send(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult api_federation_receive(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_federation_test_domain(DeadlightConnection *conn, const gchar *domain, GError **error);
static FederationDiscovery* discover_federated_instance(const gchar *target_domain, GError **error);
static void federation_discovery_free(FederationDiscovery *discovery);

// Email
static gboolean email_send_via_mailchannels(DeadlightConnection *conn, const gchar *from, const gchar *to, const gchar *subject, const gchar *body, GError **error);

// Response helpers
static DeadlightHandlerResult api_send_json_response(DeadlightConnection *conn, gint status_code, const gchar *status_text, const gchar *json_body, GError **error);
static DeadlightHandlerResult api_send_error(DeadlightConnection *conn, gint code, const gchar *status, GError *cause, const gchar *fallback, GError **error);
static DeadlightHandlerResult api_send_404(DeadlightConnection *conn, GError **error);

// JSON / metrics builders
static gchar* api_build_metrics_json(DeadlightContext *ctx);
static gchar* api_build_dashboard_json(DeadlightContext *ctx);

// Cache helpers
static gboolean is_cache_fresh(const gchar *cache_file, gint ttl_seconds);
static gchar* read_cache_file(const gchar *cache_file, GError **error);
static gboolean write_cache_file(const gchar *cache_file, const gchar *content, GError **error);

// HTTP fetch
static gchar* http_get_raw(const gchar *host, guint16 port, gboolean use_tls, const gchar *path, guint timeout_seconds, GError **error);
static gchar* fetch_from_workers(const gchar *workers_url, const gchar *endpoint, GError **error);

// Request helpers
static JsonObject* parse_request_body(DeadlightConnection *conn, GError **error);
static gboolean validate_json_fields(JsonObject *obj, const gchar **required_fields, gsize num_fields, GError **error);

// SSE
static gboolean sse_send_update(gpointer user_data);
static void sse_stream_cleanup(SSEStreamState *state);
static gboolean sse_send_event(GOutputStream *out, const gchar *event_type, const gchar *data, GError **error);
static void api_cleanup_sse_stream(DeadlightConnection *conn);

// Prometheus (called from http.c)
DeadlightHandlerResult api_handle_prometheus_metrics(DeadlightConnection *conn, GError **error);


// Federation discovery implementation
static FederationDiscovery* discover_federated_instance(const gchar *target_domain, GError **error) {
    g_info("Federation: Discovering instance at %s", target_domain);
    
    // Try HTTPS discovery first
    GSocketClient *client = g_socket_client_new();
    g_socket_client_set_tls(client, TRUE);
    g_socket_client_set_timeout(client, 10);
    
    GSocketConnection *conn = g_socket_client_connect_to_host(client, target_domain, 443, NULL, error);
    g_object_unref(client);
    
    if (!conn) {
        g_prefix_error(error, "Failed to connect to %s: ", target_domain);
        return NULL;
    }
    
    // Build HTTP request
    GString *request = g_string_new(NULL);
    g_string_append(request, "GET /.well-known/deadlight HTTP/1.1\r\n");
    g_string_append_printf(request, "Host: %s\r\n", target_domain);
    g_string_append(request, "Connection: close\r\n");
    g_string_append(request, "\r\n");
    
    // Send request
    GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(conn));
    gsize written;
    if (!g_output_stream_write_all(out, request->str, request->len, &written, NULL, error)) {
        g_string_free(request, TRUE);
        g_object_unref(conn);
        return NULL;
    }
    g_string_free(request, TRUE);
    
    // Read response
    GInputStream *in = g_io_stream_get_input_stream(G_IO_STREAM(conn));
    GString *response = g_string_new(NULL);
    gchar buf[4096];
    gssize bytes_read;
    
    while ((bytes_read = g_input_stream_read(in, buf, sizeof(buf), NULL, error)) > 0) {
        g_string_append_len(response, buf, bytes_read);
    }
    
    g_object_unref(conn);
    
    if (bytes_read < 0) {
        g_string_free(response, TRUE);
        return NULL;
    }
    
    // Extract JSON body
    const gchar *body_start = strstr(response->str, "\r\n\r\n");
    if (!body_start) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid HTTP response");
        g_string_free(response, TRUE);
        return NULL;
    }
    body_start += 4;
    
    // Parse JSON
    JsonParser *parser = json_parser_new();
    if (!json_parser_load_from_data(parser, body_start, -1, error)) {
        g_object_unref(parser);
        g_string_free(response, TRUE);
        return NULL;
    }
    
    JsonNode *root = json_parser_get_root(parser);
    if (!JSON_NODE_HOLDS_OBJECT(root)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Response is not JSON object");
        g_object_unref(parser);
        g_string_free(response, TRUE);
        return NULL;
    }
    
    JsonObject *obj = json_node_get_object(root);
    
    FederationDiscovery *discovery = g_new0(FederationDiscovery, 1);
    
    if (json_object_has_member(obj, "federation")) {
        JsonObject *fed_obj = json_object_get_object_member(obj, "federation");
        if (json_object_has_member(fed_obj, "inbox")) {
            discovery->federation_endpoint = g_strdup(json_object_get_string_member(fed_obj, "inbox"));
        }
    }

    // Fallback if the above fails
    if (!discovery->federation_endpoint) {
        if (json_object_has_member(obj, "federation_endpoint")) {
            discovery->federation_endpoint = g_strdup(json_object_get_string_member(obj, "federation_endpoint"));
        } else {
            discovery->federation_endpoint = g_strdup_printf("https://%s/api/federation/inbox", target_domain);
        }
    }
    
    discovery->supports_https = TRUE;
    
    if (json_object_has_member(obj, "public_key")) {
        discovery->public_key = g_strdup(json_object_get_string_member(obj, "public_key"));
    }
    
    g_object_unref(parser);
    g_string_free(response, TRUE);
    
    g_info("Federation: Discovered %s at %s", discovery->domain, discovery->federation_endpoint);
    
    return discovery;
}

static void federation_discovery_free(FederationDiscovery *discovery) {
    if (!discovery) return;
    g_free(discovery->domain);
    g_free(discovery->federation_endpoint);
    g_free(discovery->public_key);
    g_free(discovery);
}

// Well-known endpoint handler
static DeadlightHandlerResult api_handle_wellknown_deadlight(DeadlightConnection *conn, GError **error) {
    const gchar *our_domain = deadlight_config_get_string(conn->context, "federation", 
                                                          "domain", "proxy.deadlight.boo");
    
    gchar *json_response = g_strdup_printf(
        "{"
        "\"instance\":\"%s\","
        "\"federation_endpoint\":\"https://%s/api/federation/receive\","
        "\"protocols\":[\"https\",\"smtp\"],"
        "\"version\":\"1.0.0\","
        "\"public_key\":null"
        "}", our_domain, our_domain);
    
    DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json_response, error);
    g_free(json_response);
    return result;
}

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

    // Fast path: method + /api/ prefix
    if ((len >= 9  && memcmp(data, "GET /api/",     9)  == 0) ||
        (len >= 10 && memcmp(data, "POST /api/",    10) == 0) ||
        (len >= 9  && memcmp(data, "PUT /api/",     9)  == 0) ||
        (len >= 12 && memcmp(data, "DELETE /api/",  12) == 0) ||
        (len >= 13 && memcmp(data, "OPTIONS /api/", 13) == 0)) {
        return 100;
    }

    // /.well-known/deadlight — was checking len >= 24 against 26-byte string
    if (len >= 26 && memcmp(data, "GET /.well-known/deadlight", 26) == 0) {
        return 100;
    }

    // Slow path: absolute URI with /api/ anywhere in first line
    const guint8 *ptr = data;
    const guint8 *end = data + MIN(len, 512);

    while (ptr < end && *ptr != '\r' && *ptr != '\n') {
        if ((gsize)(end - ptr) >= 5 && memcmp(ptr, "/api/", 5) == 0) {
            g_debug("API detect: absolute URI match");
            return 100;
        }
        ptr++;
    }

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

static DeadlightHandlerResult api_send_error(DeadlightConnection *conn,
                                              gint code,
                                              const gchar *status,
                                              GError *cause,
                                              const gchar *fallback,
                                              GError **error) {
    const gchar *message = (cause && cause->message) ? cause->message : fallback;

    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "error");
    json_builder_add_string_value(builder, message);
    json_builder_end_object(builder);

    JsonGenerator *gen = json_generator_new();
    JsonNode *root = json_builder_get_root(builder);
    json_generator_set_root(gen, root);
    gchar *body = json_generator_to_data(gen, NULL);

    DeadlightHandlerResult result = api_send_json_response(conn, code, status, body, error);

    g_free(body);
    json_node_unref(root);
    g_object_unref(gen);
    g_object_unref(builder);
    if (cause) g_error_free(cause);

    return result;
}

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

    // Debug: show raw request
    gchar *preview = g_strndup((gchar *)conn->client_buffer->data,
                                MIN(conn->client_buffer->len, 500));
    g_debug("API conn %lu: Raw request (%u bytes):\n%s",
            conn->id, conn->client_buffer->len, preview);
    g_free(preview);

    // Parse HTTP request — single call, was duplicated before
    DeadlightRequest *request = deadlight_request_new(conn);
    gchar *request_str = g_strndup((gchar *)conn->client_buffer->data,
                                    conn->client_buffer->len);

    if (!deadlight_request_parse_headers(request, request_str, strlen(request_str))) {
        g_warning("API conn %lu: Failed to parse request headers", conn->id);
        g_free(request_str);
        deadlight_request_free(request);
        return HANDLER_ERROR;
    }
    g_free(request_str);

    conn->current_request = request;

    g_debug("API conn %lu: Method='%s' URI='%s' body=%u bytes",
            conn->id, request->method, request->uri,
            request->body ? request->body->len : 0);

    // Rate limit check
    if (conn->context->plugins_data) {
        gboolean limited = deadlight_ratelimiter_check_request(
            conn->context, conn->client_address, request->uri);

        if (limited) {
            g_warning("API: Rate limit exceeded for %s on %s",
                      conn->client_address, request->uri);

            const gchar *rl_response =
                "HTTP/1.1 429 Too Many Requests\r\n"
                "Content-Type: application/json\r\n"
                "Retry-After: 60\r\n"
                "X-RateLimit-Limit: 60\r\n"
                "X-RateLimit-Remaining: 0\r\n"
                "Content-Length: 48\r\n"
                "\r\n"
                "{\"error\":\"Rate limit exceeded\",\"retry_after\":60}";

            GOutputStream *os = g_io_stream_get_output_stream(
                G_IO_STREAM(conn->client_connection));
            g_output_stream_write_all(os, rl_response, strlen(rl_response),
                                      NULL, NULL, error);

            conn->current_request = NULL;
            deadlight_request_free(request);
            return HANDLER_SUCCESS_CLEANUP_NOW;
        }
    }

    // CORS preflight
    if (g_str_equal(request->method, "OPTIONS")) {
        const gchar *cors =
            "HTTP/1.1 200 OK\r\n"
            "Access-Control-Allow-Origin: https://deadlight.boo\r\n"
            "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, X-API-Key, Authorization\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        GOutputStream *os = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(os, cors, strlen(cors), NULL, NULL, error);
        conn->current_request = NULL;
        deadlight_request_free(request);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    DeadlightHandlerResult result;
    const gchar *uri = request->uri;

    // ── Route table ──────────────────────────────────────────────────────
    if (g_str_equal(uri, "/api/health")) {
        gchar *body = g_strdup_printf(
            "{\"status\":\"ok\",\"version\":\"%s\","
            "\"timestamp\":%ld,\"proxy\":\"deadlight\"}",
            DEADLIGHT_VERSION_STRING, time(NULL));
        result = api_send_json_response(conn, 200, "OK", body, error);
        g_free(body);
    }
    else if (g_str_equal(uri, "/.well-known/deadlight")) {
        result = api_handle_wellknown_deadlight(conn, error);
    }
    else if (g_str_equal(uri, "/api/connections")) {
        result = api_handle_connections_endpoint(conn, error);
    }
    else if (g_str_has_prefix(uri, "/api/system/")) {
        result = api_handle_system_endpoint(conn, request, error);
    }
    else if (g_str_has_prefix(uri, "/api/email/")) {
        result = api_handle_email_endpoint(conn, request, error);
    }
    else if (g_str_has_prefix(uri, "/api/outbound/email")) {
        result = api_handle_outbound_email(conn, request, error);
    }
    else if (g_str_has_prefix(uri, "/api/blog/")) {
        result = api_handle_blog_endpoint(conn, request, error);
    }
    else if (g_str_has_prefix(uri, "/api/federation/")) {
        result = api_handle_federation_endpoint(conn, request, error);
    }
    else if (g_str_equal(uri, "/api/logs")) {
        result = api_handle_logs_endpoint(conn, error);
    }
    else if (g_str_equal(uri, "/api/dashboard")) {
        result = api_handle_dashboard_endpoint(conn, error);
    }
    else if (g_str_equal(uri, "/api/stream")) {
        result = api_handle_stream_endpoint(conn, error);
    }
    else if (g_str_has_prefix(uri, "/api/metrics")) {
        result = api_handle_metrics_endpoint(conn, error);
    }
    else {
        g_debug("API: No route for URI: %s", uri);
        result = api_send_404(conn, error);
    }
    // ── End route table ──────────────────────────────────────────────────

    conn->current_request = NULL;
    deadlight_request_free(request);
    return result;
}

/**
 * Perform a simple HTTP/HTTPS GET request and return the response body.
 * Caller must g_free() the returned string.
 * Returns NULL on failure with error set.
 */
static gchar* http_get_raw(const gchar *host,
                            guint16 port,
                            gboolean use_tls,
                            const gchar *path,
                            guint timeout_seconds,
                            GError **error) {
    GSocketClient *client = g_socket_client_new();
    g_socket_client_set_timeout(client, timeout_seconds);
    if (use_tls) {
        g_socket_client_set_tls(client, TRUE);
    }

    GSocketConnection *conn = g_socket_client_connect_to_host(
        client, host, port, NULL, error);
    g_object_unref(client);

    if (!conn) {
        g_prefix_error(error, "Failed to connect to %s:%u: ", host, (guint)port);
        return NULL;
    }

    // Build request
    GString *request = g_string_new(NULL);
    g_string_append_printf(request, "GET %s HTTP/1.1\r\n", path);
    g_string_append_printf(request, "Host: %s\r\n", host);
    g_string_append(request, "Connection: close\r\n");
    g_string_append(request, "User-Agent: Deadlight-Proxy/" DEADLIGHT_VERSION_STRING "\r\n");
    g_string_append(request, "\r\n");

    GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(conn));
    gsize written;
    if (!g_output_stream_write_all(out, request->str, request->len,
                                   &written, NULL, error)) {
        g_string_free(request, TRUE);
        g_object_unref(conn);
        g_prefix_error(error, "Failed to write request to %s: ", host);
        return NULL;
    }
    g_string_free(request, TRUE);

    // Read full response
    GInputStream *in = g_io_stream_get_input_stream(G_IO_STREAM(conn));
    GString *response = g_string_new(NULL);
    gchar buf[4096];
    gssize bytes_read;

    while ((bytes_read = g_input_stream_read(in, buf, sizeof(buf), NULL, error)) > 0) {
        g_string_append_len(response, buf, bytes_read);
    }
    g_object_unref(conn);

    if (bytes_read < 0) {
        // error already set by g_input_stream_read
        g_string_free(response, TRUE);
        return NULL;
    }

    // Find body
    const gchar *body_start = strstr(response->str, "\r\n\r\n");
    if (!body_start) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                    "No header/body separator in response from %s", host);
        g_string_free(response, TRUE);
        return NULL;
    }

    gchar *body = g_strdup(body_start + 4);
    g_string_free(response, TRUE);
    return body;
}

// ═══════════════════════════════════════════════════════════════════════════
// LOGGING ENDPOINT
// ═══════════════════════════════════════════════════════════════════════════

static DeadlightHandlerResult api_handle_logs_endpoint(DeadlightConnection *conn, 
                                                       GError **error) {
    // This function is defined in core/logging.h / logging.c
    // Make sure you updated core/logging.h to include the prototype!
    gchar *json_logs = deadlight_logging_get_buffered_json();
    
    if (!json_logs) {
        // Fallback if something went wrong
        return api_send_json_response(conn, 200, "OK", "[]", error);
    }

    DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json_logs, error);
    g_free(json_logs);
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
        gchar *body = g_strdup_printf(
            "{\"external_ip\":\"%s\",\"port\":%d}", ip, conn->context->listen_port);
        DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", body, error);
        g_free(body);
        g_free(ip);
        return result;
    }
    return api_send_404(conn, error);
}

static DeadlightHandlerResult api_handle_federation_endpoint(DeadlightConnection *conn, 
                                                             DeadlightRequest *request, 
                                                             GError **error) {
    if (g_str_equal(request->uri, "/api/federation/send")) {
        return api_federation_send(conn, error);
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
    if (!g_str_equal(request->method, "POST") ||
        !g_str_has_suffix(request->uri, "/send")) {
        return api_send_404(conn, error);
    }

    GError *parse_error = NULL;
    JsonObject *obj = parse_request_body(conn, &parse_error);
    if (!obj) {
        return api_send_error(conn, 400, "Bad Request", parse_error, "Invalid JSON", error);
    }

    GError *validate_error = NULL;
    const gchar *required[] = {"to", "body"};
    if (!validate_json_fields(obj, required, 2, &validate_error)) {
        json_object_unref(obj);
        return api_send_error(conn, 400, "Bad Request", validate_error, "Missing fields", error);
    }

    const gchar *to      = json_object_get_string_member(obj, "to");
    const gchar *from    = json_object_has_member(obj, "from")
                         ? json_object_get_string_member(obj, "from")
                         : "noreply@deadlight.boo";
    const gchar *subject = json_object_has_member(obj, "subject")
                         ? json_object_get_string_member(obj, "subject")
                         : "Message from Deadlight";
    const gchar *body    = json_object_get_string_member(obj, "body");

    GError *send_error = NULL;
    gboolean sent = email_send_via_mailchannels(conn, from, to, subject, body, &send_error);

    DeadlightHandlerResult result;
    if (sent) {
        result = api_send_json_response(conn, 200, "OK",
            "{\"status\":\"sent\",\"provider\":\"mailchannels\"}", error);
    } else {
        result = api_send_error(conn, 502, "Bad Gateway", send_error,
                                "Email send failed", error);
        send_error = NULL; // api_send_error consumed it
    }

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

    GError *parse_error = NULL;
    JsonObject *obj = parse_request_body(conn, &parse_error);
    if (!obj) {
        return api_send_error(conn, 400, "Bad Request", parse_error, "Invalid JSON", error);
    }

    GError *validate_error = NULL;
    const gchar *required[] = {"from", "to", "subject", "body"};
    if (!validate_json_fields(obj, required, 4, &validate_error)) {
        json_object_unref(obj);
        return api_send_error(conn, 400, "Bad Request", validate_error, "Missing fields", error);
    }

    const gchar *from    = json_object_get_string_member(obj, "from");
    const gchar *to      = json_object_get_string_member(obj, "to");
    const gchar *subject = json_object_get_string_member(obj, "subject");
    const gchar *body    = json_object_get_string_member(obj, "body");

    if (strlen(to) == 0) {
        json_object_unref(obj);
        return api_send_json_response(conn, 400, "Bad Request",
                                      "{\"error\":\"'to' field cannot be empty\"}", error);
    }

    // Ensure request->body is populated for HMAC validation
    if (!request->body || request->body->len == 0) {
        const gchar *body_start = strstr((gchar *)conn->client_buffer->data, "\r\n\r\n");
        if (body_start) {
            body_start += 4;
            gsize body_len = conn->client_buffer->len -
                             (body_start - (gchar *)conn->client_buffer->data);
            request->body = g_byte_array_sized_new(body_len);
            g_byte_array_append(request->body, (const guint8 *)body_start, body_len);
        }
    }

    // HMAC authentication
    const gchar *auth_header = deadlight_request_get_header(request, "Authorization");

    if (g_getenv("DEADLIGHT_DEBUG_HMAC")) {
        g_info("HMAC debug — auth: %s, body: %u bytes, secret length: %zu",
               auth_header ? auth_header : "NULL",
               request->body ? request->body->len : 0,
               strlen(conn->context->auth_secret));
    }

    if (!auth_header ||
        !validate_hmac_bytes(auth_header,
                             request->body->data,
                             request->body->len,
                             conn->context->auth_secret)) {
        g_warning("HMAC validation failed — header: %s",
                  auth_header ? auth_header : "missing");
        json_object_unref(obj);
        return api_send_json_response(conn, 401, "Unauthorized",
                                      "{\"error\":\"Invalid credentials\"}", error);
    }

    g_info("HMAC validated — sending email to %s", to);

    GError *send_error = NULL;
    gboolean sent = email_send_via_mailchannels(conn, from, to, subject, body, &send_error);

    DeadlightHandlerResult result;
    if (sent) {
        g_info("API: Email sent to %s", to);
        result = api_send_json_response(conn, 202, "Accepted",
                                        "{\"status\":\"sent\",\"provider\":\"mailchannels\"}",
                                        error);
    } else {
        g_warning("API: MailChannels failed: %s",
                  send_error ? send_error->message : "unknown");
        result = api_send_error(conn, 502, "Bad Gateway", send_error,
                                "Email provider failed", error);
        send_error = NULL; // api_send_error consumed it
    }

    json_object_unref(obj);
    return result;
}

static DeadlightHandlerResult api_handle_blog_endpoint(DeadlightConnection *conn, 
                                                       DeadlightRequest *request, 
                                                       GError **error) {
    g_info("API blog endpoint for conn %lu: %s %s", conn->id, request->method, request->uri);
    
    // Check if caching is enabled
    gboolean enable_cache = deadlight_config_get_bool(conn->context, "blog", "enable_cache", FALSE);
    const gchar *cache_dir = deadlight_config_get_string(conn->context, "blog", "cache_dir", 
                                                         "/var/lib/deadlight/blog");
    gint cache_ttl = deadlight_config_get_int(conn->context, "blog", "cache_ttl", 300);
    
    // Handle /api/blog/posts with caching
    if (g_str_equal(request->method, "GET") && g_str_has_suffix(request->uri, "/posts")) {
        gchar *cache_file = g_build_filename(cache_dir, "posts.json", NULL);
        gchar *response_body = NULL;
        
        // Try cache first if enabled
        if (enable_cache && is_cache_fresh(cache_file, cache_ttl)) {
            g_info("Blog: Cache HIT for /posts (age < %d seconds)", cache_ttl);
            GError *read_error = NULL;
            response_body = read_cache_file(cache_file, &read_error);
            
            if (response_body) {
                DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", 
                                                                       response_body, error);
                g_free(response_body);
                g_free(cache_file);
                return result;
            }
            
            if (read_error) {
                g_warning("Blog: Cache read failed: %s", read_error->message);
                g_error_free(read_error);
            }
        }
        
        // Cache miss or stale - fetch from Workers
        g_info("Blog: Cache MISS for /posts, fetching from Workers");
        const gchar *workers_url = deadlight_config_get_string(conn->context, "blog", 
                                                               "workers_url", NULL);
        
        if (!workers_url) {
            g_free(cache_file);
            return api_send_json_response(conn, 200, "OK", 
                "{\"posts\":[],\"total\":0,\"note\":\"Workers URL not configured\"}", error);
        }
        
        GError *fetch_error = NULL;
        response_body = fetch_from_workers(workers_url, "/api/blog/posts", &fetch_error);
        
        if (response_body) {
            // Update cache if enabled
            if (enable_cache) {
                g_mkdir_with_parents(cache_dir, 0755);
                if (write_cache_file(cache_file, response_body, NULL)) {
                    g_info("Blog: Updated cache for /posts");
                }
            }
            
            DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", 
                                                                   response_body, error);
            g_free(response_body);
            g_free(cache_file);
            return result;
        }
        
        // Fetch failed - try serving stale cache as fallback
        if (enable_cache) {
            g_warning("Blog: Workers fetch failed, trying stale cache: %s", 
                     fetch_error ? fetch_error->message : "unknown");
            
            GError *read_error = NULL;
            response_body = read_cache_file(cache_file, &read_error);
            
            if (response_body) {
                g_info("Blog: Serving STALE cache (offline mode)");
                gchar *response_with_warning = g_strdup_printf(
                    "{\"posts\":%s,\"_warning\":\"Served from stale cache (Workers offline)\"}", 
                    response_body);
                
                DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", 
                                                                       response_with_warning, error);
                g_free(response_with_warning);
                g_free(response_body);
                g_free(cache_file);
                if (read_error) g_error_free(read_error);
                if (fetch_error) g_error_free(fetch_error);
                return result;
            }
            
            if (read_error) g_error_free(read_error);
        }
        
        if (fetch_error) g_error_free(fetch_error);
        g_free(cache_file);
        
        return api_send_json_response(conn, 503, "Service Unavailable",
            "{\"error\":\"Workers unreachable and no cache available\"}", error);
    }
    
    // Handle /api/blog/status
    if (g_str_equal(request->method, "GET") && g_str_has_suffix(request->uri, "/status")) {
        const gchar *workers_url = deadlight_config_get_string(conn->context, "blog", 
                                                               "workers_url", NULL);
        gboolean workers_connected = FALSE;
        
        if (workers_url) {
            // Quick health check
            GError *fetch_error = NULL;
            gchar *health = fetch_from_workers(workers_url, "/api/health", &fetch_error);
            if (health) {
                workers_connected = TRUE;
                g_free(health);
            }
            if (fetch_error) g_error_free(fetch_error);
        }
        
        gchar *json_response = g_strdup_printf(
            "{\"status\":\"running\",\"version\":\"4.0.0\",\"backend\":\"%s\","
            "\"cache_enabled\":%s,\"cache_ttl\":%d}", 
            workers_connected ? "connected" : "offline",
            enable_cache ? "true" : "false",
            cache_ttl);
        
        DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", 
                                                               json_response, error);
        g_free(json_response);
        return result;
    }
    
    // Handle /api/blog/publish
    if (g_str_equal(request->method, "POST") && g_str_has_suffix(request->uri, "/publish")) {
        const gchar *json_response = 
            "{\"status\":\"success\",\"message\":\"Post published successfully\","
            "\"note\":\"Blog integration not yet implemented\"}";
        return api_send_json_response(conn, 501, "Not Implemented", json_response, error);
    }
    
    return api_send_404(conn, error);
}

static DeadlightHandlerResult api_handle_metrics_endpoint(DeadlightConnection *conn,
                                                           GError **error) {
    g_info("API metrics endpoint for conn %lu", conn->id);

    if (!conn->context) {
        return api_send_json_response(conn, 500, "Internal Server Error",
                                      "{\"error\":\"NULL context\"}", error);
    }

    gchar *json = api_build_metrics_json(conn->context);
    DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json, error);
    g_free(json);
    return result;
}
static DeadlightHandlerResult api_handle_connections_endpoint(DeadlightConnection *conn,
                                                               GError **error) {
    DeadlightContext *ctx = conn->context;

    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "connections");
    json_builder_begin_array(builder);

    guint active_count = 0;

    if (ctx->connections) {
        // Must use connection_mutex, not stats_mutex.
        // cleanup_connection_internal holds connection_mutex when removing
        // from this table — stats_mutex is only held for the bytes counter.
        deadlight_network_lock_connections(ctx);

        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, ctx->connections);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
            DeadlightConnection *c = (DeadlightConnection *)value;

            // cleaned is set at the very top of cleanup_connection_internal,
            // before any fields are freed — safe to check under the mutex
            if (!c || c->cleaned) continue;

            active_count++;

            gdouble duration = c->connection_timer
                ? g_timer_elapsed(c->connection_timer, NULL) : 0.0;

            json_builder_begin_object(builder);

            json_builder_set_member_name(builder, "id");
            json_builder_add_int_value(builder, (gint64)c->id);

            json_builder_set_member_name(builder, "host");
            json_builder_add_string_value(builder,
                c->target_host ? c->target_host : "unknown");

            json_builder_set_member_name(builder, "port");
            json_builder_add_int_value(builder, (gint64)c->target_port);

            json_builder_set_member_name(builder, "protocol");
            json_builder_add_string_value(builder,
                deadlight_protocol_to_string(c->protocol));

            json_builder_set_member_name(builder, "state");
            json_builder_add_string_value(builder,
                deadlight_state_to_string(c->state));

            json_builder_set_member_name(builder, "rx");
            json_builder_add_int_value(builder,
                (gint64)c->bytes_upstream_to_client);

            json_builder_set_member_name(builder, "tx");
            json_builder_add_int_value(builder,
                (gint64)c->bytes_client_to_upstream);

            json_builder_set_member_name(builder, "duration");
            json_builder_add_double_value(builder, duration);

            json_builder_set_member_name(builder, "client");
            json_builder_add_string_value(builder,
                c->client_address ? c->client_address : "unknown");

            json_builder_end_object(builder);
        }

        deadlight_network_unlock_connections(ctx);
    }

    json_builder_end_array(builder);

    json_builder_set_member_name(builder, "total");
    json_builder_add_int_value(builder, (gint64)ctx->total_connections);

    json_builder_set_member_name(builder, "active");
    json_builder_add_int_value(builder, (gint64)active_count);

    json_builder_end_object(builder);

    JsonGenerator *gen = json_generator_new();
    JsonNode *root = json_builder_get_root(builder);
    json_generator_set_root(gen, root);
    gchar *json = json_generator_to_data(gen, NULL);

    DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json, error);

    g_free(json);
    json_node_unref(root);
    g_object_unref(gen);
    g_object_unref(builder);

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// FEDERATION IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════

static DeadlightHandlerResult api_federation_send(DeadlightConnection *conn,
                                                   GError **error) {
    g_info("API federation send for conn %lu", conn->id);

    GError *parse_error = NULL;
    JsonObject *obj = parse_request_body(conn, &parse_error);
    if (!obj) {
        return api_send_error(conn, 400, "Bad Request", parse_error, "Invalid JSON", error);
    }

    GError *validate_error = NULL;
    const gchar *required[] = {"target_domain", "content", "author"};
    if (!validate_json_fields(obj, required, 3, &validate_error)) {
        json_object_unref(obj);
        return api_send_error(conn, 400, "Bad Request", validate_error, "Missing fields", error);
    }

    const gchar *target_domain = json_object_get_string_member(obj, "target_domain");
    const gchar *content       = json_object_get_string_member(obj, "content");
    const gchar *author        = json_object_get_string_member(obj, "author");
    // target_user removed — was declared G_GNUC_UNUSED and never referenced

    GError *discovery_error = NULL;
    FederationDiscovery *discovery = discover_federated_instance(target_domain,
                                                                  &discovery_error);

    if (discovery && discovery->supports_https) {
        g_info("Federation: Attempting direct HTTPS to %s", discovery->federation_endpoint);

        gchar *host = NULL;
        guint16 port = 443;

        if (g_str_has_prefix(discovery->federation_endpoint, "https://")) {
            host = g_strdup(discovery->federation_endpoint + 8);
            gchar *slash = strchr(host, '/');
            if (slash) *slash = '\0';
        } else {
            host = g_strdup(target_domain);
        }

        DeadlightConnection *fed_conn_ctx = g_new0(DeadlightConnection, 1);
        fed_conn_ctx->context     = conn->context;
        fed_conn_ctx->target_host = g_strdup(host);
        fed_conn_ctx->target_port = port;
        fed_conn_ctx->will_use_ssl = TRUE;
        fed_conn_ctx->id          = conn->id;

        GError *connect_error = NULL;
        if (deadlight_network_connect_upstream(fed_conn_ctx, &connect_error)) {
            g_info("Federation: Connected to %s", host);

            if (fed_conn_ctx->upstream_tls) {
                gchar *path = strrchr(discovery->federation_endpoint, '/');
                if (!path) path = "/api/federation/receive";

                const gchar *our_domain = deadlight_config_get_string(
                    conn->context, "federation", "domain", "proxy.deadlight.boo");

                // Build payload — fix: use temp vars so g_strdup_printf results
                // are freed. Previously they were passed directly to
                // json_builder_add_string_value which copies them, leaking the
                // original allocation.
                JsonBuilder *builder = json_builder_new();
                json_builder_begin_object(builder);

                gchar *from_field = g_strdup_printf("%s@%s", author, our_domain);
                json_builder_set_member_name(builder, "from");
                json_builder_add_string_value(builder, from_field);
                g_free(from_field);

                json_builder_set_member_name(builder, "subject");
                json_builder_add_string_value(builder, "Federated Post via Proxy");

                json_builder_set_member_name(builder, "body");
                json_builder_add_string_value(builder, content);

                json_builder_set_member_name(builder, "timestamp");
                json_builder_add_int_value(builder, time(NULL));

                json_builder_set_member_name(builder, "headers");
                json_builder_begin_object(builder);

                json_builder_set_member_name(builder, "X-Deadlight-Type");
                json_builder_add_string_value(builder, "federation");

                gchar *msg_id = g_strdup_printf("<%ld@proxy.deadlight.boo>", time(NULL));
                json_builder_set_member_name(builder, "Message-ID");
                json_builder_add_string_value(builder, msg_id);
                g_free(msg_id);

                json_builder_end_object(builder); // headers
                json_builder_end_object(builder); // root

                JsonGenerator *gen = json_generator_new();
                JsonNode *root = json_builder_get_root(builder);
                json_generator_set_root(gen, root);
                gchar *json_payload = json_generator_to_data(gen, NULL);

                GString *http_request = g_string_new(NULL);
                g_string_append_printf(http_request, "POST %s HTTP/1.1\r\n", path);
                g_string_append_printf(http_request, "Host: %s\r\n", host);
                g_string_append(http_request, "Content-Type: application/json\r\n");
                g_string_append_printf(http_request, "Content-Length: %zu\r\n",
                                       strlen(json_payload));
                g_string_append_printf(http_request, "From: federation@%s\r\n", our_domain);
                g_string_append(http_request, "Connection: close\r\n\r\n");
                g_string_append(http_request, json_payload);

                g_info("Federation: Sending %zu bytes to %s", http_request->len, host);

                GOutputStream *out = g_io_stream_get_output_stream(
                    G_IO_STREAM(fed_conn_ctx->upstream_tls));
                gsize written;
                GError *write_error = NULL;

                if (g_output_stream_write_all(out, http_request->str, http_request->len,
                                              &written, NULL, &write_error)) {
                    GInputStream *in = g_io_stream_get_input_stream(
                        G_IO_STREAM(fed_conn_ctx->upstream_tls));
                    gchar buf[2048];
                    gssize bytes = g_input_stream_read(in, buf, sizeof(buf) - 1,
                                                       NULL, NULL);

                    if (bytes > 0) {
                        buf[bytes] = '\0';
                        g_debug("Federation: Response: %s", buf);

                        if (strstr(buf, "200 OK") || strstr(buf, "202 Accepted")) {
                            g_info("Federation: HTTPS delivery succeeded to %s",
                                   target_domain);

                            gchar *response = g_strdup_printf(
                                "{\"status\":\"sent\","
                                "\"transport\":\"https\","
                                "\"target\":\"%s\"}",
                                target_domain);

                            DeadlightHandlerResult result =
                                api_send_json_response(conn, 200, "OK", response, error);

                            g_free(response);
                            g_string_free(http_request, TRUE);
                            g_free(json_payload);
                            json_node_unref(root);
                            g_object_unref(gen);
                            g_object_unref(builder);
                            if (fed_conn_ctx->upstream_connection)
                                g_object_unref(fed_conn_ctx->upstream_connection);
                            g_free(fed_conn_ctx->target_host);
                            g_free(fed_conn_ctx);
                            g_free(host);
                            federation_discovery_free(discovery);
                            json_object_unref(obj);
                            return result;
                        }

                        g_warning("Federation: Non-success response: %s", buf);
                    }
                } else {
                    g_warning("Federation: Write failed: %s",
                              write_error ? write_error->message : "unknown");
                    if (write_error) g_error_free(write_error);
                }

                g_string_free(http_request, TRUE);
                g_free(json_payload);
                json_node_unref(root);
                g_object_unref(gen);
                g_object_unref(builder);

            } else {
                g_warning("Federation: TLS not established for %s", host);
            }

            if (fed_conn_ctx->upstream_connection)
                g_object_unref(fed_conn_ctx->upstream_connection);

        } else {
            g_warning("Federation: Connection failed to %s: %s", host,
                      connect_error ? connect_error->message : "unknown");
            if (connect_error) g_error_free(connect_error);
        }

        g_free(fed_conn_ctx->target_host);
        g_free(fed_conn_ctx);
        g_free(host);
    } else {
        g_info("Federation: HTTPS not available, falling back to email");
    }

    if (discovery_error) {
        g_warning("Federation: Discovery failed: %s", discovery_error->message);
        g_error_free(discovery_error);
    }
    federation_discovery_free(discovery);

    // Fallback: email transport
    g_info("Federation: Email fallback to %s", target_domain);

    gchar *subject    = g_strdup_printf("[Federation] Post from %s", author);
    gchar *to_address = g_strdup_printf("federation@%s", target_domain);

    GError *send_error = NULL;
    gboolean sent = email_send_via_mailchannels(conn, "federation@deadlight.boo",
                                                 to_address, subject, content,
                                                 &send_error);
    DeadlightHandlerResult result;
    if (sent) {
        g_info("Federation: Email fallback succeeded to %s", target_domain);
        result = api_send_json_response(conn, 200, "OK",
            "{\"status\":\"sent\",\"transport\":\"email\"}", error);
    } else {
        g_warning("Federation: All transports failed for %s: %s", target_domain,
                  send_error ? send_error->message : "unknown");
        result = api_send_error(conn, 502, "Bad Gateway", send_error,
                                "All federation transports failed", error);
        send_error = NULL; // consumed
    }

    g_free(subject);
    g_free(to_address);
    json_object_unref(obj);
    return result;
}

static DeadlightHandlerResult api_federation_receive(DeadlightConnection *conn,
                                                      DeadlightRequest *request,
                                                      GError **error) {
    g_info("API federation receive for conn %lu", conn->id);

    const gchar *from_header = deadlight_request_get_header(request, "From");
    if (from_header) {
        g_info("Federation: Received from %s", from_header);
    }

    GError *parse_error = NULL;
    JsonObject *obj = parse_request_body(conn, &parse_error);
    if (!obj) {
        return api_send_error(conn, 400, "Bad Request", parse_error, "Invalid JSON", error);
    }

    const gchar *content = json_object_has_member(obj, "content")
                         ? json_object_get_string_member(obj, "content") : "";
    const gchar *author  = json_object_has_member(obj, "author")
                         ? json_object_get_string_member(obj, "author") : "unknown";

    const gchar *storage_dir = "/var/lib/deadlight/federation";
    g_mkdir_with_parents(storage_dir, 0755);

    time_t now = time(NULL);
    gchar *filename = g_strdup_printf("%s/post_%ld_%s.json", storage_dir, now, author);

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

    DeadlightHandlerResult result;
    if (stored) {
        g_info("Federation: Stored post from %s to %s", author, filename);
        gchar *body = g_strdup_printf(
            "{\"status\":\"received\",\"queued\":true,"
            "\"stored\":\"%s\",\"from\":\"%s\"}",
            filename, from_header ? from_header : "unknown");
        result = api_send_json_response(conn, 200, "OK", body, error);
        g_free(body);
    } else {
        g_warning("Federation: Storage failed: %s",
                  write_error ? write_error->message : "unknown");
        result = api_send_error(conn, 500, "Internal Server Error", write_error,
                                "Storage failed", error);
        write_error = NULL; // consumed
    }

    g_free(filename);
    json_node_unref(root);
    g_object_unref(gen);
    g_object_unref(builder);
    json_object_unref(obj);
    return result;
}

static DeadlightHandlerResult api_federation_test_domain(DeadlightConnection *conn,
                                                          const gchar *domain,
                                                          GError **error) {
    g_info("Federation: Testing domain %s", domain);

    GResolver *resolver = g_resolver_get_default();
    GError *lookup_error = NULL;
    GList *addresses = g_resolver_lookup_by_name(resolver, domain, NULL, &lookup_error);

    gboolean reachable = FALSE;
    const gchar *status = "unknown";

    if (addresses) {
        GSocketClient *client = g_socket_client_new();
        g_socket_client_set_timeout(client, 5);

        GError *connect_error = NULL;
        GSocketConnection *test_conn = g_socket_client_connect_to_host(
            client, domain, 587, NULL, &connect_error);

        if (test_conn) {
            reachable = TRUE;
            status = "verified";
            g_object_unref(test_conn);
        } else {
            g_clear_error(&connect_error);
            test_conn = g_socket_client_connect_to_host(
                client, domain, 25, NULL, &connect_error);
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
        g_info("Federation: DNS failed for %s: %s", domain,
               lookup_error ? lookup_error->message : "unknown");
    }

    if (lookup_error) g_error_free(lookup_error);
    g_object_unref(resolver);

    gchar *body = g_strdup_printf(
        "{\"domain\":\"%s\","
        "\"status\":\"%s\","
        "\"trust_level\":\"%s\","
        "\"test_time\":%ld,"
        "\"active\":%s}",
        domain, status,
        reachable ? "verified" : "unverified",
        time(NULL),
        reachable ? "true" : "false");

    DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", body, error);
    g_free(body);
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
                   "TLS connection to MailChannels not established");
        // Clean up the connection properly
        if (mc_conn->upstream_connection) {
            g_object_unref(mc_conn->upstream_connection);
        }
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
    return api_send_json_response(conn, 404, "Not Found",
                                  "{\"error\":\"API endpoint not found\"}", error);
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
// CACHE MANAGEMENT HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Check if a cache file exists and is fresh
 */
static gboolean is_cache_fresh(const gchar *cache_file, gint ttl_seconds) {
    if (!g_file_test(cache_file, G_FILE_TEST_EXISTS)) {
        return FALSE;
    }
    
    struct stat st;
    if (stat(cache_file, &st) != 0) {
        return FALSE;
    }
    
    time_t now = time(NULL);
    time_t age = now - st.st_mtime;
    
    return age < ttl_seconds;
}

/**
 * Read content from cache file
 */
static gchar* read_cache_file(const gchar *cache_file, GError **error) {
    gchar *contents = NULL;
    gsize length = 0;
    
    if (!g_file_get_contents(cache_file, &contents, &length, error)) {
        return NULL;
    }
    
    return contents;
}

/**
 * Write content to cache file
 */
static gboolean write_cache_file(const gchar *cache_file, const gchar *content, GError **error) {
    return g_file_set_contents(cache_file, content, -1, error);
}

/**
 * Fetch data from Workers via HTTP
 */
static gchar* fetch_from_workers(const gchar *workers_url,
                                  const gchar *endpoint,
                                  GError **error) {
    gchar *host = NULL;
    guint16 port = 443;
    gboolean use_tls = TRUE;

    if (g_str_has_prefix(workers_url, "https://")) {
        host = g_strdup(workers_url + 8);
    } else if (g_str_has_prefix(workers_url, "http://")) {
        host = g_strdup(workers_url + 7);
        port = 80;
        use_tls = FALSE;
    } else {
        host = g_strdup(workers_url);
    }

    // Strip trailing slash
    gsize len = strlen(host);
    if (len > 0 && host[len - 1] == '/') {
        host[len - 1] = '\0';
    }

    g_info("Blog: Fetching from Workers: https://%s%s", host, endpoint);

    gchar *result = http_get_raw(host, port, use_tls, endpoint, 10, error);
    g_free(host);

    if (!result) {
        g_prefix_error(error, "Workers fetch failed: ");
    }
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// UNIFIED DASHBOARD ENDPOINT
// ═══════════════════════════════════════════════════════════════════════════
// Purpose: Single endpoint that returns metrics + logs in one HTTP response
// Reduces polling overhead by 50% (one request instead of two)

/**
 * /api/dashboard - Unified metrics + logs endpoint
 * 
 * Returns:
 * {
 *   "metrics": {
 *     "active_connections": 5,
 *     "total_connections": 112,
 *     "bytes_transferred": 77234,
 *     "uptime": 2142.18,
 *     "connection_pool": {...},
 *     "protocols": {...},
 *     "server_info": {...},
 *     "rate_limiter": {...}
 *   },
 *   "logs": [
 *     "2026-02-16 12:13:27 [INFO] Connection 113: CONNECT request to api.github.com:443",
 *     "2026-02-16 12:13:28 [DEBUG] pblished: px_manager_get_proxies_sync: Proxy() = direct://",
 *     ...
 *   ]
 * }
 */
static DeadlightHandlerResult api_handle_dashboard_endpoint(DeadlightConnection *conn,
                                                            GError **error) {
    g_debug("API dashboard endpoint for conn %lu", conn->id);
    
    gchar *json = api_build_dashboard_json(conn->context);
    if (!json) {
        return api_send_json_response(conn, 500, "Internal Server Error",
                                     "{\"error\":\"Failed to build dashboard\"}", error);
    }
    
    DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json, error);
    g_free(json);
    return result;
}
// ═══════════════════════════════════════════════════════════════════════════
// PROMETHEUS METRICS HANDLER
// ═══════════════════════════════════════════════════════════════════════════

DeadlightHandlerResult api_handle_prometheus_metrics(DeadlightConnection *conn, GError **error) {
    DeadlightContext *ctx = conn->context;
    
    // Get rate limiter stats if available
    guint64 total_requests = 0;
    guint64 blocked_requests = 0;
    
    if (ctx->plugins_data) {
        deadlight_ratelimiter_get_stats(ctx, &blocked_requests, &total_requests);
    }
    
    // Build Prometheus metrics
    GString *metrics = g_string_new(NULL);
    
    g_string_append(metrics, "# HELP deadlight_active_connections Number of active connections\n");
    g_string_append(metrics, "# TYPE deadlight_active_connections gauge\n");
    g_string_append_printf(metrics, "deadlight_active_connections %lu\n", 
                          (gulong)ctx->active_connections);
    
    g_string_append(metrics, "# HELP deadlight_total_connections Total connections served\n");
    g_string_append(metrics, "# TYPE deadlight_total_connections counter\n");
    g_string_append_printf(metrics, "deadlight_total_connections %lu\n", 
                          (gulong)ctx->total_connections);
    
    g_string_append(metrics, "# HELP deadlight_bytes_transferred_total Total bytes transferred\n");
    g_string_append(metrics, "# TYPE deadlight_bytes_transferred_total counter\n");
    g_string_append_printf(metrics, "deadlight_bytes_transferred_total %ld\n", 
                          ctx->bytes_transferred);
    
    g_string_append(metrics, "# HELP deadlight_ratelimiter_requests_total Total requests processed by rate limiter\n");
    g_string_append(metrics, "# TYPE deadlight_ratelimiter_requests_total counter\n");
    g_string_append_printf(metrics, "deadlight_ratelimiter_requests_total %lu\n", 
                          (gulong)total_requests);
    
    g_string_append(metrics, "# HELP deadlight_ratelimiter_blocked_total Total requests blocked by rate limiter\n");
    g_string_append(metrics, "# TYPE deadlight_ratelimiter_blocked_total counter\n");
    g_string_append_printf(metrics, "deadlight_ratelimiter_blocked_total %lu\n", 
                          (gulong)blocked_requests);
    
    // Send response
    GOutputStream *client_os = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->client_connection));
    
    gchar *response = g_strdup_printf(
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; version=0.0.4\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", 
        metrics->len, metrics->str);
    
    gboolean write_success = g_output_stream_write_all(client_os, response, 
                                                        strlen(response), NULL, NULL, error);
    
    g_free(response);
    g_string_free(metrics, TRUE);
    
    return write_success ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
}

/**
 * Build a JSON string containing all proxy metrics.
 * Used by both /api/metrics and /api/dashboard (via api_build_dashboard_json).
 * Caller must g_free() the returned string.
 */
static gchar* api_build_metrics_json(DeadlightContext *ctx) {
    if (!ctx) return g_strdup("{\"error\":\"NULL context\"}");

    // Count active connections by protocol
    gint protocol_counts[13] = {0};

    if (ctx->connections) {
        deadlight_network_lock_connections(ctx);

        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, ctx->connections);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            DeadlightConnection *c = (DeadlightConnection *)value;
            if (c && !c->cleaned && c->protocol < 13) {
                protocol_counts[c->protocol]++;
            }
        }

        deadlight_network_unlock_connections(ctx);
    }

    GString *json = g_string_new("{");

    // Basic counters
    g_string_append_printf(json,
        "\"active_connections\":%lu,"
        "\"total_connections\":%lu,"
        "\"bytes_transferred\":%ld,",
        (gulong)ctx->active_connections,
        (gulong)ctx->total_connections,
        ctx->bytes_transferred);

    // Uptime
    gdouble uptime = ctx->uptime_timer
        ? g_timer_elapsed(ctx->uptime_timer, NULL) : 0.0;
    g_string_append_printf(json, "\"uptime\":%.2f,", uptime);

    // Connection pool
    if (ctx->conn_pool) {
        guint idle, active;
        guint64 total_gets, hits, evicted, failed;
        gdouble hit_rate;

        connection_pool_get_stats(ctx->conn_pool, &idle, &active,
                                  &total_gets, &hits, &hit_rate, &evicted, &failed);
        g_string_append_printf(json,
            "\"connection_pool\":{"
            "\"idle\":%u,"
            "\"active\":%u,"
            "\"total_requests\":%lu,"
            "\"cache_hits\":%lu,"
            "\"hit_rate\":%.2f,"
            "\"evicted\":%lu,"
            "\"failed\":%lu},",
            idle, active, total_gets, hits, hit_rate, evicted, failed);
    }

    // Protocol breakdown
    g_string_append_printf(json,
        "\"protocols\":{"
        "\"HTTP\":{\"active\":%d},"
        "\"HTTPS\":{\"active\":%d},"
        "\"WebSocket\":{\"active\":%d},"
        "\"SOCKS\":{\"active\":%d},"
        "\"SMTP\":{\"active\":%d},"
        "\"IMAP\":{\"active\":%d},"
        "\"FTP\":{\"active\":%d},"
        "\"API\":{\"active\":%d}},",
        protocol_counts[DEADLIGHT_PROTOCOL_HTTP],
        protocol_counts[DEADLIGHT_PROTOCOL_HTTPS],
        protocol_counts[DEADLIGHT_PROTOCOL_WEBSOCKET],
        protocol_counts[DEADLIGHT_PROTOCOL_SOCKS],
        protocol_counts[DEADLIGHT_PROTOCOL_SMTP],
        protocol_counts[DEADLIGHT_PROTOCOL_IMAP],
        protocol_counts[DEADLIGHT_PROTOCOL_FTP],
        protocol_counts[DEADLIGHT_PROTOCOL_API]);

    // Server info
    g_string_append_printf(json,
        "\"server_info\":{"
        "\"version\":\"%s\","
        "\"port\":%d,"
        "\"ssl_intercept\":%s,"
        "\"max_connections\":%d},",
        DEADLIGHT_VERSION_STRING,
        ctx->listen_port,
        ctx->ssl_intercept_enabled ? "true" : "false",
        ctx->max_connections);

    // Rate limiter
    if (ctx->plugins_data) {
        guint64 limited = 0, passed = 0;
        deadlight_ratelimiter_get_stats(ctx, &limited, &passed);
        g_string_append_printf(json,
            "\"rate_limiter\":{"
            "\"total_limited\":%lu,"
            "\"total_passed\":%lu,"
            "\"rejection_rate\":%.2f}",
            limited, passed,
            passed > 0 ? (100.0 * limited / (limited + passed)) : 0.0);
    } else {
        g_string_append(json, "\"rate_limiter\":null");
    }

    g_string_append(json, "}");
    return g_string_free(json, FALSE);
}

/**
 * Handle /api/stream - Server-Sent Events endpoint
 * 
 * Keeps connection open and pushes updates every 2 seconds (or on change)
 * Client uses: const events = new EventSource('/api/stream');
 */
static DeadlightHandlerResult api_handle_stream_endpoint(DeadlightConnection *conn,
                                                          GError **error) {
    g_info("SSE: Client %lu connected to event stream", conn->id);

    GOutputStream *client_os = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->client_connection));

    const gchar *sse_headers =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "X-Accel-Buffering: no\r\n"
        "\r\n";

    if (!g_output_stream_write_all(client_os, sse_headers, strlen(sse_headers),
                                    NULL, NULL, error)) {
        g_warning("SSE: Failed to send headers to client %lu", conn->id);
        return HANDLER_ERROR;
    }

    if (!g_output_stream_flush(client_os, NULL, error)) {
        g_warning("SSE: Failed to flush headers to client %lu", conn->id);
        return HANDLER_ERROR;
    }

    // Send initial snapshot immediately so the UI doesn't wait 2 seconds
    gchar *initial_json = api_build_dashboard_json(conn->context);
    if (initial_json) {
        sse_send_event(client_os, "dashboard", initial_json, NULL);
        g_free(initial_json);
    }

    // Allocate state — magic number makes api_cleanup_sse_stream safe to call
    // on any API connection's protocol_data without risking a misread cast
    SSEStreamState *state = g_new0(SSEStreamState, 1);
    state->magic                  = SSE_STREAM_MAGIC;
    state->conn                   = conn;
    state->output                 = client_os;
    state->closed                 = FALSE;
    state->last_total_connections = conn->context->total_connections;
    state->last_bytes_transferred = conn->context->bytes_transferred;

    state->update_timer = g_timeout_source_new_seconds(2);
    g_source_set_callback(state->update_timer, sse_send_update, state, NULL);
    g_source_attach(state->update_timer, NULL);

    conn->protocol_data = state;

    g_info("SSE: Stream established for client %lu", conn->id);
    return HANDLER_SUCCESS_ASYNC;
}

// ═══════════════════════════════════════════════════════════════════════════
// SSE UPDATE TIMER CALLBACK
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Periodic callback: Send dashboard update to SSE client
 * 
 * Only sends updates if metrics have changed (reduces bandwidth)
 */
static gboolean sse_send_update(gpointer user_data) {
    SSEStreamState *state = (SSEStreamState *)user_data;

    if (state->closed) {
        g_debug("SSE: Stream %lu already closed, stopping timer", state->conn->id);
        return G_SOURCE_REMOVE;
    }

    DeadlightContext *ctx = state->conn->context;

    gboolean metrics_changed =
        (ctx->total_connections  != state->last_total_connections) ||
        (ctx->bytes_transferred  != state->last_bytes_transferred);

    if (!metrics_changed) {
        // Heartbeat keeps the connection alive through proxies/load balancers
        // that would otherwise close idle keep-alive connections
        const gchar *heartbeat = ": heartbeat\n\n";
        GError *err = NULL;

        if (!g_output_stream_write_all(state->output, heartbeat, strlen(heartbeat),
                                       NULL, NULL, &err)) {
            g_warning("SSE: Heartbeat failed for client %lu: %s",
                      state->conn->id, err ? err->message : "unknown");
            if (err) g_error_free(err);
            sse_stream_cleanup(state);
            return G_SOURCE_REMOVE;
        }

        g_output_stream_flush(state->output, NULL, NULL);
        return G_SOURCE_CONTINUE;
    }

    gchar *json = api_build_dashboard_json(ctx);
    if (!json) {
        g_warning("SSE: Failed to build dashboard JSON for client %lu", state->conn->id);
        return G_SOURCE_CONTINUE;
    }

    GError *err = NULL;
    if (!sse_send_event(state->output, "dashboard", json, &err)) {
        g_warning("SSE: Send failed for client %lu: %s",
                  state->conn->id, err ? err->message : "unknown");
        if (err) g_error_free(err);
        g_free(json);
        sse_stream_cleanup(state);
        return G_SOURCE_REMOVE;
    }

    state->last_total_connections = ctx->total_connections;
    state->last_bytes_transferred = ctx->bytes_transferred;

    g_free(json);
    return G_SOURCE_CONTINUE;
}

/**
 * Cleanup SSE stream state
 */
static void sse_stream_cleanup(SSEStreamState *state) {
    if (!state) return;

    g_info("SSE: Cleaning up stream for client %lu", state->conn->id);

    state->closed = TRUE;

    if (state->update_timer) {
        g_source_destroy(state->update_timer);
        g_source_unref(state->update_timer);
        state->update_timer = NULL;
    }

    state->output = NULL;
    g_free(state);
}

// ═══════════════════════════════════════════════════════════════════════════
// SSE HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Send an SSE event to client
 * 
 * Format:
 *   event: dashboard
 *   data: {"metrics":{...},"logs":[...]}
 *   
 */
static gboolean sse_send_event(GOutputStream *out,
                                const gchar *event_type,
                                const gchar *data,
                                GError **error) {
    GString *event = g_string_new(NULL);

    if (event_type) {
        g_string_append_printf(event, "event: %s\n", event_type);
    }

    // Write the entire payload as a single data line.
    // SSE allows only one data: line per event when the payload is
    // guaranteed to be single-line (minified JSON from api_build_dashboard_json).
    // The previous line-splitting approach silently dropped blank lines,
    // which would corrupt any pretty-printed or multi-paragraph content.
    g_string_append_printf(event, "data: %s\n", data);

    // Blank line terminates the event
    g_string_append(event, "\n");

    gboolean success = g_output_stream_write_all(out, event->str, event->len,
                                                  NULL, NULL, error);
    if (success) {
        g_output_stream_flush(out, NULL, NULL);
    }

    g_string_free(event, TRUE);
    return success;
}

/**
 * Build dashboard JSON (same as unified endpoint)
 * 
 * Extracted to shared function so /api/dashboard and /api/stream use same logic
 */
static gchar* api_build_dashboard_json(DeadlightContext *ctx) {
    if (!ctx) return g_strdup("{\"error\":\"NULL context\"}");

    gchar *metrics = api_build_metrics_json(ctx);
    gchar *logs    = deadlight_logging_get_buffered_json();

    gchar *result = g_strdup_printf("{\"metrics\":%s,\"logs\":%s}",
                                    metrics,
                                    logs ? logs : "[]");
    g_free(metrics);
    g_free(logs);
    return result;
}

/**
 * SSE cleanup hook for api.c cleanup function
 * 
 */
static void api_cleanup_sse_stream(DeadlightConnection *conn) {
    if (!conn->protocol_data) return;

    // All API connections share protocol_data. We can only safely interpret
    // it as SSEStreamState if the magic number matches — other API endpoints
    // may store different structures here in future.
    SSEStreamState *state = (SSEStreamState *)conn->protocol_data;

    if (state->magic != SSE_STREAM_MAGIC) {
        // Not an SSE stream — leave it for whoever owns it
        return;
    }

    if (!state->closed) {
        sse_stream_cleanup(state);
    }

    conn->protocol_data = NULL;
}

// ═══════════════════════════════════════════════════════════════════════════
// CLEANUP
// ═══════════════════════════════════════════════════════════════════════════

static void api_cleanup(DeadlightConnection *conn) {
    g_debug("API cleanup for conn %lu", conn->id);
    api_cleanup_sse_stream(conn);
}