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
static gboolean
email_send_via_mailchannels(DeadlightConnection *conn,
                            const gchar *from,
                            const gchar *to,
                            const gchar *subject,
                            const gchar *body,
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
    // Safety check
    if (len < 9) return 0;

    // 1. Fast Path: Check standard Origin Form (Direct access)
    // This covers: GET /api/...
    if ((len >= 9 && memcmp(data, "GET /api/", 9) == 0) ||
        (len >= 10 && memcmp(data, "POST /api/", 10) == 0) ||
        (len >= 9 && memcmp(data, "PUT /api/", 9) == 0) ||
        (len >= 12 && memcmp(data, "DELETE /api/", 12) == 0)) {
        return 100; 
    }

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

static DeadlightHandlerResult api_handle(DeadlightConnection *conn, GError **error) {
    g_info("API handler for connection %lu", conn->id);
    
    gchar *request_preview = g_strndup((gchar*)conn->client_buffer->data, 
                                       MIN(conn->client_buffer->len, 200));
    g_debug("API conn %lu: Raw request preview: %s", conn->id, request_preview);
    g_free(request_preview);

    // Parse HTTP request
    DeadlightRequest *request = deadlight_request_new(conn);
    
    // Convert buffer to string for parsing
    gchar *request_str = g_strndup((gchar*)conn->client_buffer->data, conn->client_buffer->len);

    g_debug("API conn %lu: Parsed URI: '%s', Method: '%s'", 
            conn->id, request->uri, request->method);
    
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
            "Access-Control-Allow-Headers: Content-Type, X-API-Key, Authorization\r\n"
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
        g_debug("API handler: No route matched for URI: %s", request->uri);
        result = api_send_404(conn, error);
    }
    
    deadlight_request_free(request);
    return result;
}

static DeadlightHandlerResult api_handle_system_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    if (g_str_equal(request->uri, "/api/system/ip")) {
        // Return current external IP
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
        "Access-Control-Allow-Headers: Content-Type, X-API-Key, Authorization\r\n"
        "Content-Encoding: identity\r\n"  // Explicitly disable compression
        "Cache-Control: no-cache\r\n"     // Prevent caching issues
        "Connection: close\r\n"
        "\r\n"
        "%s", status_code, status_text, strlen(json_body), json_body);

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

static DeadlightHandlerResult
api_handle_email_endpoint(DeadlightConnection *conn,
                          DeadlightRequest *request,
                          GError **error)
{
    if (g_str_equal(request->method, "POST") && g_str_has_suffix(request->uri, "/send")) {
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

        const gchar *to      = json_object_get_string_member(obj, "to");
        const gchar *from    = json_object_has_member(obj, "from")
                             ? json_object_get_string_member(obj, "from")
                             : "noreply@deadlight.boo";
        const gchar *subject = json_object_has_member(obj, "subject")
                             ? json_object_get_string_member(obj, "subject")
                             : "Message from Deadlight";
        const gchar *body    = json_object_get_string_member(obj, "body");

        GError *send_error = NULL;
        if (email_send_via_mailchannels(conn, from, to, subject, body, &send_error)) {
            g_object_unref(parser);
            return api_send_json_response(conn, 200, "OK",
                "{\"status\":\"sent\",\"provider\":\"mailchannels\"}", error);
        } else {
            gchar *err_json = g_strdup_printf(
                "{\"error\":\"Failed to send email: %s\"}",
                send_error ? send_error->message : "unknown error");

            DeadlightHandlerResult result = api_send_json_response(conn, 502,
                "Bad Gateway", err_json, error);

            if (send_error) g_error_free(send_error);
            g_free(err_json);
            g_object_unref(parser);
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

    // ─── Populate request->body so HMAC uses real payload ──────
    if (!request->body || request->body->len == 0) {
        gsize real_len = strlen(body_str);  // body_str has no trailing junk
        request->body = g_byte_array_sized_new(real_len);
        g_byte_array_append(request->body, (const guint8*)body_str, real_len);
        g_info("Fixed empty request->body — restored %zu bytes for HMAC", real_len);
    }

    // ─── HMAC AUTH ─────────────────────────────
    const gchar *auth_header = deadlight_request_get_header(request, "Authorization");

    const gchar *payload_for_hmac = (const gchar *)request->body->data;
    gsize payload_len = request->body->len;

    // 1. Dump secret (byte-exact)
    g_info("DEBUG HMAC: secret_len=%zu '%.30s' ... '%.20s'", 
        strlen(conn->context->auth_secret), 
        conn->context->auth_secret, 
        conn->context->auth_secret + strlen(conn->context->auth_secret) - 20);

    // 2. Extracted HMAC from header (simulate validate_hmac)
    const gchar *bearer_pos = g_strstr_len(auth_header, -1, "Bearer ");
    gchar *candidate_hmac = bearer_pos ? g_strdup(bearer_pos + 7) : g_strdup("");
    g_strcanon(candidate_hmac, "0123456789abcdefABCDEF", g_ascii_tolower);  // Normalize hex
    g_info("DEBUG HMAC: extracted_candidate='%s' (len=%zu)", candidate_hmac, strlen(candidate_hmac));
    g_free(candidate_hmac);

    // 3. Call & log result (if you have compute_hmac_hex fn, else in validate_hmac)
    

    if (!auth_header || !validate_hmac_bytes(auth_header,request->body->data,request->body->len,conn->context->auth_secret)) {
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
    gboolean sent = email_send_via_mailchannels(conn, from, to, subject, body, error);
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

static gboolean
email_send_via_mailchannels(DeadlightConnection *conn,
                            const gchar *from,
                            const gchar *to,
                            const gchar *subject,
                            const gchar *body,
                            GError **error)
{
    g_info("Email: Sending via MailChannels API to %s", to);

    const gchar *api_key = deadlight_config_get_string(conn->context, "smtp", "mailchannels_api_key", NULL);
    if (!api_key || api_key[0] == '\0') {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Missing mailchannels_api_key in [smtp] section");
        return FALSE;
    }

    // 1. Configure the connection for the Upstream (MailChannels)
    // We reuse the existing DeadlightConnection object, effectively temporarily 
    // turning this "Client->Proxy" connection into a "Proxy->MailChannels" agent.
    if (conn->target_host) g_free(conn->target_host);
    conn->target_host = g_strdup("api.mailchannels.net");
    conn->target_port = 443;
    conn->will_use_ssl = TRUE; // Force SSL for the pool/connector
    
    // 2. Connect (Uses the Pool automatically!)
    if (!deadlight_network_connect_upstream(conn, error)) {
        g_prefix_error(error, "Failed to pool/connect to MailChannels: ");
        return FALSE;
    }

    // 3. Determine which stream to use (TLS or Plain)
    // deadlight_network_connect_upstream handles the SSL handshake if needed
   if (!conn->upstream_tls) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "TLS not established for HTTPS upstream");
        return FALSE;
    }

    GIOStream *upstream_io = G_IO_STREAM(conn->upstream_tls);

    GOutputStream *out = g_io_stream_get_output_stream(upstream_io);
    GInputStream  *in  = g_io_stream_get_input_stream(upstream_io);

    // 4. Build Payload (JSON)
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
    json_builder_add_string_value(builder, "Deadlight Blog");
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

    // 5. Build HTTP Request
    GString *request = g_string_new(NULL);
    g_string_append(request, "POST /tx/v1/send HTTP/1.1\r\n");
    g_string_append(request, "Host: api.mailchannels.net\r\n");
    g_string_append(request, "Content-Type: application/json\r\n");
    g_string_append_printf(request, "Content-Length: %zu\r\n", strlen(json_payload));
    g_string_append_printf(request, "Authorization: Bearer %s\r\n", api_key);
    // Keep-Alive allows the connection to be returned to the pool!
    g_string_append(request, "Connection: keep-alive\r\n"); 
    g_string_append(request, "\r\n");
    g_string_append(request, json_payload);

    g_info("Email: Sending %zu bytes to MailChannels (Pool-aware)", request->len);

    gboolean success = FALSE;
    gsize written;
    
    // 6. Send
    if (!g_output_stream_write_all(out, request->str, request->len, &written, NULL, error)) {
        goto cleanup;
    }

    // 7. Read Response
    // Since we are doing manual HTTP over a stream, we just read enough to check status
    gchar buf[8192] = {0};
    gssize read_len = g_input_stream_read(in, buf, sizeof(buf)-1, NULL, error);
    
    if (read_len > 0) {
        buf[read_len] = '\0';
        if (strstr(buf, "202 Accepted") || strstr(buf, "200 OK")) {
            g_info("Email: Successfully sent via MailChannels");
            success = TRUE;
            
            // 8. Release to Pool!
            // Since we used Keep-Alive and the request succeeded, we can reuse this SSL socket.
            // We set state to CONNECTED so the release logic accepts it.
            conn->state = DEADLIGHT_STATE_CONNECTED; 
            deadlight_network_release_to_pool(conn, "API Email Sent");
        } else {
            g_warning("Email: MailChannels rejected request:\n%s", buf);
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "MailChannels rejected the email");
            // If failed, we don't pool it (default cleanup will close it)
        }
    }

cleanup:
    if (request) g_string_free(request, TRUE);
    g_free(json_payload);
    json_node_unref(root);
    g_object_unref(gen);
    g_object_unref(builder);
    
    // NOTE: We do NOT unref the conn->upstream_connection here because 
    // deadlight_network_release_to_pool took ownership or cleanup will handle it.

    return success;
}

static DeadlightHandlerResult api_handle_metrics_endpoint(
    DeadlightConnection *conn, GError **error)
{
    DeadlightContext *ctx = conn->context;
    g_info("API metrics endpoint for conn %lu", conn->id);

    if (!ctx) {
        return api_send_json_response(
            conn, 500, "Internal Server Error",
            "{\"error\":\"NULL context\"}", error);
    }

    GString *json = g_string_new(NULL);
    g_string_append(json, "{");

    // ─────────────────────────────────────────────────────────────
    // Basic metrics
    // ─────────────────────────────────────────────────────────────
    g_string_append_printf(json,
        "\"active_connections\":%d,"
        "\"total_connections\":%d,"
        "\"bytes_transferred\":%ld,",
        ctx->active_connections,
        ctx->total_connections,
        ctx->bytes_transferred
    );

    // ─────────────────────────────────────────────────────────────
    // Uptime
    // ─────────────────────────────────────────────────────────────
    double uptime = 0.0;
    if (ctx->uptime_timer) {
        uptime = g_timer_elapsed(ctx->uptime_timer, NULL);
    }
    g_string_append_printf(json, "\"uptime\":%.2f,", uptime);

    // ─────────────────────────────────────────────────────────────
    // Protocol summary (static for now, no JSON-GLib)
    // ─────────────────────────────────────────────────────────────
    g_string_append(json, "\"protocols\":{");
    g_string_append(json, "\"HTTP\":{\"active\":0},");
    g_string_append(json, "\"HTTPS\":{\"active\":0},");
    g_string_append(json, "\"WebSocket\":{\"active\":0},");
    g_string_append(json, "\"SOCKS\":{\"active\":0},");
    g_string_append(json, "\"SMTP\":{\"active\":0},");
    g_string_append(json, "\"IMAP\":{\"active\":0},");
    g_string_append(json, "\"FTP\":{\"active\":0},");
    g_string_append(json, "\"API\":{\"active\":0}");
    g_string_append(json, "},");

    // ─────────────────────────────────────────────────────────────
    // Server info
    // ─────────────────────────────────────────────────────────────
    g_string_append(json, "\"server_info\":{");
    g_string_append_printf(json, "\"version\":\"%s\",", DEADLIGHT_VERSION_STRING);
    g_string_append_printf(json, "\"port\":%d,", ctx->listen_port);
    g_string_append_printf(
        json,
        "\"ssl_intercept\":%s,",
        ctx->ssl_intercept_enabled ? "true" : "false"
    );
    g_string_append_printf(json, "\"max_connections\":%d", ctx->max_connections);
    g_string_append(json, "}");

    g_string_append(json, "}");

    DeadlightHandlerResult result =
        api_send_json_response(conn, 200, "OK", json->str, error);

    g_string_free(json, TRUE);
    return result;
}
