#include "api.h"
#include <json-glib/json-glib.h>

// Well-known endpoint handler
DeadlightHandlerResult api_handle_wellknown_deadlight(DeadlightConnection *conn, GError **error) {
    const gchar *our_domain = deadlight_config_get_string(conn->context, "federation", 
                                                          "domain", "proxy.deadlight.boo");
    
    gchar *json_response = g_strdup_printf(
        "{"
        "\"instance\":\"%s\","
        "\"federation_endpoint\":\"https://%s/api/federation/receive\","
        "\"protocols\":[\"https\",\"smtp\"],"
        "\"version\":\"1.0.0\","
        "\"public_key\":null"  // TODO: Add PGP key
        "}", our_domain, our_domain);
    
    DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json_response, error);
    g_free(json_response);
    return result;
}

// Discovery function: query target's .well-known endpoint
typedef struct {
    gchar *domain;
    gchar *federation_endpoint;
    gchar *public_key;
    gboolean supports_https;
} FederationDiscovery;

static FederationDiscovery* discover_federated_instance(const gchar *target_domain, GError **error) {
    g_info("Federation: Discovering instance at %s", target_domain);
    
    // Try HTTPS discovery first
    gchar *discovery_url = g_strdup_printf("https://%s/.well-known/deadlight", target_domain);
    
    GSocketClient *client = g_socket_client_new();
    g_socket_client_set_tls(client, TRUE);
    g_socket_client_set_timeout(client, 10);
    
    GSocketConnection *conn = g_socket_client_connect_to_host(client, target_domain, 443, NULL, error);
    g_object_unref(client);
    
    if (!conn) {
        g_prefix_error(error, "Failed to connect to %s: ", target_domain);
        g_free(discovery_url);
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
        g_free(discovery_url);
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
        g_free(discovery_url);
        return NULL;
    }
    
    // Extract JSON body
    const gchar *body_start = strstr(response->str, "\r\n\r\n");
    if (!body_start) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid HTTP response");
        g_string_free(response, TRUE);
        g_free(discovery_url);
        return NULL;
    }
    body_start += 4;
    
    // Parse JSON
    JsonParser *parser = json_parser_new();
    if (!json_parser_load_from_data(parser, body_start, -1, error)) {
        g_object_unref(parser);
        g_string_free(response, TRUE);
        g_free(discovery_url);
        return NULL;
    }
    
    JsonNode *root = json_parser_get_root(parser);
    JsonObject *obj = json_node_get_object(root);
    
    FederationDiscovery *discovery = g_new0(FederationDiscovery, 1);
    discovery->domain = g_strdup(json_object_get_string_member(obj, "instance"));
    discovery->federation_endpoint = g_strdup(json_object_get_string_member(obj, "federation_endpoint"));
    discovery->supports_https = TRUE;
    
    if (json_object_has_member(obj, "public_key")) {
        discovery->public_key = g_strdup(json_object_get_string_member(obj, "public_key"));
    }
    
    g_object_unref(parser);
    g_string_free(response, TRUE);
    g_free(discovery_url);
    
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
