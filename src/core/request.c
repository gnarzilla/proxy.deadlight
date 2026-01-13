// src/core/request.c
// Deadlight Proxy - Request handling module
#include "deadlight.h"
#include <string.h>

// Forward declarations for helpers used only in this file
static gboolean local_parse_http_request_line(const gchar *line, DeadlightRequest *request);
static gchar *extract_path_from_uri(const gchar *uri);

// --- Public API ---

DeadlightRequest *deadlight_request_new(DeadlightConnection *connection) {
    g_return_val_if_fail(connection != NULL, NULL);
    
    DeadlightRequest *request = g_new0(DeadlightRequest, 1);
    request->connection = connection;
    request->headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    request->body = g_byte_array_new();
    
    return request;
}

void deadlight_request_free(DeadlightRequest *request) {
    if (!request) return;
    
    g_free(request->method);
    g_free(request->uri);
    g_free(request->version);
    g_free(request->host);
    g_free(request->path);
    g_free(request->query);
    g_free(request->block_reason);
    
    if (request->headers) {
        g_hash_table_destroy(request->headers);
    }
    
    if (request->body) {
        g_byte_array_free(request->body, TRUE);
    }
    
    g_free(request);
}

// Function to parse the raw buffer into the request struct
gboolean deadlight_request_parse_headers(DeadlightRequest *request, const gchar *data, gsize length) {
    g_return_val_if_fail(request != NULL, FALSE);

    const gchar *headers_end = g_strstr_len((const gchar *)data, length, "\r\n\r\n");
    if (!headers_end) return FALSE; // Incomplete headers

    gsize headers_len = (headers_end - (const gchar *)data);
    gchar *headers_str = g_strndup((const gchar *)data, headers_len);
    
    gchar **lines = g_strsplit(headers_str, "\r\n", -1);
    g_free(headers_str);

    if (!lines || !lines[0]) {
        g_strfreev(lines);
        return FALSE;
    }

    // Parse the first line (e.g., "GET /path HTTP/1.1" or "GET http://host/path HTTP/1.1")
    if (!local_parse_http_request_line(lines[0], request)) {
        g_strfreev(lines);
        return FALSE;
    }

    // Parse the rest of the lines (the headers)
    for (int i = 1; lines[i] && strlen(lines[i]) > 0; i++) {
        gchar *colon_pos = strchr(lines[i], ':');
        if (colon_pos) {
            *colon_pos = '\0';
            gchar *name = g_strstrip(g_ascii_strdown(lines[i], -1));
            gchar *value = g_strstrip(colon_pos + 1);
            deadlight_request_set_header(request, name, value);
            g_free(name);
        }
    }
    g_strfreev(lines);
    return TRUE;
}

gchar *deadlight_request_get_header(DeadlightRequest *request, const gchar *name) {
    g_return_val_if_fail(request != NULL && request->headers != NULL && name != NULL, NULL);
    gchar *lower_name = g_ascii_strdown(name, -1);
    gchar *value = g_hash_table_lookup(request->headers, lower_name);
    g_free(lower_name);
    return value;
}

void deadlight_request_set_header(DeadlightRequest *request, const gchar *name, const gchar *value) {
    g_return_if_fail(request != NULL && request->headers != NULL && name != NULL && value != NULL);
    gchar *lower_name = g_ascii_strdown(name, -1);
    g_hash_table_replace(request->headers, lower_name, g_strdup(value));
}

// --- Helper Functions ---

/**
 * Extract the path portion from a URI.
 * Handles both origin-form (/path) and absolute-form (http://host/path)
 * 
 * Examples:
 *   "/api/health" -> "/api/health"
 *   "http://localhost:8080/api/health" -> "/api/health"
 *   "https://example.com:443/path?query" -> "/path?query"
 *   "http://example.com" -> "/"
 */
static gchar *extract_path_from_uri(const gchar *uri) {
    if (!uri) return g_strdup("/");
    
    // If it's already a path (starts with /), return as-is
    if (uri[0] == '/') {
        return g_strdup(uri);
    }
    
    // Handle absolute URIs: http://host:port/path or https://host:port/path
    if (g_str_has_prefix(uri, "http://") || g_str_has_prefix(uri, "https://")) {
        // Skip the scheme (http:// or https://)
        const gchar *after_scheme = strchr(uri + 8, '/');
        
        if (after_scheme) {
            // Found the path portion
            return g_strdup(after_scheme);
        } else {
            // No path in URI (e.g., "http://example.com")
            return g_strdup("/");
        }
    }
    
    // For any other form, treat as-is (shouldn't happen in HTTP)
    return g_strdup(uri);
}

static gboolean local_parse_http_request_line(const gchar *line, DeadlightRequest *request) {
    gchar **parts = g_strsplit(line, " ", 3);
    if (g_strv_length(parts) < 3) {
        g_strfreev(parts);
        return FALSE;
    }
    
    request->method = g_strdup(parts[0]);
    
    // Extract path from URI (handles both origin-form and absolute-form)
    gchar *full_uri = parts[1];
    request->uri = extract_path_from_uri(full_uri);
    
    // Store the host if it's an absolute URI
    if (g_str_has_prefix(full_uri, "http://") || g_str_has_prefix(full_uri, "https://")) {
        // Extract host:port from absolute URI
        const gchar *host_start = full_uri + (g_str_has_prefix(full_uri, "https://") ? 8 : 7);
        const gchar *host_end = strchr(host_start, '/');
        
        if (host_end) {
            request->host = g_strndup(host_start, host_end - host_start);
        } else {
            request->host = g_strdup(host_start);
        }
    }
    
    request->version = g_strdup(parts[2]);
    
    g_strfreev(parts);
    return TRUE;
}

// --- Response Functions ---

DeadlightResponse *deadlight_response_new(DeadlightConnection *connection) {
    g_return_val_if_fail(connection != NULL, NULL);
    
    DeadlightResponse *response = g_new0(DeadlightResponse, 1);
    response->connection = connection;
    response->headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    response->body = g_byte_array_new();
    
    return response;
}

void deadlight_response_free(DeadlightResponse *response) {
    if (!response) return;
    
    g_free(response->version);
    g_free(response->reason_phrase);
    g_free(response->block_reason);
    
    if (response->headers) {
        g_hash_table_destroy(response->headers);
    }
    
    if (response->body) {
        g_byte_array_free(response->body, TRUE);
    }
    
    g_free(response);
}