// src/core/request.c
// Deadlight Proxy - Request handling module
#include "deadlight.h"

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