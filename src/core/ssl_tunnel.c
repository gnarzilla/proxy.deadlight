// src/ssl_tunnel.c

#include "ssl_tunnel.h"
#include "logging.h"
#include <openssl/ssl.h>
#include <glib-unix.h>
#include <errno.h>
#include <unistd.h> // For close()

// Data structure to manage the state of a single tunnel
typedef struct {
    DeadlightConnection *conn;
    gboolean client_source_removed;
    gboolean upstream_source_removed;
    gsize client_to_upstream_bytes;
    gsize upstream_to_client_bytes;
    guint client_source_id;
    guint upstream_source_id;
} SslTunnelData;

// This function is the final cleanup for the connection

static void cleanup_ssl_tunnel(SslTunnelData *data) {
    if (!data) return;
    DeadlightConnection *conn = data->conn;

    log_info("Connection %lu: SSL Tunnel closed (client->upstream: %.2f KB, upstream->client: %.2f KB)",
             conn->id,
             (double)data->client_to_upstream_bytes / 1024.0,
             (double)data->upstream_to_client_bytes / 1024.0);

    // This is the true "handler completed" point
    log_info("Connection %lu: Handler for 'HTTP' (CONNECT) completed.", conn->id);

    // --- CORRECTED CLEANUP LOGIC ---

    // Clean up the SSL objects. We own these.
    if (conn->client_ssl) {
        SSL_shutdown(conn->client_ssl);
        SSL_free(conn->client_ssl);
        conn->client_ssl = NULL;
    }
    if (conn->upstream_ssl) {
        SSL_shutdown(conn->upstream_ssl);
        SSL_free(conn->upstream_ssl);
        conn->upstream_ssl = NULL;
    }
    if (conn->ssl_ctx) {
        SSL_CTX_free(conn->ssl_ctx);
        conn->ssl_ctx = NULL;
    }

    // Clean up the GIOChannels we created. GLib will handle the underlying FDs.
    // We use g_clear_object to be safe. It unrefs and sets the pointer to NULL.
    g_clear_object(&conn->client_channel);
    g_clear_object(&conn->upstream_channel);

    // DO NOT touch the raw file descriptors (close()). The GSocketConnection owns them.
    // DO NOT free the connection object. The main network loop owns it.

    // Free the tunnel data struct, which we allocated in start_ssl_tunnel.
    g_free(data);

    // --- THE FINAL FIX ---
    // Now that our async business is done, we remove the connection from the
    // master hash table. This will trigger the final GDestroyNotify function
    // (cleanup_connection in network.c) which will free the conn struct itself.
    g_hash_table_remove(conn->context->connections, &conn->id);
}

// Callback for data coming from the client, to be sent to the upstream server
static gboolean client_to_upstream_ssl_cb(GIOChannel *source, GIOCondition condition, gpointer user_data) {
    (void)source; // Unused in this callback
    SslTunnelData *data = user_data;
    DeadlightConnection *conn = data->conn;
    char buffer[4096];
    gssize bytes_read, bytes_written;

    if (condition & (G_IO_HUP | G_IO_ERR)) {
        goto cleanup;
    }

    bytes_read = SSL_read(conn->client_ssl, buffer, sizeof(buffer));
    if (bytes_read <= 0) { // Clean shutdown or error
        goto cleanup;
    }

    bytes_written = SSL_write(conn->upstream_ssl, buffer, bytes_read);
    if (bytes_written <= 0) { // Error writing to upstream
        goto cleanup;
    }
    data->client_to_upstream_bytes += bytes_written;

    return G_SOURCE_CONTINUE;

cleanup:
    g_source_remove(data->client_source_id);
    data->client_source_removed = TRUE;
    if (data->upstream_source_removed) {
        cleanup_ssl_tunnel(data);
    }
    return G_SOURCE_REMOVE;
}

// Callback for data coming from the upstream server, to be sent to the client
static gboolean upstream_to_client_ssl_cb(GIOChannel *source, GIOCondition condition, gpointer user_data) {
    (void)source; // Unused in this callback
    SslTunnelData *data = user_data;
    DeadlightConnection *conn = data->conn;
    char buffer[4096];
    gssize bytes_read, bytes_written;

    if (condition & (G_IO_HUP | G_IO_ERR)) {
        goto cleanup;
    }

    bytes_read = SSL_read(conn->upstream_ssl, buffer, sizeof(buffer));
    if (bytes_read <= 0) { // Clean shutdown or error
        goto cleanup;
    }

    bytes_written = SSL_write(conn->client_ssl, buffer, bytes_read);
    if (bytes_written <= 0) { // Error writing to client
        goto cleanup;
    }
    data->upstream_to_client_bytes += bytes_written;

    return G_SOURCE_CONTINUE;

cleanup:
    g_source_remove(data->upstream_source_id);
    data->upstream_source_removed = TRUE;
    if (data->client_source_removed) {
        cleanup_ssl_tunnel(data);
    }
    return G_SOURCE_REMOVE;
}
void start_ssl_tunnel(DeadlightConnection *conn) {
    SslTunnelData *data = g_new0(SslTunnelData, 1);
    data->conn = conn;

    // The FDs and GSocketConnections are already set up. We just need to wrap them for GSource.
    conn->client_fd = g_socket_get_fd(g_socket_connection_get_socket(G_SOCKET_CONNECTION(conn->client_connection)));
    conn->upstream_fd = g_socket_get_fd(g_socket_connection_get_socket(G_SOCKET_CONNECTION(conn->upstream_connection)));

    conn->client_channel = g_io_channel_unix_new(conn->client_fd);
    conn->upstream_channel = g_io_channel_unix_new(conn->upstream_fd);

    g_io_channel_set_encoding(conn->client_channel, NULL, NULL);
    g_io_channel_set_encoding(conn->upstream_channel, NULL, NULL);

    g_io_channel_set_buffered(conn->client_channel, FALSE);
    g_io_channel_set_buffered(conn->upstream_channel, FALSE);


    // Create and attach the client->upstream watch
    GSource *client_source = g_io_create_watch(conn->client_channel, G_IO_IN | G_IO_HUP | G_IO_ERR);
    g_source_set_callback(client_source, (GSourceFunc)client_to_upstream_ssl_cb, data, NULL);
    data->client_source_id = g_source_attach(client_source, g_main_context_get_thread_default());
    g_source_unref(client_source);

    // Create and attach the upstream->client watch
    GSource *upstream_source = g_io_create_watch(conn->upstream_channel, G_IO_IN | G_IO_HUP | G_IO_ERR);
    g_source_set_callback(upstream_source, (GSourceFunc)upstream_to_client_ssl_cb, data, NULL);
    data->upstream_source_id = g_source_attach(upstream_source, g_main_context_get_thread_default());
    g_source_unref(upstream_source);
}