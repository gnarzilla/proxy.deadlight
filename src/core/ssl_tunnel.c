// src/core/ssl_tunnel.c

#include "ssl_tunnel.h"
#include "deadlight.h"
#include <glib.h>
#include <gio/gio.h>

/**
 * A synchronous, blocking function that shuttles data over two established GTlsConnection handles.
 * It will run in a loop until one side closes the connection or an error occurs.
 */
gboolean start_ssl_tunnel_blocking(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->client_tls != NULL, FALSE);
    g_return_val_if_fail(conn->upstream_tls != NULL, FALSE);

    g_info("Connection %lu: Starting synchronous TLS tunnel.", conn->id);
    conn->state = DEADLIGHT_STATE_TUNNELING;

    // Get streams from TLS connections
    GInputStream *client_input = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_tls));
    GOutputStream *client_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_tls));
    GInputStream *upstream_input = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_tls));
    GOutputStream *upstream_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_tls));

    guchar buffer[16384];
    gboolean running = TRUE;
    
    while (running) {
        GError *local_error = NULL;
        gssize bytes_read, bytes_written;
        gboolean data_transferred = FALSE;

        // Client -> Upstream
        if (g_pollable_input_stream_is_readable(G_POLLABLE_INPUT_STREAM(client_input))) {
            bytes_read = g_pollable_input_stream_read_nonblocking(
                G_POLLABLE_INPUT_STREAM(client_input),
                buffer, sizeof(buffer),
                NULL, &local_error
            );
            
            if (bytes_read > 0) {
                bytes_written = g_output_stream_write_all(
                    upstream_output, buffer, bytes_read, 
                    NULL, NULL, &local_error
                );
                if (bytes_written) {
                    conn->bytes_client_to_upstream += bytes_read;
                    data_transferred = TRUE;
                    g_output_stream_flush(upstream_output, NULL, NULL);
                }
            } else if (bytes_read == 0) {
                g_debug("Connection %lu: Client closed TLS connection", conn->id);
                running = FALSE;
            } else if (local_error) {
                if (g_error_matches(local_error, G_TLS_ERROR, G_TLS_ERROR_EOF)) {
                    g_debug("Connection %lu: Client TLS EOF", conn->id);
                    running = FALSE;
                } else if (!g_error_matches(local_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    g_debug("Connection %lu: Client read error: %s", conn->id, local_error->message);
                    running = FALSE;
                }
                g_clear_error(&local_error);
            }
        }

        // Upstream -> Client
        if (running && g_pollable_input_stream_is_readable(G_POLLABLE_INPUT_STREAM(upstream_input))) {
            bytes_read = g_pollable_input_stream_read_nonblocking(
                G_POLLABLE_INPUT_STREAM(upstream_input),
                buffer, sizeof(buffer),
                NULL, &local_error
            );
            
            if (bytes_read > 0) {
                bytes_written = g_output_stream_write_all(
                    client_output, buffer, bytes_read,
                    NULL, NULL, &local_error
                );
                if (bytes_written) {
                    conn->bytes_upstream_to_client += bytes_read;
                    data_transferred = TRUE;
                    g_output_stream_flush(client_output, NULL, NULL);
                }
            } else if (bytes_read == 0) {
                g_debug("Connection %lu: Upstream closed TLS connection", conn->id);
                running = FALSE;
            } else if (local_error) {
                if (g_error_matches(local_error, G_TLS_ERROR, G_TLS_ERROR_EOF)) {
                    g_debug("Connection %lu: Upstream TLS EOF", conn->id);
                    running = FALSE;
                } else if (!g_error_matches(local_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    g_debug("Connection %lu: Upstream read error: %s", conn->id, local_error->message);
                    running = FALSE;
                }
                g_clear_error(&local_error);
            }
        }

        // If no data transferred, sleep briefly to avoid CPU spinning
        if (running && !data_transferred) {
            g_usleep(10000); // 10ms
        }
    }

    g_info("Connection %lu: TLS tunnel closed (client->upstream: %lu B, upstream->client: %lu B)",
           conn->id, conn->bytes_client_to_upstream, conn->bytes_upstream_to_client);

    conn->state = DEADLIGHT_STATE_CLOSING;
    return TRUE;
}