// src/core/ssl_tunnel.c

#include "ssl_tunnel.h"
#include "deadlight.h"
#include <glib.h>
#include <gio/gio.h>
#include <errno.h>

gboolean start_ssl_tunnel_blocking(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->client_tls != NULL, FALSE);
    g_return_val_if_fail(conn->upstream_tls != NULL, FALSE);
    g_return_val_if_fail(G_IS_SOCKET_CONNECTION(conn->client_connection), FALSE);
    g_return_val_if_fail(G_IS_SOCKET_CONNECTION(conn->upstream_connection), FALSE);

    g_info("Connection %lu: Starting TLS tunnel.", conn->id);
    conn->state = DEADLIGHT_STATE_TUNNELING;

    GInputStream  *client_input    = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_tls));
    GOutputStream *client_output   = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_tls));
    GInputStream  *upstream_input  = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_tls));
    GOutputStream *upstream_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_tls));

    GSocket *client_socket   = g_socket_connection_get_socket(G_SOCKET_CONNECTION(conn->client_connection));
    GSocket *upstream_socket = g_socket_connection_get_socket(G_SOCKET_CONNECTION(conn->upstream_connection));

    GPollFD fds[2];
    fds[0].fd     = g_socket_get_fd(client_socket);
    fds[0].events = G_IO_IN;
    fds[1].fd     = g_socket_get_fd(upstream_socket);
    fds[1].events = G_IO_IN;

    // Separate buffers per direction — makes data flow explicit and safe
    // against future refactors that might reorder the two halves.
    guchar client_buf[16384];
    guchar upstream_buf[16384];

    gboolean running     = TRUE;
    gboolean clean_close = FALSE;

    while (running && !conn->should_stop) {
        int ret = g_poll(fds, 2, 1000);

        if (ret < 0) {
            if (errno == EINTR) continue;
            g_warning("Connection %lu: g_poll() error: %s", conn->id, g_strerror(errno));
            break;
        }

        if (ret == 0) {
            // Timeout — loop and check should_stop again
            continue;
        }

        GError *local_error = NULL;
        gssize  bytes_read;
        gsize   bytes_written;

        // --- Client -> Upstream ---
        if (fds[0].revents & (G_IO_IN | G_IO_HUP | G_IO_ERR)) {
            bytes_read = g_pollable_input_stream_read_nonblocking(
                G_POLLABLE_INPUT_STREAM(client_input),
                client_buf, sizeof(client_buf), NULL, &local_error
            );

            if (bytes_read > 0) {
                gboolean write_ok = g_output_stream_write_all(
                    upstream_output, client_buf, bytes_read,
                    &bytes_written, NULL, &local_error
                );
                if (write_ok) {
                    conn->bytes_client_to_upstream += bytes_written;
                    GError *flush_err = NULL;
                    if (!g_output_stream_flush(upstream_output, NULL, &flush_err)) {
                        g_debug("Connection %lu: Upstream flush error: %s",
                                conn->id, flush_err ? flush_err->message : "unknown");
                        g_clear_error(&flush_err);
                        running = FALSE;
                    }
                } else {
                    g_debug("Connection %lu: Upstream write failed: %s",
                            conn->id, local_error ? local_error->message : "unknown");
                    g_clear_error(&local_error);
                    running = FALSE;
                }
            } else if (bytes_read == 0 || (fds[0].revents & G_IO_HUP)) {
                g_debug("Connection %lu: Client TLS EOF", conn->id);
                clean_close = TRUE;
                running = FALSE;
            } else if (local_error) {
                if (g_error_matches(local_error, G_TLS_ERROR, G_TLS_ERROR_EOF)) {
                    g_debug("Connection %lu: Client TLS EOF", conn->id);
                    clean_close = TRUE;
                } else if (!g_error_matches(local_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    g_debug("Connection %lu: Client read error: %s",
                            conn->id, local_error->message);
                    if (error && *error == NULL) {
                        g_propagate_error(error, local_error);
                        local_error = NULL;
                    }
                }
                g_clear_error(&local_error);
                if (!g_error_matches(local_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
                    running = FALSE;
            }
        }

        // --- Upstream -> Client ---
        if (running && (fds[1].revents & (G_IO_IN | G_IO_HUP | G_IO_ERR))) {
            bytes_read = g_pollable_input_stream_read_nonblocking(
                G_POLLABLE_INPUT_STREAM(upstream_input),
                upstream_buf, sizeof(upstream_buf), NULL, &local_error
            );

            if (bytes_read > 0) {
                gboolean write_ok = g_output_stream_write_all(
                    client_output, upstream_buf, bytes_read,
                    &bytes_written, NULL, &local_error
                );
                if (write_ok) {
                    conn->bytes_upstream_to_client += bytes_written;
                    GError *flush_err = NULL;
                    if (!g_output_stream_flush(client_output, NULL, &flush_err)) {
                        g_debug("Connection %lu: Client flush error: %s",
                                conn->id, flush_err ? flush_err->message : "unknown");
                        g_clear_error(&flush_err);
                        running = FALSE;
                    }
                } else {
                    g_debug("Connection %lu: Client write failed: %s",
                            conn->id, local_error ? local_error->message : "unknown");
                    g_clear_error(&local_error);
                    running = FALSE;
                }
            } else if (bytes_read == 0 || (fds[1].revents & G_IO_HUP)) {
                g_debug("Connection %lu: Upstream closed TLS connection", conn->id);
                clean_close = TRUE;
                running = FALSE;
            } else if (local_error) {
                if (g_error_matches(local_error, G_TLS_ERROR, G_TLS_ERROR_EOF)) {
                    g_debug("Connection %lu: Upstream TLS EOF", conn->id);
                    clean_close = TRUE;
                } else if (!g_error_matches(local_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    g_debug("Connection %lu: Upstream read error: %s",
                            conn->id, local_error->message);
                    if (error && *error == NULL) {
                        g_propagate_error(error, local_error);
                        local_error = NULL;
                    }
                }
                g_clear_error(&local_error);
                if (!g_error_matches(local_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
                    running = FALSE;
            }
        }
    }

    g_info("Connection %lu: TLS tunnel closed (client->upstream: %lu B, upstream->client: %lu B)",
           conn->id, conn->bytes_client_to_upstream, conn->bytes_upstream_to_client);

    // CLOSING = clean EOF or graceful shutdown signal → eligible for pooling.
    // TUNNELING (unchanged) = error close → cleanup_connection_internal will
    // not pool this connection since it gates on state == DEADLIGHT_STATE_CLOSING.
    if (clean_close || conn->should_stop) {
        conn->state = DEADLIGHT_STATE_CLOSING;
    }

    return TRUE;
}