// src/core/ssl_tunnel.c

#include "core/ssl_tunnel.h"
#include "core/logging.h"
#include <openssl/err.h>
#include <unistd.h> // for g_usleep

/**
 * A synchronous, blocking function that shuttles data over two established SSL* handles.
 * It will run in a loop until one side closes the connection or an error occurs.
 * This fits a "one-shot" worker thread model.
 */
gboolean start_ssl_tunnel_blocking(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->client_ssl != NULL, FALSE);
    g_return_val_if_fail(conn->upstream_ssl != NULL, FALSE);

    log_info("Connection %lu: Starting synchronous SSL tunnel.", conn->id);
    conn->state = DEADLIGHT_STATE_TUNNELING;

    // Use a large buffer for SSL/TLS records
    unsigned char buffer[16384];
    gboolean running = TRUE;
    
    while (running) {
        int ret;
        int ssl_error;
        gboolean data_transferred = FALSE;

        // --- Check for data from Client -> Upstream ---
        ret = SSL_read(conn->client_ssl, buffer, sizeof(buffer));
        if (ret > 0) {
            // We read data from the client, now write it to the upstream
            SSL_write(conn->upstream_ssl, buffer, ret);
            conn->bytes_client_to_upstream += ret;
            data_transferred = TRUE;
        } else {
            ssl_error = SSL_get_error(conn->client_ssl, ret);
            if (ssl_error == SSL_ERROR_ZERO_RETURN || ssl_error == SSL_ERROR_SYSCALL) {
                running = FALSE; // Connection closed cleanly or by error
            }
            // SSL_ERROR_WANT_READ/WRITE is normal for non-blocking, just means no data yet
        }

        // --- Check for data from Upstream -> Client ---
        ret = SSL_read(conn->upstream_ssl, buffer, sizeof(buffer));
        if (ret > 0) {
            // We read data from upstream, now write it to the client
            SSL_write(conn->client_ssl, buffer, ret);
            conn->bytes_upstream_to_client += ret;
            data_transferred = TRUE;
        } else {
            ssl_error = SSL_get_error(conn->upstream_ssl, ret);
            if (ssl_error == SSL_ERROR_ZERO_RETURN || ssl_error == SSL_ERROR_SYSCALL) {
                running = FALSE; // Connection closed cleanly or by error
            }
            // SSL_ERROR_WANT_READ/WRITE is normal for non-blocking, just means no data yet
        }
        
        // If the loop is still running but nothing happened, sleep briefly to avoid burning CPU
        if (running && !data_transferred) {
            g_usleep(10000); // 10ms
        }
    }

    log_info("Connection %lu: SSL tunnel closed (client->upstream: %.2f KB, upstream->client: %.2f KB)",
             conn->id,
             (double)conn->bytes_client_to_upstream / 1024.0,
             (double)conn->bytes_upstream_to_client / 1024.0);

    conn->state = DEADLIGHT_STATE_CLOSING;
    return TRUE; // The tunnel finished its job.
}