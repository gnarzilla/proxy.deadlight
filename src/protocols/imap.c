// in src/protocols/imap.c

#include "imap.h"
#include <ctype.h>

// Forward declarations - Updated signatures
static gsize imap_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult imap_handle(DeadlightConnection *conn, GError **error);
static void imap_cleanup(DeadlightConnection *conn);

// The handler object - This will now compile without warnings
static const DeadlightProtocolHandler imap_protocol_handler = {
    .name = "IMAP",
    .protocol_id = DEADLIGHT_PROTOCOL_IMAP,
    .detect = imap_detect,
    .handle = imap_handle, // Correctly matches the new function pointer type
    .cleanup = imap_cleanup
};

void deadlight_register_imap_handler(void) {
    deadlight_protocol_register(&imap_protocol_handler);
}

// --- IMPLEMENTATION ---

static gsize imap_detect(const guint8 *data, gsize len) {
    if (len > 2 && (isalnum(data[0]) || data[0] == '*' || data[0] == '+') && data[1] == ' ') {
        return 2;
    }
    return 0;
}

// Updated the function to return DeadlightHandlerResult
static DeadlightHandlerResult imap_handle(DeadlightConnection *conn, GError **error) {
    DeadlightContext *ctx = conn->context;
    g_info("Handling IMAP connection %lu", conn->id);

    const gchar *upstream_host = deadlight_config_get_string(ctx, "imap", "upstream_host", "imap.example.com");
    gint upstream_port = deadlight_config_get_int(ctx, "imap", "upstream_port", 143);

    if (!deadlight_network_connect_upstream(conn, upstream_host, upstream_port, error)) {
        g_warning("IMAP handler failed to connect upstream for conn %lu", conn->id);
        return HANDLER_ERROR; // Return the correct error code
    }

    // deadlight_network_tunnel_data is a synchronous, blocking call.
    if (deadlight_network_tunnel_data(conn, error)) {
        // When it returns, the connection is finished. Tell the caller to clean up now.
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        // The tunnel itself failed.
        return HANDLER_ERROR;
    }
}

static void imap_cleanup(DeadlightConnection *conn) {
    (void)conn;
}