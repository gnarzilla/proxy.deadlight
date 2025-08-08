// in src/protocols/imap.c

#include "imap.h"
#include <ctype.h>

// Forward declarations
static gsize imap_detect(const guint8 *data, gsize len);
static gboolean imap_handle(DeadlightConnection *conn, GError **error);
static void imap_cleanup(DeadlightConnection *conn);

// The handler object
static const DeadlightProtocolHandler imap_protocol_handler = {
    .name = "IMAP",
    .protocol_id = DEADLIGHT_PROTOCOL_IMAP,
    .detect = imap_detect,
    .handle = imap_handle,
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

static gboolean imap_handle(DeadlightConnection *conn, GError **error) {
    DeadlightContext *ctx = conn->context;
    g_info("Handling IMAP connection %lu", conn->id);

    const gchar *upstream_host = deadlight_config_get_string(ctx, "imap", "upstream_host", "imap.example.com");
    gint upstream_port = deadlight_config_get_int(ctx, "imap", "upstream_port", 143);

    if (!deadlight_network_connect_upstream(conn, upstream_host, upstream_port, error)) {

        g_warning("IMAP handler failed to connect upstream for conn %lu", conn->id);
        return FALSE;
    }

    // For now, just tunnel the data
    return deadlight_network_tunnel_data(conn, error);
}
static void imap_cleanup(DeadlightConnection *conn) {
    // This silences the unused parameter warning for now
    (void)conn; 
    // In the future, we'll free any IMAP-specific data stored in conn->protocol_data
}