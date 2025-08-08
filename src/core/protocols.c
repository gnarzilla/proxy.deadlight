/**
 * Deadlight Proxy v4.0 - Protocol Manager
 *
 * Manages registration and detection of protocol handlers.
 */
#include "deadlight.h"

// For registering protocol handlers
#include "protocols/http.h"
#include "protocols/imap.h" // We will create this file soon
// #include "protocols/socks.h" // In the future, you'd add this

static GList *protocol_handlers = NULL;

// Public function to register a handler
void deadlight_protocol_register(const DeadlightProtocolHandler *handler) {
    protocol_handlers = g_list_append(protocol_handlers, (gpointer)handler);
    g_info("Registered protocol handler: %s", handler->name);
}

/**
 * Initialize and register all built-in protocol handlers.
 * This is called once at startup from main.c.
 */
void deadlight_protocols_init(DeadlightContext *context) {
    g_info("Initializing protocol handlers...");

    // Register your handlers here
    deadlight_register_http_handler();
    deadlight_register_imap_handler(); // We will implement this

    g_info("%d protocol handlers registered.", g_list_length(protocol_handlers));
}

/**
 * Iterates through registered handlers to find one that can
 * process the incoming data.
 */
const DeadlightProtocolHandler* deadlight_protocol_detect_and_assign(DeadlightConnection *conn, const guint8 *data, gsize length) {
    for (GList *l = protocol_handlers; l != NULL; l = l->next) {
        const DeadlightProtocolHandler *handler = l->data;
        if (handler->detect(data, length)) {
            conn->protocol = handler->protocol_id;
            conn->handler = handler;
            return handler;
        }
    }
    return NULL;
}


/**
 * Convert protocol enum to string (your existing useful function)
 */
const gchar *deadlight_protocol_to_string(DeadlightProtocol protocol) {
    switch (protocol) {
        case DEADLIGHT_PROTOCOL_HTTP: return "HTTP";
        case DEADLIGHT_PROTOCOL_HTTPS: return "HTTPS";
        case DEADLIGHT_PROTOCOL_SOCKS4: return "SOCKS4";
        case DEADLIGHT_PROTOCOL_SOCKS5: return "SOCKS5";
        case DEADLIGHT_PROTOCOL_CONNECT: return "CONNECT";
        case DEADLIGHT_PROTOCOL_WEBSOCKET: return "WebSocket";
        case DEADLIGHT_PROTOCOL_IMAP: return "IMAP"; // Add new protocol
        default: return "Unknown";
    }
}