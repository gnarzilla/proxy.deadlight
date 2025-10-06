/**
 * Deadlight VPN Gateway - Header
 * Kernel TCP-based VPN implementation (no lwIP)
 */
#ifndef DEADLIGHT_VPN_GATEWAY_H
#define DEADLIGHT_VPN_GATEWAY_H

#include <glib.h>
#include <gio/gio.h>
#include "core/deadlight.h"

// Forward declarations
typedef struct _VPNSession VPNSession;

// TCP session states
typedef enum {
    VPN_TCP_CLOSED = 0,
    VPN_TCP_SYN_SENT,
    VPN_TCP_SYN_RECEIVED,
    VPN_TCP_ESTABLISHED,
    VPN_TCP_FIN_WAIT_1,
    VPN_TCP_FIN_WAIT_2,
    VPN_TCP_CLOSING,
    VPN_TCP_TIME_WAIT,
    VPN_TCP_CLOSE_WAIT,
    VPN_TCP_LAST_ACK
} VPNTCPState;

// VPN session tracking
struct _VPNSession {
    // Connection identifiers
    guint32 client_ip;
    guint16 client_port;
    guint32 dest_ip;
    guint16 dest_port;
    gchar *session_key;
    
    // TCP state
    VPNTCPState state;
    guint32 seq;          // Our sequence number
    guint32 ack;          // Their sequence number
    guint32 isn;          // Initial sequence number
    
    // Upstream connection
    GSocketConnection *upstream_conn;
    guint upstream_watch_id;
    
    // Timestamps
    gint64 created_at;
    gint64 last_activity;
    
    // Back reference
    DeadlightVPNManager *vpn;
};

// VPN Manager
struct _DeadlightVPNManager {
    DeadlightContext *context;
    
    // TUN device
    gint tun_fd;
    GIOChannel *tun_channel;
    guint tun_watch_id;
    gchar *tun_device_name;
    
    // Session tracking
    GHashTable *sessions;  // session_key -> VPNSession
    GMutex sessions_mutex;
    
    // Configuration
    gchar *gateway_ip;
    gchar *client_subnet;
    gchar *netmask;
    
    // Statistics
    guint64 total_connections;
    guint64 active_connections;
    guint64 bytes_sent;
    guint64 bytes_received;

    guint watch_id;
};

// Public API
gboolean deadlight_vpn_gateway_init(DeadlightContext *context, GError **error);
void deadlight_vpn_gateway_cleanup(DeadlightContext *context);
void deadlight_vpn_gateway_get_stats(DeadlightContext *context,
                                    guint64 *active_connections,
                                    guint64 *total_connections,
                                    guint64 *bytes_sent,
                                    guint64 *bytes_received);

#endif // DEADLIGHT_VPN_GATEWAY_H