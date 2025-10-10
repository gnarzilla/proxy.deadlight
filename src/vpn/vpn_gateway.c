/**
 * Deadlight VPN Gateway - Kernel TCP Implementation
 * Uses real kernel sockets, no userspace TCP stack
 * Phase 1: IPv4 TCP/UDP Support
 */
#include "vpn_gateway.h"
#include "core/deadlight.h"
#include "core/logging.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

//=============================================================================
// IP/TCP Header Structures and Constants
//=============================================================================

// TCP flags
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

// IP header (simplified, 20 bytes without options)
struct ip_header {
    guint8 version_ihl;      // Version (4 bits) + IHL (4 bits)
    guint8 tos;              // Type of service
    guint16 total_length;    // Total length
    guint16 identification;  // Identification
    guint16 flags_offset;    // Flags (3 bits) + Fragment offset (13 bits)
    guint8 ttl;              // Time to live
    guint8 protocol;         // Protocol (TCP=6, UDP=17, ICMP=1)
    guint16 checksum;        // Header checksum
    guint32 src_addr;        // Source address
    guint32 dest_addr;       // Destination address
} __attribute__((packed));

// TCP header (simplified, 20 bytes without options)
struct tcp_header {
    guint16 src_port;        // Source port
    guint16 dest_port;       // Destination port
    guint32 seq_num;         // Sequence number
    guint32 ack_num;         // Acknowledgment number
    guint8 data_offset_flags;// Data offset (4 bits) + Reserved (3 bits) + Flags (1 bit)
    guint8 flags;            // Flags: FIN, SYN, RST, PSH, ACK, URG
    guint16 window_size;     // Window size
    guint16 checksum;        // Checksum
    guint16 urgent_pointer;  // Urgent pointer
} __attribute__((packed));

// IPv6 header (40 bytes fixed)
struct ipv6_header {
    guint32 version_tc_fl;   // Version(4) + Traffic class(8) + Flow label(20)
    guint16 payload_length;  // Payload length
    guint8 next_header;      // Next header (TCP=6, UDP=17, ICMPv6=58)
    guint8 hop_limit;        // Hop limit (like TTL)
    struct in6_addr src_addr;  // Source address (128 bits)
    struct in6_addr dest_addr; // Destination address (128 bits)
} __attribute__((packed));

// UDP header (8 bytes)
struct udp_header {
    guint16 src_port;
    guint16 dest_port;
    guint16 length;
    guint16 checksum;
} __attribute__((packed));

// VPNUDPSession is defined in vpn_gateway.h
// No need to redefine it here

//=============================================================================
// Forward Declarations
//=============================================================================

static gint create_tun_device(const gchar *dev_name, GError **error);
static gboolean configure_tun_device(const gchar *dev_name, const gchar *ip,
                                    const gchar *netmask, GError **error);
static gboolean on_tun_readable(GIOChannel *source, GIOCondition condition,
                               gpointer user_data);
static gboolean on_upstream_readable(GIOChannel *source, GIOCondition condition,
                                    gpointer user_data);
static gboolean on_udp_upstream_readable(GIOChannel *source, GIOCondition condition,
                                        gpointer user_data);
static void handle_ip_packet(DeadlightVPNManager *vpn, guint8 *packet,
                             gsize packet_len);
static void handle_tcp_packet(DeadlightVPNManager *vpn, struct ip_header *ip_hdr,
                              struct tcp_header *tcp_hdr, guint8 *payload,
                              gsize payload_len);
static void handle_udp_packet(DeadlightVPNManager *vpn, struct ip_header *ip_hdr,
                              struct udp_header *udp_hdr, guint8 *payload,
                              gsize payload_len);
static void send_tcp_packet(DeadlightVPNManager *vpn, VPNSession *session,
                           guint8 flags, const guint8 *payload, gsize payload_len);
static void send_udp_packet(DeadlightVPNManager *vpn, VPNUDPSession *session,
                           const guint8 *payload, gsize payload_len);
static guint16 ip_checksum(const void *data, gsize len);
static guint16 tcp_checksum(guint32 src_ip, guint32 dest_ip,
                           const void *tcp_data, gsize tcp_len);
static guint16 udp_checksum(guint32 src_ip, guint32 dest_ip,
                           const void *udp_data, gsize udp_len);
static VPNSession *vpn_session_new(DeadlightVPNManager *vpn, guint32 client_ip,
                                   guint16 client_port, guint32 dest_ip,
                                   guint16 dest_port);
static void vpn_session_free(VPNSession *session);
static VPNUDPSession *vpn_udp_session_new(DeadlightVPNManager *vpn, guint32 client_ip,
                                          guint16 client_port, guint32 dest_ip,
                                          guint16 dest_port);
static void vpn_udp_session_free(VPNUDPSession *session);
static gboolean cleanup_idle_sessions(gpointer user_data);
static gboolean cleanup_idle_udp_sessions(gpointer user_data);
static guint16 tcp6_checksum(const struct in6_addr *src_addr,
                            const struct in6_addr *dest_addr,
                            const void *tcp_data, gsize tcp_len);
static guint16 udp6_checksum(const struct in6_addr *src_addr,
                            const struct in6_addr *dest_addr,
                            const void *udp_data, gsize udp_len);
static void send_tcp6_packet(DeadlightVPNManager *vpn, VPNSession *session,
                            guint8 flags, const guint8 *payload, gsize payload_len);
static void send_udp6_packet(DeadlightVPNManager *vpn, VPNUDPSession *session,
                            const guint8 *payload, gsize payload_len);
static void handle_tcp6_packet(DeadlightVPNManager *vpn, struct ipv6_header *ip6_hdr,
                              struct tcp_header *tcp_hdr, guint8 *payload, gsize payload_len);
static void handle_udp6_packet(DeadlightVPNManager *vpn, struct ipv6_header *ip6_hdr,
                              struct udp_header *udp_hdr, guint8 *payload, gsize payload_len);
static void handle_ipv6_packet(DeadlightVPNManager *vpn, guint8 *packet, gsize packet_len);

//=============================================================================
// Helper functions
//=============================================================================


//=============================================================================
// TUN Device Management
//=============================================================================

static gint create_tun_device(const gchar *dev_name, GError **error) {
    struct ifreq ifr;
    gint fd;

    // First, try to delete any existing device with this name
    if (dev_name) {
        gchar *cmd = g_strdup_printf("ip link delete %s 2>/dev/null", dev_name);
        int ret = system(cmd);
        (void)ret;  // Explicitly ignore return value
        g_free(cmd);
        
        // Give the kernel a moment to clean up
        g_usleep(100000);  // 100ms
    }

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno),
                   "Failed to open /dev/net/tun: %s", g_strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (dev_name) {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno),
                   "TUNSETIFF ioctl failed: %s", g_strerror(errno));
        close(fd);
        return -1;
    }

    log_info("VPN: Created TUN device %s (fd=%d)", ifr.ifr_name, fd);
    return fd;
}

static gboolean configure_tun_device(const gchar *dev_name, const gchar *ip,
                                    const gchar *netmask, GError **error) {
    gchar *cmd;
    gint ret;

    // Bring interface up
    cmd = g_strdup_printf("ip link set %s up", dev_name);
    ret = system(cmd);
    g_free(cmd);
    if (ret != 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to bring up %s", dev_name);
        return FALSE;
    }

    // Set IP address
    cmd = g_strdup_printf("ip addr add %s/%s dev %s", ip, netmask, dev_name);
    ret = system(cmd);
    g_free(cmd);
    if (ret != 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to set IP on %s", dev_name);
        return FALSE;
    }

    log_info("VPN: Configured %s with IP %s/%s", dev_name, ip, netmask);
    return TRUE;
}

//=============================================================================
// Checksum Functions
//=============================================================================

static guint16 ip_checksum(const void *data, gsize len) {
    const guint16 *buf = data;
    guint32 sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(guint8 *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (guint16)~sum;
}

static guint16 tcp_checksum(guint32 src_ip, guint32 dest_ip,
                           const void *tcp_data, gsize tcp_len) {
    // TCP pseudo-header (use memcpy to avoid alignment issues)
    guint8 pseudo_buf[12];
    guint32 src_addr_net = htonl(src_ip);
    guint32 dest_addr_net = htonl(dest_ip);
    guint16 tcp_length_net = htons(tcp_len);
    
    memcpy(pseudo_buf + 0, &src_addr_net, 4);
    memcpy(pseudo_buf + 4, &dest_addr_net, 4);
    pseudo_buf[8] = 0;  // zero
    pseudo_buf[9] = IPPROTO_TCP;  // protocol
    memcpy(pseudo_buf + 10, &tcp_length_net, 2);

    guint32 sum = 0;
    const guint16 *buf = (const guint16 *)pseudo_buf;
    gsize len = 12;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    buf = tcp_data;
    len = tcp_len;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(guint8 *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (guint16)~sum;
}

static guint16 udp_checksum(guint32 src_ip, guint32 dest_ip,
                           const void *udp_data, gsize udp_len) {
    // UDP pseudo-header (use memcpy to avoid alignment issues)
    guint8 pseudo_buf[12];
    guint32 src_addr_net = htonl(src_ip);
    guint32 dest_addr_net = htonl(dest_ip);
    guint16 udp_length_net = htons(udp_len);
    
    memcpy(pseudo_buf + 0, &src_addr_net, 4);
    memcpy(pseudo_buf + 4, &dest_addr_net, 4);
    pseudo_buf[8] = 0;  // zero
    pseudo_buf[9] = IPPROTO_UDP;  // protocol
    memcpy(pseudo_buf + 10, &udp_length_net, 2);

    guint32 sum = 0;
    const guint16 *buf = (const guint16 *)pseudo_buf;
    gsize len = 12;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    buf = udp_data;
    len = udp_len;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(guint8 *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (guint16)~sum;
}

static guint16 tcp6_checksum(const struct in6_addr *src_addr,
                            const struct in6_addr *dest_addr,
                            const void *tcp_data, gsize tcp_len) {
    // IPv6 pseudo-header for TCP checksum
    // Format: src_addr(16) + dest_addr(16) + tcp_length(4) + zeros(3) + next_header(1)
    guint8 pseudo_buf[40];  // 16 + 16 + 4 + 3 + 1 = 40 bytes
    
    // Copy source address (128 bits = 16 bytes)
    memcpy(pseudo_buf + 0, src_addr, 16);
    
    // Copy destination address (128 bits = 16 bytes)
    memcpy(pseudo_buf + 16, dest_addr, 16);
    
    // TCP length (32 bits, big-endian)
    guint32 tcp_length_net = htonl(tcp_len);
    memcpy(pseudo_buf + 32, &tcp_length_net, 4);
    
    // Three zero bytes
    pseudo_buf[36] = 0;
    pseudo_buf[37] = 0;
    pseudo_buf[38] = 0;
    
    // Next header (protocol = TCP = 6)
    pseudo_buf[39] = IPPROTO_TCP;

    // Calculate checksum over pseudo-header + TCP segment
    guint32 sum = 0;
    const guint16 *buf = (const guint16 *)pseudo_buf;
    gsize len = 40;

    // Sum pseudo-header
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    // Sum TCP header + data
    buf = tcp_data;
    len = tcp_len;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    // Handle odd byte
    if (len == 1) {
        sum += *(guint8 *)buf;
    }

    // Fold 32-bit sum to 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (guint16)~sum;
}

static guint16 udp6_checksum(const struct in6_addr *src_addr,
                            const struct in6_addr *dest_addr,
                            const void *udp_data, gsize udp_len) {
    // IPv6 pseudo-header for UDP checksum (same format as TCP)
    guint8 pseudo_buf[40];
    
    memcpy(pseudo_buf + 0, src_addr, 16);
    memcpy(pseudo_buf + 16, dest_addr, 16);
    
    guint32 udp_length_net = htonl(udp_len);
    memcpy(pseudo_buf + 32, &udp_length_net, 4);
    
    pseudo_buf[36] = 0;
    pseudo_buf[37] = 0;
    pseudo_buf[38] = 0;
    pseudo_buf[39] = IPPROTO_UDP;

    guint32 sum = 0;
    const guint16 *buf = (const guint16 *)pseudo_buf;
    gsize len = 40;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    buf = udp_data;
    len = udp_len;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(guint8 *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (guint16)~sum;
}

//=============================================================================
// Session Management
//=============================================================================

static VPNSession *vpn_session_new(DeadlightVPNManager *vpn, guint32 client_ip,
                                   guint16 client_port, guint32 dest_ip,
                                   guint16 dest_port) {
    VPNSession *session = g_new0(VPNSession, 1);
    
    // Store IPv4 addresses in IPv4-mapped IPv6 format
    memset(&session->client_ip, 0, sizeof(struct in6_addr));
    session->client_ip.__in6_u.__u6_addr8[10] = 0xFF;
    session->client_ip.__in6_u.__u6_addr8[11] = 0xFF;
    guint32 client_ip_net = htonl(client_ip);
    memcpy(&session->client_ip.__in6_u.__u6_addr8[12], &client_ip_net, 4);
    
    memset(&session->dest_ip, 0, sizeof(struct in6_addr));
    session->dest_ip.__in6_u.__u6_addr8[10] = 0xFF;
    session->dest_ip.__in6_u.__u6_addr8[11] = 0xFF;
    guint32 dest_ip_net = htonl(dest_ip);
    memcpy(&session->dest_ip.__in6_u.__u6_addr8[12], &dest_ip_net, 4);
    
    session->client_port = client_port;
    session->dest_port = dest_port;
    
    // Create session key using dotted notation
    gchar client_str[INET_ADDRSTRLEN];
    gchar dest_str[INET_ADDRSTRLEN];
    struct in_addr tmp;
    tmp.s_addr = htonl(client_ip);
    inet_ntop(AF_INET, &tmp, client_str, INET_ADDRSTRLEN);
    tmp.s_addr = htonl(dest_ip);
    inet_ntop(AF_INET, &tmp, dest_str, INET_ADDRSTRLEN);
    
    session->session_key = g_strdup_printf("%s:%u->%s:%u",
                                          client_str, client_port,
                                          dest_str, dest_port);
    
    session->state = VPN_TCP_CLOSED;
    session->seq = g_random_int();  // Random ISN
    session->isn = session->seq;
    session->ack = 0;
    session->created_at = g_get_monotonic_time();
    session->last_activity = session->created_at;
    session->vpn = vpn;
    session->upstream_conn = NULL;
    session->upstream_watch_id = 0;
    session->retrans_timer_id = 0;
    session->last_packet.data = NULL;
    session->last_packet.len = 0;
    
    return session;
}

static void vpn_session_free(VPNSession *session) {
    if (!session) return;
    
    if (session->upstream_watch_id > 0) {
        g_source_remove(session->upstream_watch_id);
    }
    if (session->retrans_timer_id > 0) {
        g_source_remove(session->retrans_timer_id);
    }
    if (session->upstream_conn) {
        GError *error = NULL;
        g_io_stream_close(G_IO_STREAM(session->upstream_conn), NULL, &error);
        if (error) {
            log_warn("VPN: Error closing upstream for %s: %s", session->session_key, error->message);
            g_error_free(error);
        }
        g_object_unref(session->upstream_conn);
    }
    g_free(session->last_packet.data);
    g_free(session->session_key);
    g_free(session);
}

static VPNUDPSession* vpn_udp_session_new(DeadlightVPNManager *vpn, 
                                          guint32 client_ip, guint16 client_port,
                                          guint32 dest_ip, guint16 dest_port) {
    VPNUDPSession *session = g_new0(VPNUDPSession, 1);
    
    // Store IPv4 addresses in IPv4-mapped IPv6 format
    memset(&session->client_ip, 0, sizeof(struct in6_addr));
    session->client_ip.__in6_u.__u6_addr8[10] = 0xFF;
    session->client_ip.__in6_u.__u6_addr8[11] = 0xFF;
    guint32 client_ip_net = htonl(client_ip);
    memcpy(&session->client_ip.__in6_u.__u6_addr8[12], &client_ip_net, 4);
    
    memset(&session->dest_ip, 0, sizeof(struct in6_addr));
    session->dest_ip.__in6_u.__u6_addr8[10] = 0xFF;
    session->dest_ip.__in6_u.__u6_addr8[11] = 0xFF;
    guint32 dest_ip_net = htonl(dest_ip);
    memcpy(&session->dest_ip.__in6_u.__u6_addr8[12], &dest_ip_net, 4);
    
    session->client_port = client_port;
    session->dest_port = dest_port;
    
    // Create session key
    gchar client_str[INET_ADDRSTRLEN];
    gchar dest_str[INET_ADDRSTRLEN];
    struct in_addr tmp;
    tmp.s_addr = htonl(client_ip);
    inet_ntop(AF_INET, &tmp, client_str, INET_ADDRSTRLEN);
    tmp.s_addr = htonl(dest_ip);
    inet_ntop(AF_INET, &tmp, dest_str, INET_ADDRSTRLEN);
    
    session->session_key = g_strdup_printf("%s:%u->%s:%u",
                                          client_str, client_port,
                                          dest_str, dest_port);
    
    session->last_activity = g_get_monotonic_time();
    session->vpn = vpn;
    session->upstream_socket = NULL;
    session->upstream_watch_id = 0;
    
    return session;
}

static void vpn_udp_session_free(VPNUDPSession *session) {
    if (!session) return;
    
    if (session->upstream_watch_id > 0) {
        g_source_remove(session->upstream_watch_id);
    }
    
    if (session->upstream_socket) {
        g_socket_close(session->upstream_socket, NULL);
        g_object_unref(session->upstream_socket);
    }
    
    g_free(session->session_key);
    g_free(session);
}

static gboolean cleanup_idle_sessions(gpointer user_data) {
    DeadlightVPNManager *vpn = user_data;
    gint64 now = g_get_monotonic_time();
    gint64 timeout = 300 * G_TIME_SPAN_SECOND;  // 5 minutes

    GList *to_remove = NULL;
    g_mutex_lock(&vpn->sessions_mutex);

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, vpn->sessions);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        VPNSession *session = value;
        if ((now - session->last_activity) > timeout) {
            to_remove = g_list_prepend(to_remove, g_strdup(session->session_key));
        }
    }

    for (GList *l = to_remove; l; l = l->next) {
        g_hash_table_remove(vpn->sessions, l->data);
        vpn->active_connections--;
        g_free(l->data);
    }
    g_list_free(to_remove);
    g_mutex_unlock(&vpn->sessions_mutex);

    return G_SOURCE_CONTINUE;
}

static gboolean cleanup_idle_udp_sessions(gpointer user_data) {
    DeadlightVPNManager *vpn = user_data;
    gint64 now = g_get_monotonic_time();
    gint64 timeout = 30 * G_TIME_SPAN_SECOND;  // 30 seconds for UDP (shorter timeout)

    GList *to_remove = NULL;
    g_mutex_lock(&vpn->sessions_mutex);

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, vpn->udp_sessions);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        VPNUDPSession *session = value;
        if ((now - session->last_activity) > timeout) {
            to_remove = g_list_prepend(to_remove, g_strdup(session->session_key));
        }
    }

    guint removed = 0;
    for (GList *l = to_remove; l; l = l->next) {
        g_hash_table_remove(vpn->udp_sessions, l->data);
        removed++;
        g_free(l->data);
    }
    g_list_free(to_remove);
    
    if (removed > 0) {
        log_debug("VPN: Cleaned up %u idle UDP sessions (%u remaining)", 
                 removed, g_hash_table_size(vpn->udp_sessions));
    }
    
    g_mutex_unlock(&vpn->sessions_mutex);

    return G_SOURCE_CONTINUE;
}

//=============================================================================
// Packet Sending Functions
//=============================================================================

static void send_tcp_packet(DeadlightVPNManager *vpn, VPNSession *session,
                           guint8 flags, const guint8 *payload, gsize payload_len) {
    guint8 packet[4096];
    struct ip_header *ip_hdr = (struct ip_header *)packet;
    struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + sizeof(struct ip_header));
    
    gsize ip_hdr_len = sizeof(struct ip_header);
    gsize tcp_hdr_len = sizeof(struct tcp_header);
    gsize total_len = ip_hdr_len + tcp_hdr_len + payload_len;

    if (total_len > sizeof(packet)) {
        log_warn("VPN: UDP packet too large (%zu bytes)", total_len);
        return;  // Don't truncate, just drop oversized packets
    }

    // Extract IPv4 addresses from IPv4-mapped IPv6
    guint32 client_ip, dest_ip;
    memcpy(&client_ip, &session->client_ip.__in6_u.__u6_addr8[12], 4);
    memcpy(&dest_ip, &session->dest_ip.__in6_u.__u6_addr8[12], 4);

    // Build IP header
    memset(ip_hdr, 0, ip_hdr_len);
    ip_hdr->version_ihl = 0x45;  // IPv4, 5-word header
    ip_hdr->total_length = htons(total_len);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_TCP;
    ip_hdr->src_addr = dest_ip;  // We're sending FROM dest TO client
    ip_hdr->dest_addr = client_ip;
    ip_hdr->checksum = ip_checksum(ip_hdr, ip_hdr_len);

    // Build TCP header
    memset(tcp_hdr, 0, tcp_hdr_len);
    tcp_hdr->src_port = htons(session->dest_port);
    tcp_hdr->dest_port = htons(session->client_port);
    tcp_hdr->seq_num = htonl(session->seq);
    tcp_hdr->ack_num = htonl(session->ack);
    tcp_hdr->data_offset_flags = (5 << 4);  // 5-word header
    tcp_hdr->flags = flags;
    tcp_hdr->window_size = htons(65535);

    // Copy payload
    if (payload_len > 0 && payload) {
        memcpy(packet + ip_hdr_len + tcp_hdr_len, payload, payload_len);
    }

    // TCP checksum (convert to host order for checksum function)
    guint32 src_ip_host = ntohl(dest_ip);
    guint32 dst_ip_host = ntohl(client_ip);
    tcp_hdr->checksum = tcp_checksum(src_ip_host, dst_ip_host,
                                    tcp_hdr, tcp_hdr_len + payload_len);

    // Write to TUN
    gssize written = write(vpn->tun_fd, packet, total_len);
    if (written < 0 || (gsize)written != total_len) {
        log_warn("VPN: Failed/partial TUN write: %zd/%zu (%s)", 
                 written, total_len, strerror(errno));
        return;
    }

    vpn->bytes_sent += (guint64)written;

    log_debug("VPN: Sent %s to %s (%zu bytes, SEQ=%u, ACK=%u)",
             (flags & TCP_SYN) ? "SYN-ACK" : (flags & TCP_FIN) ? "FIN" :
             (flags & TCP_RST) ? "RST" : (flags & TCP_PSH) ? "PSH-ACK" : "ACK",
             session->session_key, total_len, session->seq, session->ack);

    // Store for retransmission
    if (flags & (TCP_SYN | TCP_PSH | TCP_FIN)) {
        g_free(session->last_packet.data);
        session->last_packet.data = payload_len ? g_memdup2(payload, payload_len) : NULL;
        session->last_packet.len = payload_len;
        session->last_packet.flags = flags;
        session->last_packet.retries = 0;
        session->last_packet.sent_at = g_get_monotonic_time();
    }
}

static void send_udp6_packet(DeadlightVPNManager *vpn, VPNUDPSession *session,
                            const guint8 *payload, gsize payload_len) {
    guint8 packet[4096];
    struct ipv6_header *ip6_hdr = (struct ipv6_header *)packet;
    struct udp_header *udp_hdr = (struct udp_header *)(packet + sizeof(struct ipv6_header));
    
    gsize ip6_hdr_len = sizeof(struct ipv6_header);
    gsize udp_hdr_len = sizeof(struct udp_header);
    gsize total_len = ip6_hdr_len + udp_hdr_len + payload_len;
    
    if (total_len > sizeof(packet)) {
        log_warn("VPN: IPv6 UDP packet too large (%zu bytes)", total_len);
        return;
    }
    
    // Build IPv6 header
    memset(ip6_hdr, 0, ip6_hdr_len);
    ip6_hdr->version_tc_fl = htonl(0x60000000);  // IPv6
    ip6_hdr->payload_length = htons(udp_hdr_len + payload_len);
    ip6_hdr->next_header = IPPROTO_UDP;
    ip6_hdr->hop_limit = 64;
    memcpy(&ip6_hdr->src_addr, &session->dest_ip, sizeof(struct in6_addr));
    memcpy(&ip6_hdr->dest_addr, &session->client_ip, sizeof(struct in6_addr));
    
    // Build UDP header
    memset(udp_hdr, 0, udp_hdr_len);
    udp_hdr->src_port = htons(session->dest_port);
    udp_hdr->dest_port = htons(session->client_port);
    udp_hdr->length = htons(udp_hdr_len + payload_len);
    
    // Copy payload
    if (payload_len > 0 && payload) {
        memcpy(packet + ip6_hdr_len + udp_hdr_len, payload, payload_len);
    }
    
    // UDP checksum
    struct in6_addr src_copy, dest_copy;
    memcpy(&src_copy, &ip6_hdr->src_addr, sizeof(struct in6_addr));
    memcpy(&dest_copy, &ip6_hdr->dest_addr, sizeof(struct in6_addr));
    udp_hdr->checksum = udp6_checksum(&src_copy, &dest_copy,
                                     udp_hdr, udp_hdr_len + payload_len);
    // Write to TUN
    gssize written = write(vpn->tun_fd, packet, total_len);
    if (written < 0) {
        log_warn("VPN: Failed to write IPv6 UDP packet to TUN: %s", g_strerror(errno));
        return;
    }
    
    vpn->bytes_sent += written;
    
    gchar client_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &session->client_ip, client_str, INET6_ADDRSTRLEN);
    log_debug("VPN: Sent IPv6 UDP reply to [%s]:%u (%zu bytes)", 
             client_str, session->client_port, total_len);
}

static void send_tcp6_packet(DeadlightVPNManager *vpn, VPNSession *session,
                            guint8 flags, const guint8 *payload, gsize payload_len) {
    guint8 packet[4096];
    struct ipv6_header *ip6_hdr = (struct ipv6_header *)packet;
    struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + sizeof(struct ipv6_header));
    
    gsize ip6_hdr_len = sizeof(struct ipv6_header);
    gsize tcp_hdr_len = sizeof(struct tcp_header);
    gsize total_len = ip6_hdr_len + tcp_hdr_len + payload_len;

    if (total_len > sizeof(packet)) {
        log_warn("VPN: IPv6 packet too large (%zu bytes), dropping", total_len);
        return;
    }

    // Build IPv6 header
    memset(ip6_hdr, 0, ip6_hdr_len);
    
    // Version (4 bits) = 6, Traffic class (8 bits) = 0, Flow label (20 bits) = 0
    ip6_hdr->version_tc_fl = htonl(0x60000000);  // 0110 0000 ... = IPv6
    
    // Payload length (does NOT include IPv6 header, only TCP header + data)
    ip6_hdr->payload_length = htons(tcp_hdr_len + payload_len);
    
    ip6_hdr->next_header = IPPROTO_TCP;
    ip6_hdr->hop_limit = 64;
    
    // Source = destination (we're replying FROM the dest TO the client)
    memcpy(&ip6_hdr->src_addr, &session->dest_ip, sizeof(struct in6_addr));
    memcpy(&ip6_hdr->dest_addr, &session->client_ip, sizeof(struct in6_addr));

    // Build TCP header
    memset(tcp_hdr, 0, tcp_hdr_len);
    tcp_hdr->src_port = htons(session->dest_port);
    tcp_hdr->dest_port = htons(session->client_port);
    tcp_hdr->seq_num = htonl(session->seq);
    tcp_hdr->ack_num = htonl(session->ack);
    tcp_hdr->data_offset_flags = (5 << 4);  // 5-word header (20 bytes)
    tcp_hdr->flags = flags;
    tcp_hdr->window_size = htons(65535);
    tcp_hdr->urgent_pointer = 0;

    // Copy payload
    if (payload_len > 0 && payload) {
        memcpy(packet + ip6_hdr_len + tcp_hdr_len, payload, payload_len);
    }

    // TCP checksum for IPv6 (uses pseudo-header)
    struct in6_addr src_copy, dest_copy;
    memcpy(&src_copy, &ip6_hdr->src_addr, sizeof(struct in6_addr));
    memcpy(&dest_copy, &ip6_hdr->dest_addr, sizeof(struct in6_addr));
    tcp_hdr->checksum = tcp6_checksum(&src_copy, &dest_copy,
                                     tcp_hdr, tcp_hdr_len + payload_len);
    // Write to TUN
    gssize written = write(vpn->tun_fd, packet, total_len);
    if (written < 0 || (gsize)written != total_len) {
        log_warn("VPN: Failed/partial TUN write for IPv6: %zd/%zu (%s)", 
                 written, total_len, strerror(errno));
        return;
    }

    vpn->bytes_sent += (guint64)written;

    gchar client_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &session->client_ip, client_str, INET6_ADDRSTRLEN);

    log_debug("VPN: Sent IPv6 %s to [%s]:%u (%zu bytes, SEQ=%u, ACK=%u)",
             (flags & TCP_SYN) ? "SYN-ACK" : (flags & TCP_FIN) ? "FIN" :
             (flags & TCP_RST) ? "RST" : (flags & TCP_PSH) ? "PSH-ACK" : "ACK",
             client_str, session->client_port, total_len, session->seq, session->ack);

    // Store for retransmission
    if (flags & (TCP_SYN | TCP_PSH | TCP_FIN)) {
        g_free(session->last_packet.data);
        session->last_packet.data = payload_len ? g_memdup2(payload, payload_len) : NULL;
        session->last_packet.len = payload_len;
        session->last_packet.flags = flags;
        session->last_packet.retries = 0;
        session->last_packet.sent_at = g_get_monotonic_time();
    }
}

static void send_udp_packet(DeadlightVPNManager *vpn, VPNUDPSession *session,
                           const guint8 *payload, gsize payload_len) {
    guint8 packet[4096];
    struct ip_header *ip_hdr = (struct ip_header *)packet;
    struct udp_header *udp_hdr = (struct udp_header *)(packet + sizeof(struct ip_header));
    
    gsize ip_hdr_len = sizeof(struct ip_header);
    gsize udp_hdr_len = sizeof(struct udp_header);
    gsize total_len = ip_hdr_len + udp_hdr_len + payload_len;
    
    if (total_len > sizeof(packet)) {
        log_warn("VPN: UDP packet too large (%zu bytes)", total_len);
        return;
    }
    
    // Extract IPv4 addresses from IPv4-mapped IPv6
    guint32 client_ip, dest_ip;
    memcpy(&client_ip, &session->client_ip.__in6_u.__u6_addr8[12], 4);
    memcpy(&dest_ip, &session->dest_ip.__in6_u.__u6_addr8[12], 4);
    
    // Build IP header
    memset(ip_hdr, 0, ip_hdr_len);
    ip_hdr->version_ihl = 0x45;
    ip_hdr->total_length = htons(total_len);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_UDP;
    ip_hdr->src_addr = dest_ip;  // FROM dest TO client
    ip_hdr->dest_addr = client_ip;
    ip_hdr->checksum = ip_checksum(ip_hdr, ip_hdr_len);
    
    // Build UDP header
    memset(udp_hdr, 0, udp_hdr_len);
    udp_hdr->src_port = htons(session->dest_port);
    udp_hdr->dest_port = htons(session->client_port);
    udp_hdr->length = htons(udp_hdr_len + payload_len);
    
    // Copy payload
    if (payload_len > 0 && payload) {
        memcpy(packet + ip_hdr_len + udp_hdr_len, payload, payload_len);
    }
    
    // UDP checksum (convert to host order)
    guint32 src_ip_host = ntohl(dest_ip);
    guint32 dst_ip_host = ntohl(client_ip);
    udp_hdr->checksum = udp_checksum(src_ip_host, dst_ip_host,
                                    udp_hdr, udp_hdr_len + payload_len);
    
    // Write to TUN
    gssize written = write(vpn->tun_fd, packet, total_len);
    if (written < 0) {
        log_warn("VPN: Failed to write UDP packet to TUN: %s", g_strerror(errno));
        return;
    }
    
    vpn->bytes_sent += written;
    log_debug("VPN: Sent UDP reply to %s (%zu bytes)", session->session_key, total_len);
}

//=============================================================================
// Packet Receiving Functions
//=============================================================================

static gboolean on_upstream_readable(GIOChannel *source, GIOCondition condition,
                                    gpointer user_data) {
    VPNSession *session = user_data;
    DeadlightVPNManager *vpn = session->vpn;
    (void)source;

    if (condition & (G_IO_HUP | G_IO_ERR)) {
        log_debug("VPN: Upstream closed for %s", session->session_key);
        send_tcp_packet(vpn, session, TCP_FIN | TCP_ACK, NULL, 0);
        session->seq++;
        session->state = VPN_TCP_FIN_WAIT_1;
        return G_SOURCE_REMOVE;
    }

    // Read data from upstream
    guint8 buffer[8192];
    GInputStream *input = g_io_stream_get_input_stream(G_IO_STREAM(session->upstream_conn));
    GError *error = NULL;
    gssize bytes = g_input_stream_read(input, buffer, sizeof(buffer), NULL, &error);

    if (bytes > 0) {
        send_tcp_packet(vpn, session, TCP_PSH | TCP_ACK, buffer, bytes);
        session->seq += bytes;
        session->last_activity = g_get_monotonic_time();
        log_debug("VPN: Forwarded %zd bytes from upstream to %s", bytes, session->session_key);
    } else if (bytes == 0 || error) {
        if (error) {
            log_debug("VPN: Upstream read error for %s: %s", session->session_key, error->message);
            g_error_free(error);
        }
        send_tcp_packet(vpn, session, TCP_FIN | TCP_ACK, NULL, 0);
        session->seq++;
        session->state = VPN_TCP_FIN_WAIT_1;
        return G_SOURCE_REMOVE;
    }

    return G_SOURCE_CONTINUE;
}

static gboolean on_udp_upstream_readable(GIOChannel *source, GIOCondition condition,
                                        gpointer user_data) {
    VPNUDPSession *session = user_data;
    DeadlightVPNManager *vpn = session->vpn;
    (void)source;
    
    if (condition & (G_IO_HUP | G_IO_ERR)) {
        log_debug("VPN: UDP upstream closed/error for %s (condition=%d)", 
                 session->session_key, condition);
        return G_SOURCE_REMOVE;
    }
    
    if (!(condition & G_IO_IN)) {
        log_debug("VPN: UDP callback but no data ready for %s", session->session_key);
        return G_SOURCE_CONTINUE;
    }
    
    guint8 buffer[2048];
    GError *error = NULL;
    gssize bytes = g_socket_receive(session->upstream_socket, (gchar *)buffer,
                                   sizeof(buffer), NULL, &error);
    
    if (bytes > 0) {
        // Determine if this is IPv4 or IPv6 session by checking address family
        gboolean is_ipv6 = FALSE;
        
        // Check if it's an IPv4-mapped IPv6 address
        if (IN6_IS_ADDR_V4MAPPED(&session->client_ip)) {
            is_ipv6 = FALSE;  // IPv4
        } else {
            is_ipv6 = TRUE;   // Native IPv6
        }
        
        if (is_ipv6) {
            send_udp6_packet(vpn, session, buffer, bytes);
        } else {
            send_udp_packet(vpn, session, buffer, bytes);
        }
        
        session->last_activity = g_get_monotonic_time();
        log_debug("VPN: Forwarded %zd UDP bytes from upstream to %s", 
                 bytes, session->session_key);
    } else if (bytes == 0) {
        log_debug("VPN: UDP upstream EOF for %s", session->session_key);
        return G_SOURCE_REMOVE;
    } else if (error) {
        if (error->code != G_IO_ERROR_WOULD_BLOCK) {
            log_debug("VPN: UDP upstream read error for %s: %s", 
                     session->session_key, error->message);
            g_error_free(error);
            return G_SOURCE_REMOVE;
        }
        g_error_free(error);
    }
    
    return G_SOURCE_CONTINUE;
}

//=============================================================================
// Protocol Handlers
//=============================================================================

static void handle_tcp_packet(DeadlightVPNManager *vpn, struct ip_header *ip_hdr,
                              struct tcp_header *tcp_hdr, guint8 *payload,
                              gsize payload_len) {
    guint32 client_ip = ntohl(ip_hdr->src_addr);
    guint32 dest_ip = ntohl(ip_hdr->dest_addr);
    guint16 client_port = ntohs(tcp_hdr->src_port);
    guint16 dest_port = ntohs(tcp_hdr->dest_port);
    guint8 flags = tcp_hdr->flags;
    guint32 recv_seq = ntohl(tcp_hdr->seq_num);
    guint32 recv_ack = ntohl(tcp_hdr->ack_num);

    gchar client_str[INET_ADDRSTRLEN];
    gchar dest_str[INET_ADDRSTRLEN];
    struct in_addr tmp;
    tmp.s_addr = ip_hdr->src_addr;
    inet_ntop(AF_INET, &tmp, client_str, INET_ADDRSTRLEN);
    tmp.s_addr = ip_hdr->dest_addr;
    inet_ntop(AF_INET, &tmp, dest_str, INET_ADDRSTRLEN);

    log_debug("VPN: TCP packet: %s:%u -> %s:%u flags=0x%02x seq=%u ack=%u payload=%zu",
             client_str, client_port, dest_str, dest_port, flags, recv_seq, recv_ack, payload_len);

    gchar *key = g_strdup_printf("%s:%u->%s:%u", client_str, client_port, dest_str, dest_port);

    g_mutex_lock(&vpn->sessions_mutex);
    VPNSession *session = g_hash_table_lookup(vpn->sessions, key);

    // Handle SYN (new connection)
    if (!session && (flags & TCP_SYN) && !(flags & TCP_ACK)) {
        if (vpn->active_connections >= 1000) {
            log_warn("VPN: Max sessions reached, rejecting %s", key);
            g_mutex_unlock(&vpn->sessions_mutex);
            g_free(key);
            return;
        }
        
        session = vpn_session_new(vpn, client_ip, client_port, dest_ip, dest_port);
        session->ack = recv_seq + 1;
        session->state = VPN_TCP_SYN_RECEIVED;

        // Create real kernel socket
        GError *error = NULL;
        log_info("VPN: Connecting to upstream: %s:%u", dest_str, dest_port);
        
        session->upstream_conn = deadlight_network_connect_tcp(vpn->context, dest_str, dest_port, &error);

        if (!session->upstream_conn) {
            log_warn("VPN: Failed to connect to %s:%u - %s", 
                    dest_str, dest_port,
                    error ? error->message : "unknown error");
            if (error) g_error_free(error);
            
            // Send RST to client
            send_tcp_packet(vpn, session, TCP_RST | TCP_ACK, NULL, 0);
            vpn_session_free(session);
            g_mutex_unlock(&vpn->sessions_mutex);
            g_free(key);
            return;
        }

        // Watch for upstream data
        GSocket *sock = g_socket_connection_get_socket(session->upstream_conn);
        GIOChannel *chan = g_io_channel_unix_new(g_socket_get_fd(sock));
        session->upstream_watch_id = g_io_add_watch(chan, G_IO_IN | G_IO_HUP | G_IO_ERR,
                                                   on_upstream_readable, session);
        g_io_channel_unref(chan);

        g_hash_table_insert(vpn->sessions, g_strdup(key), session);
        vpn->total_connections++;
        vpn->active_connections++;

        // Send SYN-ACK
        send_tcp_packet(vpn, session, TCP_SYN | TCP_ACK, NULL, 0);
        session->seq++;

        g_mutex_unlock(&vpn->sessions_mutex);
        g_free(key);
        return;
    }

    if (!session) {
        log_debug("VPN: No session for %s, ignoring packet", key);
        g_mutex_unlock(&vpn->sessions_mutex);
        g_free(key);
        return;
    }

    session->last_activity = g_get_monotonic_time();

    // Handle ACK for SYN-ACK (complete handshake)
    if (session->state == VPN_TCP_SYN_RECEIVED && (flags & TCP_ACK)) {
        if (recv_ack != session->seq) {
            log_debug("VPN: Invalid ACK for %s: expected %u, got %u", 
                     session->session_key, session->seq, recv_ack);
            send_tcp_packet(vpn, session, TCP_RST, NULL, 0);
            g_hash_table_remove(vpn->sessions, session->session_key);
            vpn->active_connections--;
            g_mutex_unlock(&vpn->sessions_mutex);
            g_free(key);
            return;
        }
        session->state = VPN_TCP_ESTABLISHED;
        log_info("VPN: Connection established: %s", session->session_key);
    }

    // Forward data to upstream
    if ((session->state == VPN_TCP_ESTABLISHED) && payload_len > 0) {
        GOutputStream *output = g_io_stream_get_output_stream(
            G_IO_STREAM(session->upstream_conn));
        GError *error = NULL;
        gssize written = g_output_stream_write(output, payload, payload_len, NULL, &error);

        if (written > 0) {
            session->ack = recv_seq + written;
            send_tcp_packet(vpn, session, TCP_ACK, NULL, 0);
            log_debug("VPN: Forwarded %zd bytes from %s to upstream", written, session->session_key);
        } else if (error) {
            log_warn("VPN: Failed to write to upstream for %s: %s",
                    session->session_key, error->message);
            g_error_free(error);
            send_tcp_packet(vpn, session, TCP_RST, NULL, 0);
            g_hash_table_remove(vpn->sessions, session->session_key);
            vpn->active_connections--;
        }
    }

    // Handle FIN
    if (flags & TCP_FIN) {
        session->ack = recv_seq + 1;
        send_tcp_packet(vpn, session, TCP_ACK, NULL, 0);
        
        if (session->state == VPN_TCP_ESTABLISHED) {
            session->state = VPN_TCP_CLOSE_WAIT;
            send_tcp_packet(vpn, session, TCP_FIN | TCP_ACK, NULL, 0);
            session->seq++;
            session->state = VPN_TCP_LAST_ACK;
        } else if (session->state == VPN_TCP_FIN_WAIT_1) {
            session->state = VPN_TCP_FIN_WAIT_2;
        }
    }
    
    // Handle final ACK in FIN_WAIT_2
    if (session->state == VPN_TCP_FIN_WAIT_2 && (flags & TCP_ACK) && recv_ack == session->seq) {
        session->state = VPN_TCP_TIME_WAIT;
        log_debug("VPN: Connection closing: %s", session->session_key);
        g_hash_table_remove(vpn->sessions, session->session_key);
        vpn->active_connections--;
    }

    // Handle RST
    if (flags & TCP_RST) {
        log_info("VPN: Connection reset: %s", session->session_key);
        g_hash_table_remove(vpn->sessions, session->session_key);
        vpn->active_connections--;
    }

    // Remove closed sessions
    if (session->state == VPN_TCP_LAST_ACK && (flags & TCP_ACK) && recv_ack == session->seq) {
        log_debug("VPN: Connection closed: %s", session->session_key);
        g_hash_table_remove(vpn->sessions, session->session_key);
        vpn->active_connections--;
    }

    g_mutex_unlock(&vpn->sessions_mutex);
    g_free(key);
}

static void handle_udp_packet(DeadlightVPNManager *vpn, struct ip_header *ip_hdr,
                              struct udp_header *udp_hdr, guint8 *payload,
                              gsize payload_len) {
    guint32 client_ip = ntohl(ip_hdr->src_addr);
    guint32 dest_ip = ntohl(ip_hdr->dest_addr);
    guint16 client_port = ntohs(udp_hdr->src_port);
    guint16 dest_port = ntohs(udp_hdr->dest_port);
    
    gchar client_str[INET_ADDRSTRLEN];
    gchar dest_str[INET_ADDRSTRLEN];
    struct in_addr tmp;
    tmp.s_addr = ip_hdr->src_addr;
    inet_ntop(AF_INET, &tmp, client_str, INET_ADDRSTRLEN);
    tmp.s_addr = ip_hdr->dest_addr;
    inet_ntop(AF_INET, &tmp, dest_str, INET_ADDRSTRLEN);
    
    log_debug("VPN: UDP packet: %s:%u -> %s:%u payload=%zu",
             client_str, client_port, dest_str, dest_port, payload_len);
    
    gchar *key = g_strdup_printf("%s:%u->%s:%u", client_str, client_port, dest_str, dest_port);
    
    g_mutex_lock(&vpn->sessions_mutex);
    VPNUDPSession *session = g_hash_table_lookup(vpn->udp_sessions, key);
    
    if (!session) {
        // Check session limits (prevent file descriptor exhaustion)
        guint current_udp_sessions = g_hash_table_size(vpn->udp_sessions);
        if (current_udp_sessions >= 500) {  // Limit UDP sessions
            log_warn("VPN: Max UDP sessions reached (%u), rejecting %s", 
                     current_udp_sessions, key);
            g_mutex_unlock(&vpn->sessions_mutex);
            g_free(key);
            return;
        }
        
        // Create new UDP session
        log_info("VPN: New UDP session: %s (total: %u)", key, current_udp_sessions + 1);
        
        session = vpn_udp_session_new(vpn, client_ip, client_port, dest_ip, dest_port);
        
        // Create UDP socket
        GError *error = NULL;
        session->upstream_socket = g_socket_new(G_SOCKET_FAMILY_IPV4,
                                               G_SOCKET_TYPE_DATAGRAM,
                                               G_SOCKET_PROTOCOL_UDP,
                                               &error);
        
        if (!session->upstream_socket) {
            log_warn("VPN: Failed to create UDP socket for %s: %s",
                    key, error ? error->message : "unknown");
            if (error) g_error_free(error);
            vpn_udp_session_free(session);
            g_mutex_unlock(&vpn->sessions_mutex);
            g_free(key);
            return;
        }
        
        // IMPORTANT: Set non-blocking mode for the socket
        g_socket_set_blocking(session->upstream_socket, FALSE);
        
        // Watch for upstream responses
        gint fd = g_socket_get_fd(session->upstream_socket);
        GIOChannel *chan = g_io_channel_unix_new(fd);
        g_io_channel_set_encoding(chan, NULL, NULL);
        g_io_channel_set_buffered(chan, FALSE);
        session->upstream_watch_id = g_io_add_watch(chan, G_IO_IN | G_IO_HUP | G_IO_ERR,
                                                   on_udp_upstream_readable, session);
        g_io_channel_unref(chan);
        
        g_hash_table_insert(vpn->udp_sessions, g_strdup(session->session_key), session);
        
        log_debug("VPN: Created UDP session, watching fd=%d", fd);
    }
    
    session->last_activity = g_get_monotonic_time();
    
    // Send UDP packet to upstream
    GSocketAddress *addr = g_inet_socket_address_new(
        g_inet_address_new_from_string(dest_str), dest_port);
    
    GError *error = NULL;
    gssize sent = g_socket_send_to(session->upstream_socket, addr,
                                   (const gchar *)payload, payload_len,
                                   NULL, &error);
    
    g_object_unref(addr);
    
    if (sent > 0) {
        log_debug("VPN: Forwarded %zd UDP bytes from %s to %s:%u", 
                 sent, session->session_key, dest_str, dest_port);
    } else if (error) {
        log_warn("VPN: Failed to send UDP to upstream for %s: %s",
                session->session_key, error->message);
        g_error_free(error);
    }
    
    g_mutex_unlock(&vpn->sessions_mutex);
    g_free(key);
}

static void handle_ip_packet(DeadlightVPNManager *vpn, guint8 *packet, gsize packet_len) {
    if (packet_len < 1) {
        return;
    }

    // Check IP version (first 4 bits)
    guint8 version = (packet[0] >> 4) & 0x0F;

    if (version == 4) {
        // IPv4 handler
        if (packet_len < sizeof(struct ip_header)) {
            return;
        }

        struct ip_header *ip_hdr = (struct ip_header *)packet;
        guint8 ihl = (ip_hdr->version_ihl & 0x0F) * 4;

        if (packet_len < ihl) {
            log_debug("VPN: Packet too short for IP header");
            return;
        }

        if (ip_hdr->protocol == IPPROTO_TCP) {
            if (packet_len < ihl + sizeof(struct tcp_header)) {
                return;
            }
            struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + ihl);
            guint8 tcp_hdr_len = ((tcp_hdr->data_offset_flags >> 4) & 0x0F) * 4;
            
            if (packet_len < ihl + tcp_hdr_len) {
                log_debug("VPN: Packet too short for TCP header");
                return;
            }
            
            guint8 *payload = packet + ihl + tcp_hdr_len;
            gsize payload_len = packet_len - ihl - tcp_hdr_len;
            handle_tcp_packet(vpn, ip_hdr, tcp_hdr, payload, payload_len);
            
        } else if (ip_hdr->protocol == IPPROTO_UDP) {
            if (packet_len < ihl + sizeof(struct udp_header)) {
                return;
            }
            struct udp_header *udp_hdr = (struct udp_header *)(packet + ihl);
            guint8 *payload = packet + ihl + sizeof(struct udp_header);
            gsize payload_len = packet_len - ihl - sizeof(struct udp_header);
            handle_udp_packet(vpn, ip_hdr, udp_hdr, payload, payload_len);
            
        } else {
            log_debug("VPN: Ignoring IPv4 packet with protocol=%d", ip_hdr->protocol);
        }
        
    } else if (version == 6) {
        // IPv6 handler
        handle_ipv6_packet(vpn, packet, packet_len);
        
    } else {
        log_debug("VPN: Unknown IP version: %d", version);
    }
}

static void handle_ipv6_packet(DeadlightVPNManager *vpn, guint8 *packet, gsize packet_len) {
    if (packet_len < sizeof(struct ipv6_header)) {
        log_debug("VPN: IPv6 packet too short");
        return;
    }

    struct ipv6_header *ip6_hdr = (struct ipv6_header *)packet;
    
    // Extract version
    guint8 version = (ntohl(ip6_hdr->version_tc_fl) >> 28) & 0x0F;
    if (version != 6) {
        log_debug("VPN: Invalid IPv6 version: %d", version);
        return;
    }

    guint8 next_header = ip6_hdr->next_header;
    guint16 payload_len = ntohs(ip6_hdr->payload_length);
    
    if (packet_len < sizeof(struct ipv6_header) + payload_len) {
        log_debug("VPN: IPv6 packet length mismatch");
        return;
    }

    gchar src_str[INET6_ADDRSTRLEN];
    gchar dest_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6_hdr->src_addr, src_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6_hdr->dest_addr, dest_str, INET6_ADDRSTRLEN);

    log_debug("VPN: IPv6 packet: %s -> %s (next_header=%d, len=%zu)",
             src_str, dest_str, next_header, packet_len);

    if (next_header == IPPROTO_TCP) {
        if (packet_len < sizeof(struct ipv6_header) + sizeof(struct tcp_header)) {
            return;
        }
        struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + sizeof(struct ipv6_header));
        guint8 tcp_hdr_len = ((tcp_hdr->data_offset_flags >> 4) & 0x0F) * 4;
        
        guint8 *payload = packet + sizeof(struct ipv6_header) + tcp_hdr_len;
        gsize payload_len_actual = packet_len - sizeof(struct ipv6_header) - tcp_hdr_len;
        
        handle_tcp6_packet(vpn, ip6_hdr, tcp_hdr, payload, payload_len_actual);
        
    } else if (next_header == IPPROTO_UDP) {
        if (packet_len < sizeof(struct ipv6_header) + sizeof(struct udp_header)) {
            return;
        }
        struct udp_header *udp_hdr = (struct udp_header *)(packet + sizeof(struct ipv6_header));
        guint8 *payload = packet + sizeof(struct ipv6_header) + sizeof(struct udp_header);
        gsize payload_len_actual = packet_len - sizeof(struct ipv6_header) - sizeof(struct udp_header);
        
        handle_udp6_packet(vpn, ip6_hdr, udp_hdr, payload, payload_len_actual);
        
    } else {
        log_debug("VPN: Ignoring IPv6 packet with next_header=%d", next_header);
    }
}

static void handle_udp6_packet(DeadlightVPNManager *vpn, struct ipv6_header *ip6_hdr,
                               struct udp_header *udp_hdr, guint8 *payload,
                               gsize payload_len) {
    guint16 client_port = ntohs(udp_hdr->src_port);
    guint16 dest_port = ntohs(udp_hdr->dest_port);
    
    gchar client_str[INET6_ADDRSTRLEN];
    gchar dest_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6_hdr->src_addr, client_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6_hdr->dest_addr, dest_str, INET6_ADDRSTRLEN);
    
    log_debug("VPN: IPv6 UDP packet: [%s]:%u -> [%s]:%u payload=%zu",
             client_str, client_port, dest_str, dest_port, payload_len);
    
    gchar *key = g_strdup_printf("[%s]:%u->[%s]:%u", client_str, client_port, dest_str, dest_port);
    
    g_mutex_lock(&vpn->sessions_mutex);
    VPNUDPSession *session = g_hash_table_lookup(vpn->udp_sessions_v6, key);
    
    if (!session) {
        guint current_udp_sessions = g_hash_table_size(vpn->udp_sessions_v6);
        if (current_udp_sessions >= 500) {
            log_warn("VPN: Max IPv6 UDP sessions reached (%u), rejecting %s", 
                     current_udp_sessions, key);
            g_mutex_unlock(&vpn->sessions_mutex);
            g_free(key);
            return;
        }
        
        log_info("VPN: New IPv6 UDP session: %s (total: %u)", key, current_udp_sessions + 1);
        
        session = g_new0(VPNUDPSession, 1);
        memcpy(&session->client_ip, &ip6_hdr->src_addr, sizeof(struct in6_addr));
        memcpy(&session->dest_ip, &ip6_hdr->dest_addr, sizeof(struct in6_addr));
        session->client_port = client_port;
        session->dest_port = dest_port;
        session->session_key = g_strdup(key);
        session->last_activity = g_get_monotonic_time();
        session->vpn = vpn;
        session->upstream_socket = NULL;
        session->upstream_watch_id = 0;
        
        // Create UDP socket (IPv6)
        GError *error = NULL;
        session->upstream_socket = g_socket_new(G_SOCKET_FAMILY_IPV6,
                                               G_SOCKET_TYPE_DATAGRAM,
                                               G_SOCKET_PROTOCOL_UDP,
                                               &error);
        
        if (!session->upstream_socket) {
            log_warn("VPN: Failed to create IPv6 UDP socket for %s: %s",
                    key, error ? error->message : "unknown");
            if (error) g_error_free(error);
            vpn_udp_session_free(session);
            g_mutex_unlock(&vpn->sessions_mutex);
            g_free(key);
            return;
        }
        
        g_socket_set_blocking(session->upstream_socket, FALSE);
        
        // Watch for upstream responses
        gint fd = g_socket_get_fd(session->upstream_socket);
        GIOChannel *chan = g_io_channel_unix_new(fd);
        g_io_channel_set_encoding(chan, NULL, NULL);
        g_io_channel_set_buffered(chan, FALSE);
        session->upstream_watch_id = g_io_add_watch(chan, G_IO_IN | G_IO_HUP | G_IO_ERR,
                                                   on_udp_upstream_readable, session);
        g_io_channel_unref(chan);
        
        g_hash_table_insert(vpn->udp_sessions_v6, g_strdup(session->session_key), session);
    }
    
    session->last_activity = g_get_monotonic_time();
    
    // Send UDP packet to upstream
    GSocketAddress *addr = g_inet_socket_address_new(
        g_inet_address_new_from_string(dest_str), dest_port);
    
    GError *error = NULL;
    gssize sent = g_socket_send_to(session->upstream_socket, addr,
                                   (const gchar *)payload, payload_len,
                                   NULL, &error);
    
    g_object_unref(addr);
    
    if (sent > 0) {
        log_debug("VPN: Forwarded %zd IPv6 UDP bytes from %s to [%s]:%u", 
                 sent, session->session_key, dest_str, dest_port);
    } else if (error) {
        log_warn("VPN: Failed to send IPv6 UDP to upstream for %s: %s",
                session->session_key, error->message);
        g_error_free(error);
    }
    
    g_mutex_unlock(&vpn->sessions_mutex);
    g_free(key);
}

static void handle_tcp6_packet(DeadlightVPNManager *vpn, struct ipv6_header *ip6_hdr,
                               struct tcp_header *tcp_hdr, guint8 *payload,
                               gsize payload_len) {
    guint16 client_port = ntohs(tcp_hdr->src_port);
    guint16 dest_port = ntohs(tcp_hdr->dest_port);
    guint8 flags = tcp_hdr->flags;
    guint32 recv_seq = ntohl(tcp_hdr->seq_num);
    guint32 recv_ack = ntohl(tcp_hdr->ack_num);

    gchar client_str[INET6_ADDRSTRLEN];
    gchar dest_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6_hdr->src_addr, client_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6_hdr->dest_addr, dest_str, INET6_ADDRSTRLEN);

    log_debug("VPN: IPv6 TCP packet: [%s]:%u -> [%s]:%u flags=0x%02x seq=%u ack=%u payload=%zu",
             client_str, client_port, dest_str, dest_port, flags, recv_seq, recv_ack, payload_len);

    gchar *key = g_strdup_printf("[%s]:%u->[%s]:%u", client_str, client_port, dest_str, dest_port);

    g_mutex_lock(&vpn->sessions_mutex);
    VPNSession *session = g_hash_table_lookup(vpn->sessions_v6, key);

    // Handle SYN (new connection)
    if (!session && (flags & TCP_SYN) && !(flags & TCP_ACK)) {
        if (vpn->active_connections >= 1000) {
            log_warn("VPN: Max sessions reached, rejecting %s", key);
            g_mutex_unlock(&vpn->sessions_mutex);
            g_free(key);
            return;
        }
        
        session = g_new0(VPNSession, 1);
        memcpy(&session->client_ip, &ip6_hdr->src_addr, sizeof(struct in6_addr));
        memcpy(&session->dest_ip, &ip6_hdr->dest_addr, sizeof(struct in6_addr));
        session->client_port = client_port;
        session->dest_port = dest_port;
        session->session_key = g_strdup(key);
        
        session->state = VPN_TCP_CLOSED;
        session->seq = g_random_int();
        session->isn = session->seq;
        session->ack = recv_seq + 1;
        session->created_at = g_get_monotonic_time();
        session->last_activity = session->created_at;
        session->vpn = vpn;
        session->upstream_conn = NULL;
        session->upstream_watch_id = 0;
        session->retrans_timer_id = 0;
        session->last_packet.data = NULL;
        session->last_packet.len = 0;
        
        // Connect upstream
        GError *error = NULL;
        log_info("VPN: Connecting to IPv6 upstream: [%s]:%u", dest_str, dest_port);
        
        session->upstream_conn = deadlight_network_connect_tcp(vpn->context, dest_str, dest_port, &error);

        if (!session->upstream_conn) {
            log_warn("VPN: Failed to connect to [%s]:%u - %s", 
                    dest_str, dest_port,
                    error ? error->message : "unknown error");
            if (error) g_error_free(error);
            
            send_tcp6_packet(vpn, session, TCP_RST | TCP_ACK, NULL, 0);
            vpn_session_free(session);
            g_mutex_unlock(&vpn->sessions_mutex);
            g_free(key);
            return;
        }

        // Watch for upstream data
        GSocket *sock = g_socket_connection_get_socket(session->upstream_conn);
        GIOChannel *chan = g_io_channel_unix_new(g_socket_get_fd(sock));
        session->upstream_watch_id = g_io_add_watch(chan, G_IO_IN | G_IO_HUP | G_IO_ERR,
                                                   on_upstream_readable, session);
        g_io_channel_unref(chan);

        g_hash_table_insert(vpn->sessions_v6, g_strdup(key), session);
        vpn->total_connections++;
        vpn->active_connections++;

        // Send SYN-ACK
        send_tcp6_packet(vpn, session, TCP_SYN | TCP_ACK, NULL, 0);
        session->seq++;
        session->state = VPN_TCP_SYN_RECEIVED;

        g_mutex_unlock(&vpn->sessions_mutex);
        g_free(key);
        return;
    }

    if (!session) {
        log_debug("VPN: No IPv6 session for %s, ignoring packet", key);
        g_mutex_unlock(&vpn->sessions_mutex);
        g_free(key);
        return;
    }

    session->last_activity = g_get_monotonic_time();

    // Handle ACK for SYN-ACK (complete handshake)
    if (session->state == VPN_TCP_SYN_RECEIVED && (flags & TCP_ACK)) {
        if (recv_ack != session->seq) {
            log_debug("VPN: Invalid ACK for %s: expected %u, got %u", 
                     session->session_key, session->seq, recv_ack);
            send_tcp6_packet(vpn, session, TCP_RST, NULL, 0);
            g_hash_table_remove(vpn->sessions_v6, session->session_key);
            vpn->active_connections--;
            g_mutex_unlock(&vpn->sessions_mutex);
            g_free(key);
            return;
        }
        session->state = VPN_TCP_ESTABLISHED;
        log_info("VPN: IPv6 connection established: %s", session->session_key);
    }

    // Forward data to upstream
    if ((session->state == VPN_TCP_ESTABLISHED) && payload_len > 0) {
        GOutputStream *output = g_io_stream_get_output_stream(
            G_IO_STREAM(session->upstream_conn));
        GError *error = NULL;
        gssize written = g_output_stream_write(output, payload, payload_len, NULL, &error);

        if (written > 0) {
            session->ack = recv_seq + written;
            send_tcp6_packet(vpn, session, TCP_ACK, NULL, 0);
            log_debug("VPN: Forwarded %zd bytes from %s to upstream", written, session->session_key);
        } else if (error) {
            log_warn("VPN: Failed to write to upstream for %s: %s",
                    session->session_key, error->message);
            g_error_free(error);
            send_tcp6_packet(vpn, session, TCP_RST, NULL, 0);
            g_hash_table_remove(vpn->sessions_v6, session->session_key);
            vpn->active_connections--;
        }
    }

    // Handle FIN
    if (flags & TCP_FIN) {
        session->ack = recv_seq + 1;
        send_tcp6_packet(vpn, session, TCP_ACK, NULL, 0);
        
        if (session->state == VPN_TCP_ESTABLISHED) {
            session->state = VPN_TCP_CLOSE_WAIT;
            send_tcp6_packet(vpn, session, TCP_FIN | TCP_ACK, NULL, 0);
            session->seq++;
            session->state = VPN_TCP_LAST_ACK;
        } else if (session->state == VPN_TCP_FIN_WAIT_1) {
            session->state = VPN_TCP_FIN_WAIT_2;
        }
    }
    
    // Handle final ACK in FIN_WAIT_2
    if (session->state == VPN_TCP_FIN_WAIT_2 && (flags & TCP_ACK) && recv_ack == session->seq) {
        session->state = VPN_TCP_TIME_WAIT;
        log_debug("VPN: IPv6 connection closing: %s", session->session_key);
        g_hash_table_remove(vpn->sessions_v6, session->session_key);
        vpn->active_connections--;
    }

    // Handle RST
    if (flags & TCP_RST) {
        log_info("VPN: IPv6 connection reset: %s", session->session_key);
        g_hash_table_remove(vpn->sessions_v6, session->session_key);
        vpn->active_connections--;
    }

    // Remove closed sessions
    if (session->state == VPN_TCP_LAST_ACK && (flags & TCP_ACK) && recv_ack == session->seq) {
        log_debug("VPN: IPv6 connection closed: %s", session->session_key);
        g_hash_table_remove(vpn->sessions_v6, session->session_key);
        vpn->active_connections--;
    }

    g_mutex_unlock(&vpn->sessions_mutex);
    g_free(key);
}

static gboolean on_tun_readable(GIOChannel *source, GIOCondition condition,
                               gpointer user_data) {
    DeadlightVPNManager *vpn = user_data;
    (void)source;

    if (condition & (G_IO_HUP | G_IO_ERR)) {
        log_error("VPN: TUN device error or hangup");
        return G_SOURCE_REMOVE;
    }

    guint8 packet[2048];
    gssize bytes = read(vpn->tun_fd, packet, sizeof(packet));

    if (bytes < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_warn("VPN: TUN read error: %s", g_strerror(errno));
        }
        return G_SOURCE_CONTINUE;
    }

    if (bytes > 0) {
        vpn->bytes_received += bytes;
        handle_ip_packet(vpn, packet, bytes);
    }

    return G_SOURCE_CONTINUE;
}

//=============================================================================
// Public API
//=============================================================================

gboolean deadlight_vpn_gateway_init(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(context->vpn != NULL, FALSE);

    DeadlightVPNManager *vpn = context->vpn;

    log_info("VPN: Initializing VPN gateway...");

    // Get configuration
    gchar *dev_name = deadlight_config_get_string(context, "vpn", "device", "tun0");
    gchar *gateway_ip = deadlight_config_get_string(context, "vpn", "address", "10.8.0.1");
    gchar *netmask = deadlight_config_get_string(context, "vpn", "netmask", "255.255.255.0");

    vpn->tun_device_name = g_strdup(dev_name);
    vpn->gateway_ip = g_strdup(gateway_ip);
    vpn->netmask = g_strdup(netmask);

    // Create TUN device
    vpn->tun_fd = create_tun_device(dev_name, error);
    g_free(dev_name);
    if (vpn->tun_fd < 0) {
        g_free(gateway_ip);
        g_free(netmask);
        return FALSE;
    }

    // Configure TUN device
    if (!configure_tun_device(vpn->tun_device_name, gateway_ip, netmask, error)) {
        g_free(gateway_ip);
        g_free(netmask);
        close(vpn->tun_fd);
        return FALSE;
    }

    g_free(gateway_ip);
    g_free(netmask);

    // Set non-blocking
    fcntl(vpn->tun_fd, F_SETFL, O_NONBLOCK);

    // Setup GIO monitoring
    vpn->tun_channel = g_io_channel_unix_new(vpn->tun_fd);
    g_io_channel_set_encoding(vpn->tun_channel, NULL, NULL);
    g_io_channel_set_buffered(vpn->tun_channel, FALSE);
    vpn->tun_watch_id = g_io_add_watch(vpn->tun_channel, G_IO_IN | G_IO_HUP | G_IO_ERR,
                                   on_tun_readable, vpn);

    // Initialize session tracking
    vpn->sessions = g_hash_table_new_full(g_str_hash, g_str_equal,
                                          g_free,
                                          (GDestroyNotify)vpn_session_free);
    vpn->udp_sessions = g_hash_table_new_full(g_str_hash, g_str_equal,
                                          g_free,
                                          (GDestroyNotify)vpn_udp_session_free);
    vpn->sessions_v6 = g_hash_table_new_full(g_str_hash, g_str_equal,
                                             g_free,
                                             (GDestroyNotify)vpn_session_free);
    vpn->udp_sessions_v6 = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                 g_free,
                                                 (GDestroyNotify)vpn_udp_session_free);
    g_mutex_init(&vpn->sessions_mutex);

    // Setup periodic cleanup of idle sessions
    g_timeout_add_seconds(60, cleanup_idle_sessions, vpn);
    g_timeout_add_seconds(10, cleanup_idle_udp_sessions, vpn);  // Run every 10 seconds for UDP

    log_info("VPN: Gateway initialized successfully on %s", vpn->tun_device_name);
    return TRUE;
}

void deadlight_vpn_gateway_cleanup(DeadlightContext *context) {
    g_return_if_fail(context != NULL);
    g_return_if_fail(context->vpn != NULL);

    DeadlightVPNManager *vpn = context->vpn;

    log_info("VPN: Shutting down gateway...");

    // Remove TUN watch
    if (vpn->tun_watch_id > 0) {
        g_source_remove(vpn->tun_watch_id);
        vpn->tun_watch_id = 0;
    }

    // Close TUN channel
    if (vpn->tun_channel) {
        g_io_channel_shutdown(vpn->tun_channel, FALSE, NULL);
        g_io_channel_unref(vpn->tun_channel);
        vpn->tun_channel = NULL;
    }

    // Close TUN device
    if (vpn->tun_fd >= 0) {
        close(vpn->tun_fd);
        vpn->tun_fd = -1;
    }

    // Delete the TUN device
    if (vpn->tun_device_name) {
        gchar *cmd = g_strdup_printf("ip link delete %s 2>/dev/null", vpn->tun_device_name);
        gint ret = system(cmd);
        if (ret == 0) {
            log_info("VPN: Deleted TUN device %s", vpn->tun_device_name);
        } else {
            log_debug("VPN: Could not delete TUN device %s (may not exist)", 
                     vpn->tun_device_name);
        }
        g_free(cmd);
    }

    // Cleanup sessions
    if (vpn->sessions) {
        g_hash_table_destroy(vpn->sessions);
        vpn->sessions = NULL;
    }
    
    if (vpn->udp_sessions) {
        g_hash_table_destroy(vpn->udp_sessions);
        vpn->udp_sessions = NULL;
    }

    if (vpn->sessions_v6) {
        g_hash_table_destroy(vpn->sessions);
        vpn->sessions_v6 = NULL;
    }
    
    if (vpn->udp_sessions_v6) {
        g_hash_table_destroy(vpn->udp_sessions);
        vpn->udp_sessions_v6 = NULL;
    }

    g_mutex_clear(&vpn->sessions_mutex);

    g_free(vpn->tun_device_name);
    g_free(vpn->gateway_ip);
    g_free(vpn->client_subnet);
    g_free(vpn->netmask);

    log_info("VPN: Gateway cleanup complete");
}

void deadlight_vpn_gateway_get_stats(DeadlightContext *context,
                                    guint64 *active_connections,
                                    guint64 *total_connections,
                                    guint64 *bytes_sent,
                                    guint64 *bytes_received) {
    g_return_if_fail(context != NULL);
    g_return_if_fail(context->vpn != NULL);

    DeadlightVPNManager *vpn = context->vpn;

    if (active_connections) *active_connections = vpn->active_connections;
    if (total_connections) *total_connections = vpn->total_connections;
    if (bytes_sent) *bytes_sent = vpn->bytes_sent;
    if (bytes_received) *bytes_received = vpn->bytes_received;
}