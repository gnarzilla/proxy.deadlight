/**
 * Deadlight VPN Gateway - Kernel TCP Implementation
 * Uses real kernel sockets, no userspace TCP stack
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
// IP/TCP Header Structures
//=============================================================================

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

// TCP flags
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

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
static void handle_ip_packet(DeadlightVPNManager *vpn, guint8 *packet,
                             gsize packet_len);
static void handle_tcp_packet(DeadlightVPNManager *vpn, struct ip_header *ip_hdr,
                              struct tcp_header *tcp_hdr, guint8 *payload,
                              gsize payload_len);
static void send_tcp_packet(DeadlightVPNManager *vpn, VPNSession *session,
                           guint8 flags, const guint8 *payload, gsize payload_len);
static guint16 ip_checksum(const void *data, gsize len);
static guint16 tcp_checksum(guint32 src_ip, guint32 dest_ip,
                           const void *tcp_data, gsize tcp_len);
static VPNSession *vpn_session_new(DeadlightVPNManager *vpn, guint32 client_ip,
                                   guint16 client_port, guint32 dest_ip,
                                   guint16 dest_port);
static void vpn_session_free(VPNSession *session);
static gboolean cleanup_idle_sessions(gpointer user_data);

//=============================================================================
// TUN Device Management
//=============================================================================

static gint create_tun_device(const gchar *dev_name, GError **error) {
    struct ifreq ifr;
    gint fd;

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
    // TCP pseudo-header for checksum
    struct {
        guint32 src_addr;
        guint32 dest_addr;
        guint8 zero;
        guint8 protocol;
        guint16 tcp_length;
    } __attribute__((packed)) pseudo_hdr;

    pseudo_hdr.src_addr = htonl(src_ip);
    pseudo_hdr.dest_addr = htonl(dest_ip);
    pseudo_hdr.zero = 0;
    pseudo_hdr.protocol = IPPROTO_TCP;
    pseudo_hdr.tcp_length = htons(tcp_len);

    // Calculate checksum over pseudo-header + TCP segment
    guint32 sum = 0;
    const guint16 *buf = (const guint16 *)&pseudo_hdr;
    gsize len = sizeof(pseudo_hdr);

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

//=============================================================================
// Session Management
//=============================================================================

static VPNSession *vpn_session_new(DeadlightVPNManager *vpn, guint32 client_ip,
                                   guint16 client_port, guint32 dest_ip,
                                   guint16 dest_port) {
    VPNSession *session = g_new0(VPNSession, 1);

    session->client_ip = client_ip;
    session->client_port = client_port;
    session->dest_ip = dest_ip;
    session->dest_port = dest_port;
    session->session_key = g_strdup_printf("%u:%u->%u:%u",
                                          client_ip, client_port,
                                          dest_ip, dest_port);
    session->state = VPN_TCP_CLOSED;
    session->isn = g_random_int();
    session->seq = session->isn;
    session->ack = 0;
    session->created_at = g_get_monotonic_time();
    session->last_activity = session->created_at;
    session->vpn = vpn;

    return session;
}

static void vpn_session_free(VPNSession *session) {
    if (!session) return;

    if (session->upstream_watch_id > 0) {
        g_source_remove(session->upstream_watch_id);
    }

    if (session->upstream_conn) {
        g_io_stream_close(G_IO_STREAM(session->upstream_conn), NULL, NULL);
        g_object_unref(session->upstream_conn);
    }

    g_free(session->session_key);
    g_free(session);
}

static gboolean cleanup_idle_sessions(gpointer user_data) {
    DeadlightVPNManager *vpn = user_data;
    gint64 now = g_get_monotonic_time();
    gint64 timeout = 300 * G_TIME_SPAN_SECOND;  // 5 minutes

    g_mutex_lock(&vpn->sessions_mutex);

    GHashTableIter iter;
    gpointer key, value;
    GList *to_remove = NULL;

    g_hash_table_iter_init(&iter, vpn->sessions);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        VPNSession *session = value;
        if ((now - session->last_activity) > timeout) {
            to_remove = g_list_prepend(to_remove, g_strdup(session->session_key));
        }
    }

    for (GList *l = to_remove; l; l = l->next) {
        gchar *session_key = l->data;
        g_hash_table_remove(vpn->sessions, session_key);
        g_free(session_key);
    }

    g_list_free(to_remove);
    g_mutex_unlock(&vpn->sessions_mutex);

    return G_SOURCE_CONTINUE;
}

//=============================================================================
// Packet Handling
//=============================================================================

static void send_tcp_packet(DeadlightVPNManager *vpn, VPNSession *session,
                           guint8 flags, const guint8 *payload, gsize payload_len) {
    guint8 packet[2048];
    struct ip_header *ip_hdr = (struct ip_header *)packet;
    struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + sizeof(struct ip_header));

    gsize ip_hdr_len = sizeof(struct ip_header);
    gsize tcp_hdr_len = sizeof(struct tcp_header);
    gsize total_len = ip_hdr_len + tcp_hdr_len + payload_len;

    if (total_len > sizeof(packet)) {
        log_warn("VPN: Packet too large (%zu bytes), truncating", total_len);
        payload_len = sizeof(packet) - ip_hdr_len - tcp_hdr_len;
        total_len = sizeof(packet);
    }

    // Build IP header
    memset(ip_hdr, 0, ip_hdr_len);
    ip_hdr->version_ihl = 0x45;  // IPv4, 5-word header
    ip_hdr->total_length = htons(total_len);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_TCP;
    ip_hdr->src_addr = htonl(session->dest_ip);
    ip_hdr->dest_addr = htonl(session->client_ip);
    ip_hdr->checksum = ip_checksum(ip_hdr, ip_hdr_len);

    // Build TCP header
    memset(tcp_hdr, 0, tcp_hdr_len);
    tcp_hdr->src_port = htons(session->dest_port);
    tcp_hdr->dest_port = htons(session->client_port);
    tcp_hdr->seq_num = htonl(session->seq);
    tcp_hdr->ack_num = htonl(session->ack);
    tcp_hdr->data_offset_flags = 0x50;  // 5-word header
    tcp_hdr->flags = flags;
    tcp_hdr->window_size = htons(65535);

    // Copy payload
    if (payload_len > 0 && payload) {
        memcpy(packet + ip_hdr_len + tcp_hdr_len, payload, payload_len);
    }

    // TCP checksum
    tcp_hdr->checksum = tcp_checksum(session->dest_ip, session->client_ip,
                                    tcp_hdr, tcp_hdr_len + payload_len);

    // Write to TUN
    gssize written = write(vpn->tun_fd, packet, total_len);
    if (written < 0) {
        log_warn("VPN: Failed to write packet to TUN: %s", g_strerror(errno));
        return;
    }

    vpn->bytes_sent += written;

    log_debug("VPN: Sent %s to %s (%zu bytes, SEQ=%u, ACK=%u)",
             (flags & TCP_SYN) ? "SYN-ACK" : (flags & TCP_FIN) ? "FIN" :
             (flags & TCP_RST) ? "RST" : (flags & TCP_PSH) ? "PSH-ACK" : "ACK",
             session->session_key, total_len, session->seq, session->ack);
}

static gboolean on_upstream_readable(GIOChannel *source, GIOCondition condition,
                                    gpointer user_data) {
    VPNSession *session = user_data;
    DeadlightVPNManager *vpn = session->vpn;

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

    gchar *key = g_strdup_printf("%u:%u->%u:%u", client_ip, client_port, dest_ip, dest_port);

    g_mutex_lock(&vpn->sessions_mutex);
    VPNSession *session = g_hash_table_lookup(vpn->sessions, key);

    // Handle SYN (new connection)
    if (!session && (flags & TCP_SYN) && !(flags & TCP_ACK)) {
        log_info("VPN: New connection: %s", key);

        session = vpn_session_new(vpn, client_ip, client_port, dest_ip, dest_port);
        session->ack = recv_seq + 1;
        session->state = VPN_TCP_SYN_RECEIVED;

        // Create real kernel socket
        GError *error = NULL;
        struct in_addr addr = { .s_addr = htonl(dest_ip) };
        session->upstream_conn = deadlight_network_connect_tcp(
            vpn->context, inet_ntoa(addr), dest_port, &error);

        if (!session->upstream_conn) {
            log_warn("VPN: Failed to connect to %s: %s", key,
                    error ? error->message : "unknown error");
            if (error) g_error_free(error);
            send_tcp_packet(vpn, session, TCP_RST, NULL, 0);
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

        g_hash_table_insert(vpn->sessions, g_strdup(session->session_key), session);
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
        g_mutex_unlock(&vpn->sessions_mutex);
        g_free(key);
        return;
    }

    session->last_activity = g_get_monotonic_time();

    if (session->state == VPN_TCP_SYN_RECEIVED && (flags & TCP_ACK)) {
        if (recv_ack != session->seq) {
            log_debug("VPN: Invalid ACK for %s: expected %u, got %u", session->session_key, session->seq, recv_ack);
            send_tcp_packet(vpn, session, TCP_RST, NULL, 0);
            g_hash_table_remove(vpn->sessions, session->session_key);
            vpn->active_connections--;
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
        }
    }

    // Handle FIN
    if (flags & TCP_FIN) {
        session->ack = recv_seq + 1;
        send_tcp_packet(vpn, session, TCP_ACK, NULL, 0);  // Ack the FIN
        if (session->state == VPN_TCP_ESTABLISHED) {
            session->state = VPN_TCP_CLOSE_WAIT;
            // Send our FIN
            send_tcp_packet(vpn, session, TCP_FIN | TCP_ACK, NULL, 0);
            session->seq++;
            session->state = VPN_TCP_LAST_ACK;
        } else if (session->state == VPN_TCP_FIN_WAIT_1) {
            session->state = VPN_TCP_FIN_WAIT_2;
        }
    }
    if (session->state == VPN_TCP_FIN_WAIT_2 && (flags & TCP_ACK) && recv_ack == session->seq) {
        session->state = VPN_TCP_TIME_WAIT;
        // Optionally, delay removal for 2*MSL (e.g., 2 minutes)
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
    if (session->state == VPN_TCP_LAST_ACK || session->state == VPN_TCP_CLOSED) {
        g_hash_table_remove(vpn->sessions, session->session_key);
        vpn->active_connections--;
    }

    g_mutex_unlock(&vpn->sessions_mutex);
    g_free(key);
}

static void handle_ip_packet(DeadlightVPNManager *vpn, guint8 *packet, gsize packet_len) {
    if (packet_len < sizeof(struct ip_header)) {
        return;
    }

    struct ip_header *ip_hdr = (struct ip_header *)packet;
    guint8 version = (ip_hdr->version_ihl >> 4) & 0x0F;
    guint8 ihl = (ip_hdr->version_ihl & 0x0F) * 4;

    if (version != 4) {
        log_debug("VPN: Ignoring non-IPv4 packet (version=%d)", version);
        return;
    }

    if (ip_hdr->protocol != IPPROTO_TCP) {
        log_debug("VPN: Ignoring non-TCP packet (protocol=%d)", ip_hdr->protocol);
        return;
    }

    if (packet_len < ihl + sizeof(struct tcp_header)) {
        return;
    }

    struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + ihl);
    guint8 tcp_hdr_len = ((tcp_hdr->data_offset_flags >> 4) & 0x0F) * 4;
    guint8 *payload = packet + ihl + tcp_hdr_len;
    gsize payload_len = packet_len - ihl - tcp_hdr_len;

    handle_tcp_packet(vpn, ip_hdr, tcp_hdr, payload, payload_len);
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
    g_mutex_init(&vpn->sessions_mutex);

    // Setup periodic cleanup of idle sessions
    g_timeout_add_seconds(60, cleanup_idle_sessions, vpn);

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

        // Bring interface down
        if (vpn->tun_device_name) {
            gchar *cmd = g_strdup_printf("ip link set %s down", vpn->tun_device_name);
            system(cmd);
            g_free(cmd);
        }
    }

    // Cleanup sessions
    if (vpn->sessions) {
        g_hash_table_destroy(vpn->sessions);
        vpn->sessions = NULL;
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