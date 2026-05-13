#ifdef ANDROID

#include "deadlight.h"
#include <glib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* ==================== VPN ==================== */
void deadlight_vpn_gateway_init(void *ctx) {
    g_message("VPN gateway disabled on Android");
}
void deadlight_vpn_gateway_cleanup(void *ctx) {}

/* ==================== Lightweight Android Rate Limiter ==================== */
#define ANDROID_RL_REQUESTS_PER_WINDOW  60
#define ANDROID_RL_WINDOW_SECONDS       60
#define ANDROID_RL_MAX_ENTRIES          256

typedef struct {
    guint32 count;
    gint64 window_start;
} AndroidRateLimitEntry;

static GHashTable *android_rl_table = NULL;
static GMutex android_rl_mutex;

static void android_rl_init(void) {
    if (G_UNLIKELY(!android_rl_table)) {
        android_rl_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        g_mutex_init(&android_rl_mutex);
    }
}

int deadlight_ratelimiter_check_request(void *conn_ptr) {
    if (!conn_ptr) return 0;

    DeadlightConnection *conn = (DeadlightConnection *)conn_ptr;
    if (!conn->client_address || !*conn->client_address) 
        return 0;   /* fallback: allow if no address */

    android_rl_init();

    const char *ip_str = conn->client_address;   /* assuming it's already a string like "192.168.1.1" */

    g_mutex_lock(&android_rl_mutex);

    gint64 now = g_get_monotonic_time() / G_USEC_PER_SEC;
    AndroidRateLimitEntry *entry = g_hash_table_lookup(android_rl_table, ip_str);

    if (!entry) {
        entry = g_new0(AndroidRateLimitEntry, 1);
        entry->window_start = now;
        g_hash_table_insert(android_rl_table, g_strdup(ip_str), entry);
    }

    /* Reset window if expired */
    if (now - entry->window_start >= ANDROID_RL_WINDOW_SECONDS) {
        entry->count = 0;
        entry->window_start = now;
    }

    entry->count++;

    /* Very light pruning */
    if (g_hash_table_size(android_rl_table) > ANDROID_RL_MAX_ENTRIES) {
        g_hash_table_remove_all(android_rl_table);
    }

    gboolean limited = (entry->count > ANDROID_RL_REQUESTS_PER_WINDOW);
    g_mutex_unlock(&android_rl_mutex);

    if (limited) {
        g_warning("Android RL: Rate limited %s (%u reqs)", ip_str, entry->count);
        return 1;
    }
    return 0;
}
/* ==================== Android Rate Limiter + Stats ==================== */

// Simple structure for stat exports
typedef struct {
    char ip[INET6_ADDRSTRLEN];
    guint32 count;
    gint64 reset_in;
} DeadlightRLStat;

/* 
   Returns a GList of DeadlightRLStat allocated on the heap.
   The caller is responsible for freeing the list and the data.
*/
void* deadlight_ratelimiter_get_stats(void) {
    if (!android_rl_table) return NULL;

    GList *results = NULL;
    GHashTableIter iter;
    gpointer key, value;
    gint64 now = g_get_monotonic_time() / G_USEC_PER_SEC;

    g_mutex_lock(&android_rl_mutex);

    g_hash_table_iter_init(&iter, android_rl_table);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        AndroidRateLimitEntry *entry = (AndroidRateLimitEntry *)value;
        DeadlightRLStat *s = g_new0(DeadlightRLStat, 1);
        
        g_strlcpy(s->ip, (char*)key, sizeof(s->ip));
        s->count = entry->count;
        s->reset_in = ANDROID_RL_WINDOW_SECONDS - (now - entry->window_start);
        
        if (s->reset_in < 0) s->reset_in = 0;

        results = g_list_append(results, s);
    }

    g_mutex_unlock(&android_rl_mutex);
    return (void*)results;
}

/* ==================== SSL Tunnel ==================== */
int start_ssl_tunnel_blocking(void *conn) {
    g_message("SSL tunnel disabled on Android");
    return -1;
}

#endif /* ANDROID */