#ifdef ANDROID

#include "deadlight.h"
#include <glib.h>

/* VPN gateway stubs */
void deadlight_vpn_gateway_init(void *ctx) {
    g_message("VPN gateway disabled on Android");
}
void deadlight_vpn_gateway_cleanup(void *ctx) {}

/* Rate limiter stubs */
void* deadlight_ratelimiter_get_stats(void) { return NULL; }
int deadlight_ratelimiter_check_request(void *conn) { return 1; }

/* SSL tunnel stub */
int start_ssl_tunnel_blocking(void *conn) {
    g_message("SSL tunnel disabled on Android");
    return -1;
}

#endif /* ANDROID */
