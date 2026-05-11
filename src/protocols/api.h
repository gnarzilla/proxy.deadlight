#ifndef DEADLIGHT_API_H
#define DEADLIGHT_API_H

#include "../core/deadlight.h"

DeadlightHandlerResult api_handle_prometheus_metrics(DeadlightConnection *conn, GError **error);
void deadlight_register_api_handler(void);
DeadlightHandlerResult api_send_json_response(DeadlightConnection *conn, gint status_code, const gchar *status_text, const gchar *json_body, GError **error);

#endif
