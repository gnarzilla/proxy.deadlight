// src/ssl_tunnel.h

#ifndef SSL_TUNNEL_H
#define SSL_TUNNEL_H

#include "deadlight.h" // Includes glib and gives us DeadlightConnection

// Starts the bidirectional data pump over the established SSL connections
// stored in the conn object.
void start_ssl_tunnel(DeadlightConnection *conn);

#endif // SSL_TUNNEL_H
