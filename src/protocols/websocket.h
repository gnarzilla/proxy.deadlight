#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include "core/deadlight.h"

// WebSocket protocol handler registration
void deadlight_register_websocket_handler(void);

// WebSocket opcodes
typedef enum {
    WS_OPCODE_CONTINUATION = 0x0,
    WS_OPCODE_TEXT = 0x1,
    WS_OPCODE_BINARY = 0x2,
    WS_OPCODE_CLOSE = 0x8,
    WS_OPCODE_PING = 0x9,
    WS_OPCODE_PONG = 0xA
} WebSocketOpcode;

// WebSocket frame structure
typedef struct {
    gboolean fin;
    gboolean rsv1, rsv2, rsv3;
    WebSocketOpcode opcode;
    gboolean masked;
    guint64 payload_length;
    guint8 masking_key[4];
    GByteArray *payload;
} WebSocketFrame;

#endif // WEBSOCKET_H
