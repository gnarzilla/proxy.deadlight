/**
 * Deadlight Federation Protocol
 * 
 * Handles cryptographically signed messages from other instances.
 * Implements the "Inbox" pattern: Verify -> Acknowledge -> Queue to Disk.
 */

#include "core/deadlight.h"
#include <json-glib/json-glib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

// Max drift allowed for Replay Protection (5 minutes)
#define FED_MAX_TIME_DRIFT 300 

// Forward declarations
static gboolean verify_signature_ed25519(const gchar *payload, const gchar *sig_hex, const gchar *pubkey_hex);
static gboolean save_to_inbox(const gchar *filename, const gchar *data, GError **error);
static void send_json_response(DeadlightConnection *conn, int status, const gchar *msg);

/**
 * Handle incoming Federation Envelope
 * POST /api/federation/receive
 */
DeadlightHandlerResult api_federation_receive(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    g_info("Federation: Receiving incoming envelope from %s", conn->client_address);

    if (!request->body || request->body->len == 0) {
        send_json_response(conn, 400, "Missing request body");
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    // 1. Parse JSON Envelope
    JsonParser *parser = json_parser_new();
    if (!json_parser_load_from_data(parser, (const gchar*)request->body->data, request->body->len, error)) {
        g_object_unref(parser);
        send_json_response(conn, 400, "Invalid JSON");
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    JsonNode *root = json_parser_get_root(parser);
    JsonObject *obj = json_node_get_object(root);

    // 2. Extract Fields
    if (!json_object_has_member(obj, "payload") || 
        !json_object_has_member(obj, "signature") || 
        !json_object_has_member(obj, "pubkey") ||
        !json_object_has_member(obj, "timestamp")) {
        g_object_unref(parser);
        send_json_response(conn, 400, "Missing required envelope fields");
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    const gchar *payload = json_object_get_string_member(obj, "payload");
    const gchar *signature = json_object_get_string_member(obj, "signature");
    const gchar *pubkey = json_object_get_string_member(obj, "pubkey");
    gint64 timestamp = json_object_get_int_member(obj, "timestamp");

    // 3. Security: Timestamp Check (Replay Protection)
    gint64 now = g_get_real_time() / 1000000; // Microseconds to Seconds
    if (timestamp < (now - FED_MAX_TIME_DRIFT) || timestamp > (now + FED_MAX_TIME_DRIFT)) {
        g_warning("Federation: Rejecting packet from %s (Timestamp drift: %ld vs %ld)", 
                  conn->client_address, timestamp, now);
        g_object_unref(parser);
        send_json_response(conn, 401, "Timestamp rejected");
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    // 4. Security: Signature Verification (Ed25519)
    if (!verify_signature_ed25519(payload, signature, pubkey)) {
        g_warning("Federation: INVALID SIGNATURE from %s (Key: %.10s...)", 
                  conn->client_address, pubkey);
        g_object_unref(parser);
        send_json_response(conn, 401, "Invalid signature");
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    g_info("Federation: Verified payload from %.10s...", pubkey);

    // 5. Success! Save to Staging Inbox
    // We do NOT parse the payload here. We save the raw valid envelope.
    // A background worker (or manual process) handles the DB import.
    
    gchar *filename = g_strdup_printf("inbox_%ld_%.10s.json", timestamp, signature);
    if (!save_to_inbox(filename, (const gchar*)request->body->data, error)) {
        g_free(filename);
        g_object_unref(parser);
        send_json_response(conn, 500, "Internal storage error");
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    g_info("Federation: Persisted to inbox/%s", filename);

    g_free(filename);
    g_object_unref(parser);

    // 6. Return 202 Accepted
    send_json_response(conn, 202, "Message accepted");
    return HANDLER_SUCCESS_CLEANUP_NOW;
}

// --- Helper Functions ---

static void send_json_response(DeadlightConnection *conn, int status, const gchar *msg) {
    gchar *json = g_strdup_printf("{\"status\":%d,\"message\":\"%s\"}", status, msg);
    
    // Simple HTTP response construction
    gchar *resp = g_strdup_printf(
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", 
        status, 
        (status == 200 || status == 202) ? "OK" : "Error",
        strlen(json), 
        json
    );

    GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    g_output_stream_write_all(out, resp, strlen(resp), NULL, NULL, NULL);

    g_free(resp);
    g_free(json);
}

static gboolean save_to_inbox(const gchar *filename, const gchar *data, GError **error) {
    // Ensure inbox directory exists
    // Note: In production, configure this path in deadlight.conf
    const gchar *inbox_dir = "data/inbox"; 
    g_mkdir_with_parents(inbox_dir, 0700);

    gchar *path = g_build_filename(inbox_dir, filename, NULL);
    gboolean result = g_file_set_contents(path, data, -1, error);
    g_free(path);
    return result;
}

/**
 * Verifies an Ed25519 signature using OpenSSL EVP
 * 
 * Payload: The raw data string that was signed
 * Sig_Hex: 64 bytes hex string (128 chars)
 * PubKey_Hex: 32 bytes hex string (64 chars)
 */
static gboolean verify_signature_ed25519(const gchar *payload, const gchar *sig_hex, const gchar *pubkey_hex) {
    // 1. Convert Hex to Bytes
    // Ed25519 PubKey is 32 bytes
    if (strlen(pubkey_hex) != 64) return FALSE;
    // Ed25519 Sig is 64 bytes
    if (strlen(sig_hex) != 128) return FALSE;

    guchar pubkey_bin[32];
    guchar sig_bin[64];

    // Simple hex decode (replace with utils function if available)
    for (int i = 0; i < 32; i++) {
        sscanf(pubkey_hex + 2*i, "%02hhx", &pubkey_bin[i]);
    }
    for (int i = 0; i < 64; i++) {
        sscanf(sig_hex + 2*i, "%02hhx", &sig_bin[i]);
    }

    // 2. OpenSSL Verification
    // Since we have raw keys, we construct the EVP_PKEY manually
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey_bin, 32);
    if (!pkey) {
        g_warning("Federation: Failed to load raw public key");
        return FALSE;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return FALSE;
    }

    // Initialize for Pure Ed25519 (NULL digest implies Pure mode)
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return FALSE;
    }

    // Verify
    int rc = EVP_DigestVerify(md_ctx, sig_bin, 64, (const unsigned char*)payload, strlen(payload));

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return (rc == 1);
}