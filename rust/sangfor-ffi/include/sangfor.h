/* The C ABI of sangfor-core: one surface for the iOS packet tunnel extension,
 * an Android VpnService process, an OHOS extension ability, and the desktop
 * daemons.
 *
 * Lifecycle:
 *
 *   SangforHandle *h = sangfor_start(plan_json, 1, &error);
 *   sangfor_set_effect_handler(h, on_effect, ctx);
 *   // pump the TUN / packet flow:
 *   sangfor_write_packet(h, packet, len);
 *   // report transport events:
 *   sangfor_on_node_connected(h, connection);
 *   sangfor_on_node_data(h, connection, bytes, len);
 *   ...
 *   sangfor_stop(h);
 *
 * Every string this header hands out is heap-allocated and must be released
 * with sangfor_free(). Buffers passed in are copied before the call returns.
 */
#ifndef SANGFOR_FFI_H
#define SANGFOR_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SangforHandle SangforHandle;

/* What the host must do, delivered through SangforEffectFn. */
enum SangforEffectKind {
  /* Open a TLS channel to `text` ("host:port"); report back with
   * sangfor_on_node_connected / sangfor_on_node_failed. */
  SANGFOR_EFFECT_CONNECT_NODE = 1,
  /* Send `bytes` on node channel `id`. */
  SANGFOR_EFFECT_SEND = 2,
  /* Close node channel `id`. */
  SANGFOR_EFFECT_CLOSE_NODE = 3,
  /* Write `bytes` (one raw IP packet) into the TUN / packet flow. */
  SANGFOR_EFFECT_EMIT_PACKET = 4,
  /* Open a TCP-tunnel connection to `text` for dial `id`. */
  SANGFOR_EFFECT_DIAL = 5,
  /* Write `bytes` to relay stream `id`. */
  SANGFOR_EFFECT_RELAY_SEND = 6,
  /* Half-close relay stream `id`. */
  SANGFOR_EFFECT_RELAY_CLOSE_WRITE = 7,
  /* Close relay stream `id`. */
  SANGFOR_EFFECT_RELAY_CLOSE = 8,
  /* Throttle relay stream `id`; `len` is 1 when pausing, 0 when resuming. */
  SANGFOR_EFFECT_RELAY_PAUSE = 9,
  /* The gateway assigned a virtual IP; `text` is a comma-separated list. */
  SANGFOR_EFFECT_VIRTUAL_IP = 10,
  /* A diagnostic to log; `text` carries the message. */
  SANGFOR_EFFECT_ERROR = 11,
  /* The session is dead; the control plane must log in again. */
  SANGFOR_EFFECT_FATAL = 12
};

/* Fields that do not apply to a kind are null. `bytes` is only valid for the
 * duration of the call. */
typedef void (*SangforEffectFn)(void *ctx,
                                int32_t kind,
                                uint64_t id,
                                const uint8_t *bytes,
                                size_t len,
                                const char *text);

/* Starts a data plane from a session plan document (JSON). `spawn_runtime`
 * non-zero starts the thread that drives timers; pass 0 and call
 * sangfor_tick() yourself to keep the core on your own event loop.
 * Returns NULL on failure and writes a heap string to *error (free it with
 * sangfor_free). */
SangforHandle *sangfor_start(const char *plan_json,
                             int spawn_runtime,
                             char **error);

void sangfor_set_effect_handler(SangforHandle *handle,
                                SangforEffectFn callback,
                                void *ctx);

/* One egress packet. Returns 0 when the plane handled it, non-zero when it
 * declined (no resource covers the destination). */
int sangfor_write_packet(SangforHandle *handle, const uint8_t *packet, size_t len);

void sangfor_tick(SangforHandle *handle);

/* JSON counters; free with sangfor_free. */
char *sangfor_stats(SangforHandle *handle);

/* The assigned virtual IP, or NULL before the handshake; free with
 * sangfor_free. */
char *sangfor_virtual_ip(SangforHandle *handle);

void sangfor_on_node_connected(SangforHandle *handle, uint64_t connection);
void sangfor_on_node_failed(SangforHandle *handle,
                            uint64_t connection,
                            const char *message);
void sangfor_on_node_data(SangforHandle *handle,
                          uint64_t connection,
                          const uint8_t *data,
                          size_t len);
void sangfor_on_node_closed(SangforHandle *handle,
                            uint64_t connection,
                            const char *message);

void sangfor_on_dial_connected(SangforHandle *handle, uint64_t dial);
void sangfor_on_dial_failed(SangforHandle *handle, uint64_t dial, const char *message);
void sangfor_on_relay_data(SangforHandle *handle,
                           uint64_t dial,
                           const uint8_t *data,
                           size_t len);
void sangfor_on_relay_closed(SangforHandle *handle, uint64_t dial);

/* Stops the plane, joins the runtime thread, and frees the handle.
 * Idempotent; NULL is a no-op. */
void sangfor_stop(SangforHandle *handle);

void sangfor_free(void *pointer);

#ifdef __cplusplus
}
#endif

#endif /* SANGFOR_FFI_H */
