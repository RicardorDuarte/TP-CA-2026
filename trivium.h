#ifndef CA_TRIVIUM_H
#define CA_TRIVIUM_H

#include <stddef.h>
#include <stdint.h>

#define TRIVIUM_KEY_BYTES 10
#define TRIVIUM_IV_BYTES 10
#define TRIVIUM_STATE_BITS 288
#define TRIVIUM_MAX_KEYSTREAM_BYTES (UINT64_C(1) << 61)

typedef struct {
    // One byte per state bit favors readability over speed.
    uint8_t state[TRIVIUM_STATE_BITS];
    uint64_t bytes_generated;
} trivium_ctx;

/*
 * Initialize with exactly 80 key bits and 80 IV bits, then run 1,152 warm-up
 * steps. Key/IV bytes are consumed last byte first, most-significant bit first
 * within each byte: state[0] receives key[9]'s bit 7. The first output bit
 * occupies bit 0 of the first output byte. This convention matches the ECRYPT
 * 80/80 test vectors cited in REPORT_NOTES.md.
 * Reinitialization discards all previous stream state.
 */
void trivium_init(trivium_ctx *ctx, const uint8_t key[TRIVIUM_KEY_BYTES], const uint8_t iv[TRIVIUM_IV_BYTES]);

/*
 * Continue from the current stream position. Return 1 on success, or 0 if the
 * request would exceed 2^64 keystream bits for this initialization. Failure
 * leaves both context and output unchanged. A zero-byte call accepts NULL data
 * buffers and changes no state; ctx must always point to an initialized context.
 * For nonempty calls the caller supplies valid buffers of at least length bytes.
 */
int trivium_generate(trivium_ctx *ctx, uint8_t *output, size_t length);

/* Encryption and decryption are the same XOR operation. In-place is supported;
 * partially overlapping input and output buffers are not supported. */
int trivium_crypt(trivium_ctx *ctx, const uint8_t *input, uint8_t *output, size_t length);

#endif
