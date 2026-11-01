#ifndef CA_SPECK128_H
#define CA_SPECK128_H

#include <stdint.h>

#define SPECK128_KEY_BYTES 16
#define SPECK128_BLOCK_BYTES 16
#define SPECK128_ROUNDS 32

// 128-bit block and a 128-bit key
typedef struct {
    uint64_t round_keys[SPECK128_ROUNDS];
} speck128_ctx;

/*
 * Buffers must contain the fixed number of bytes specified above.
 * Byte order follows the designers' 2019 implementation guide: little-endian
 * words, with the first eight block bytes representing y and the next eight x.
 * A context contains the expanded key and can be reused for multiple blocks.
 */
void speck128_init(speck128_ctx *ctx, const uint8_t key[SPECK128_KEY_BYTES]);

void speck128_cipher_block(const speck128_ctx *ctx, const uint8_t input[SPECK128_BLOCK_BYTES], uint8_t output[SPECK128_BLOCK_BYTES]);
void speck128_decipher_block(const speck128_ctx *ctx, const uint8_t input[SPECK128_BLOCK_BYTES], uint8_t output[SPECK128_BLOCK_BYTES]);

#endif
