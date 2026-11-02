#ifndef CA_SPECK128_H
#define CA_SPECK128_H

#include <stdint.h>

#define SPECK128_KEY_BYTES 16
#define SPECK128_BLOCK_BYTES 16
#define SPECK128_ROUNDS 32

typedef struct {
    uint64_t round_keys[SPECK128_ROUNDS];
} speck128_ctx;

// little-endian: primeiros 8 bytes sao y, os seguintes sao x
void speck128_init(speck128_ctx *ctx, const uint8_t key[SPECK128_KEY_BYTES]);

void speck128_cipher_block(const speck128_ctx *ctx, const uint8_t input[SPECK128_BLOCK_BYTES], uint8_t output[SPECK128_BLOCK_BYTES]);
void speck128_decipher_block(const speck128_ctx *ctx, const uint8_t input[SPECK128_BLOCK_BYTES], uint8_t output[SPECK128_BLOCK_BYTES]);

#endif
