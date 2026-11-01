/*
 * Original, bit-based implementation of the designers' Trivium specification.
 * Source: Christophe De Canniere, Analysis and Design of Symmetric Encryption
 * Algorithms (2007), section 6.7, with Bart Preneel as thesis supervisor.
 * https://cosicdatabase.esat.kuleuven.be/backend/publications/files/these/139
 * No implementation code from the test-vector mirror is used here.
 */
#include "trivium.h"
#include <string.h>

static uint8_t trivium_clock(trivium_ctx *ctx){
    uint8_t *state = ctx->state;

    /* The specification numbers bits 1..288; C indexes them 0..287. */
    uint8_t t1 = state[65] ^ state[92];
    uint8_t t2 = state[161] ^ state[176];
    uint8_t t3 = state[242] ^ state[287];
    uint8_t output_bit = t1 ^ t2 ^ t3;

    /* Compute all feedback bits before shifting any register. */
    t1 ^= (state[90] & state[91]) ^ state[170];
    t2 ^= (state[174] & state[175]) ^ state[263];
    t3 ^= (state[285] & state[286]) ^ state[68];

    /* Three registers, of lengths 93, 84 and 111 bits. */
    memmove(state + 1, state, 92);
    state[0] = t3;
    memmove(state + 94, state + 93, 83);
    state[93] = t1;
    memmove(state + 178, state + 177, 110);
    state[177] = t2;

    return output_bit;
}

static uint8_t trivium_next_byte(trivium_ctx *ctx){
    uint8_t output = 0;

    for (unsigned int i = 0; i < 8; ++i) {
        output |= (uint8_t)(trivium_clock(ctx) << i);
    }
    return output;
}

void trivium_init(trivium_ctx *ctx, const uint8_t key[TRIVIUM_KEY_BYTES], const uint8_t iv[TRIVIUM_IV_BYTES]){

    memset(ctx, 0, sizeof(*ctx));

    for (unsigned int i = 0; i < 80; ++i) {
        unsigned int byte_index = TRIVIUM_KEY_BYTES - 1 - (i / 8);
        unsigned int shift = 7 - (i % 8);

        /* ECRYPT vector convention: last byte first, high bit first. */
        ctx->state[i] = (uint8_t)((key[byte_index] >> shift) & 1);
        ctx->state[93 + i] = (uint8_t)((iv[byte_index] >> shift) & 1);
    }
    ctx->state[285] = 1;
    ctx->state[286] = 1;
    ctx->state[287] = 1;

    for (unsigned int i = 0; i < 4 * TRIVIUM_STATE_BITS; ++i) {
        (void)trivium_clock(ctx);
    }
}

int trivium_generate(trivium_ctx *ctx, uint8_t *output, size_t length){
    if (length > TRIVIUM_MAX_KEYSTREAM_BYTES - ctx->bytes_generated) {
        return 0;
    }

    for (size_t i = 0; i < length; ++i) {
        output[i] = trivium_next_byte(ctx);
    }
    ctx->bytes_generated += length;
    return 1;
}

int trivium_crypt(trivium_ctx *ctx, const uint8_t *input, uint8_t *output, size_t length){

    if (length > TRIVIUM_MAX_KEYSTREAM_BYTES - ctx->bytes_generated) {
        return 0;
    }

    for (size_t i = 0; i < length; ++i) {
        output[i] = input[i] ^ trivium_next_byte(ctx);
    }
    ctx->bytes_generated += length;
    return 1;
}
