/*
 * adaptado de Wu Han, trivium-c:
 * https://github.com/wuhanstudio/trivium/blob/b8bc30f412c4c9cf3d8ea0c7ed1755be577ebdd1/trivium-c/trivium.c
 * licenca: THIRD_PARTY_NOTICES.md
 */
#include "trivium.h"
#include <string.h>

static uint8_t trivium_clock(trivium_ctx *ctx){
    uint8_t *state = ctx->state;

    // no pdf os bits comecam em 1
    uint8_t t1 = state[65] ^ state[92];
    uint8_t t2 = state[161] ^ state[176];
    uint8_t t3 = state[242] ^ state[287];
    uint8_t output_bit = t1 ^ t2 ^ t3;

    // calcula os tres antes de mexer no estado
    uint8_t s1 = t1 ^ (state[90] & state[91]) ^ state[170];
    uint8_t s2 = t2 ^ (state[174] & state[175]) ^ state[263];
    uint8_t s3 = t3 ^ (state[285] & state[286]) ^ state[68];

    // de tras para a frente para nao perder os bits
    for (int i = TRIVIUM_STATE_BITS - 1; i > 0; --i) {
        state[i] = state[i - 1];
    }

    // inicio de cada registo
    state[0] = s3;
    state[93] = s1;
    state[177] = s2;

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

    for (int byte = 0; byte < TRIVIUM_KEY_BYTES; ++byte) {
        for (int bit = 0; bit < 8; ++bit) {
            int position = byte * 8 + bit;
            ctx->state[position] = (uint8_t)((key[9 - byte] >> (7 - bit)) & 1);
            ctx->state[93 + position] = (uint8_t)((iv[9 - byte] >> (7 - bit)) & 1);
        }
    }
    ctx->state[285] = 1;
    ctx->state[286] = 1;
    ctx->state[287] = 1;


    for (int i = 0; i < 1152; ++i) {
        trivium_clock(ctx);
    }
}

// gera o keystream
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

// xor de cada byte de input com a keystream gerasda. faz cipher e decipher
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
