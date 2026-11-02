// adaptado de Beaulieu et al., SIMON and SPECK Implementation Guide (2019), sec. 1 e 6
// https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
#include "speck128.h"
#include <stddef.h>

// count tem de ficar entre 1 e 63
static uint64_t rotate_left(uint64_t word, unsigned int count){
    return (word << count) | (word >> (64 - count));
}

static uint64_t rotate_right(uint64_t word, unsigned int count){
    return (word >> count) | (word << (64 - count));
}

static uint64_t load_le64(const uint8_t bytes[8]){
    uint64_t word = 0;

    for (unsigned int i = 0; i < 8; ++i) {
        word |= (uint64_t)bytes[i] << (8 * i);
    }
    return word;
}

static void store_le64(uint8_t bytes[8], uint64_t word){
    for (unsigned int i = 0; i < 8; ++i) {
        bytes[i] = (uint8_t)(word >> (8 * i));
    }
}

static void speck_round(uint64_t *x, uint64_t *y, uint64_t round_key){
    *x = rotate_right(*x, 8);
    *x += *y;
    *x ^= round_key;
    *y = rotate_left(*y, 3);
    *y ^= *x;
}

static void speck_inverse_round(uint64_t *x, uint64_t *y, uint64_t round_key){
    *y ^= *x;
    *y = rotate_right(*y, 3);
    *x ^= round_key;
    *x -= *y;
    *x = rotate_left(*x, 8);
}

//expande a chave original para 32 subchaves de 64 bits
void speck128_init(speck128_ctx *ctx,const uint8_t key[SPECK128_KEY_BYTES]){
    uint64_t a = load_le64(key);
    uint64_t b = load_le64(key + 8);

    for (size_t i = 0; i < SPECK128_ROUNDS - 1; ++i) {
        ctx->round_keys[i] = a;
        speck_round(&b, &a, (uint64_t)i);
    }
    ctx->round_keys[SPECK128_ROUNDS - 1] = a;
}

// pega num bloco e aplica as 32 rondas e guarda o resultado
void speck128_cipher_block(const speck128_ctx *ctx, const uint8_t input[SPECK128_BLOCK_BYTES],
                            uint8_t output[SPECK128_BLOCK_BYTES]){

    uint64_t x = load_le64(input + 8);
    uint64_t y = load_le64(input);

    for (size_t i = 0; i < SPECK128_ROUNDS; ++i) {
        speck_round(&x, &y, ctx->round_keys[i]);
    }

    store_le64(output, y);
    store_le64(output + 8, x);
}

//inverso
void speck128_decipher_block(const speck128_ctx *ctx, const uint8_t input[SPECK128_BLOCK_BYTES],
                            uint8_t output[SPECK128_BLOCK_BYTES]){

    uint64_t x = load_le64(input + 8);
    uint64_t y = load_le64(input);

    for (size_t i = SPECK128_ROUNDS; i > 0; --i) {
        speck_inverse_round(&x, &y, ctx->round_keys[i - 1]);
    }

    store_le64(output, y);
    store_le64(output + 8, x);
}
