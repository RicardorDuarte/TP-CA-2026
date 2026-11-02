#ifndef CA_TRIVIUM_H
#define CA_TRIVIUM_H

#include <stddef.h>
#include <stdint.h>

#define TRIVIUM_KEY_BYTES 10
#define TRIVIUM_IV_BYTES 10
#define TRIVIUM_STATE_BITS 288
#define TRIVIUM_MAX_KEYSTREAM_BYTES (UINT64_C(1) << 61)

typedef struct {
    // um bit por posicao
    uint8_t state[TRIVIUM_STATE_BITS];
    uint64_t bytes_generated;
} trivium_ctx;

// key/iv: ultimo byte primeiro, bit mais alto primeiro
// primeiro bit gerado fica no bit 0 do byte
void trivium_init(trivium_ctx *ctx, const uint8_t key[TRIVIUM_KEY_BYTES], const uint8_t iv[TRIVIUM_IV_BYTES]);

// devolve 0 se passar do limite, sem alterar o estado nem o output
// buffers NULL so com length 0
int trivium_generate(trivium_ctx *ctx, uint8_t *output, size_t length);

// serve para cifrar e decifrar; input e output podem ser o mesmo buffer
// nao aceita buffers parcialmente sobrepostos
int trivium_crypt(trivium_ctx *ctx, const uint8_t *input, uint8_t *output, size_t length);

#endif
