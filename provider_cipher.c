// callbacks: https://docs.openssl.org/3.5/man7/provider-cipher/
#include "provider_cipher.h"
#include "speck128.h"
#include "trivium.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <string.h>

typedef struct {
    unsigned int mode;
    size_t key_length;
    size_t iv_length;
    size_t block_size;
} cipher_spec;

static const cipher_spec ecb_spec = {EVP_CIPH_ECB_MODE, 16, 0, 16};
static const cipher_spec cbc_spec = {EVP_CIPH_CBC_MODE, 16, 16, 16};
static const cipher_spec ctr_spec = {EVP_CIPH_CTR_MODE, 16, 16, 1};
static const cipher_spec trivium_spec = {EVP_CIPH_STREAM_CIPHER, 10, 10, 1};

typedef struct {
    const cipher_spec *spec;
    union {
        speck128_ctx speck;
        trivium_ctx trivium;
    } core;
    uint8_t key[16];
    uint8_t original_iv[16];
    uint8_t iv[16];
    uint8_t pending[16];
    uint8_t keystream[16];
    size_t pending_length;
    size_t stream_position;
    unsigned int padding; //tudo a partir daqui ou e 0 ou 1
    int encrypting;
    int key_set;
    int iv_set;
    int initialized;
    int started;
    int finished;
    int failed;
    int counter_exhausted;
} cipher_ctx;

static int cipher_error(const char *message){
    ERR_raise_data(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED, "%s", message);
    return 0;
}

static void *cipher_newctx(const cipher_spec *spec){
    cipher_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->spec = spec;
        ctx->padding = 1;
        ctx->iv_set = spec->iv_length == 0;
        ctx->stream_position = 16;
    }
    return ctx;
}

static void *ecb_newctx(void *provctx){
    (void)provctx;
    return cipher_newctx(&ecb_spec);
}

static void *cbc_newctx(void *provctx){
    (void)provctx;
    return cipher_newctx(&cbc_spec);
}

static void *ctr_newctx(void *provctx){
    (void)provctx;
    return cipher_newctx(&ctr_spec);
}

static void *trivium_newctx(void *provctx){
    (void)provctx;
    return cipher_newctx(&trivium_spec);
}

static void cipher_freectx(void *vctx){
    OPENSSL_clear_free(vctx, sizeof(cipher_ctx));
}

static void *cipher_dupctx(void *vctx){
    //o estado esta todo na struct nao ha buffers separados
    return OPENSSL_memdup(vctx, sizeof(cipher_ctx));
}

static const OSSL_PARAM *cipher_gettable_params(void *provctx){
    static const OSSL_PARAM parameters[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
        OSSL_PARAM_END
    };

    (void)provctx;
    return parameters;
}

static int cipher_get_params(OSSL_PARAM params[], const cipher_spec *spec){
    OSSL_PARAM *parameter;

    parameter = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (parameter != NULL && !OSSL_PARAM_set_uint(parameter, spec->mode)) return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (parameter != NULL && !OSSL_PARAM_set_size_t(parameter, spec->key_length)) return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (parameter != NULL && !OSSL_PARAM_set_size_t(parameter, spec->iv_length)) return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (parameter != NULL && !OSSL_PARAM_set_size_t(parameter, spec->block_size)) return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (parameter != NULL && !OSSL_PARAM_set_int(parameter, 0)) return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (parameter != NULL && !OSSL_PARAM_set_int(parameter, 0)) return 0;
    return 1;
}

static int ecb_get_params(OSSL_PARAM params[]){
    return cipher_get_params(params, &ecb_spec);
}

static int cbc_get_params(OSSL_PARAM params[]){
    return cipher_get_params(params, &cbc_spec);
}

static int ctr_get_params(OSSL_PARAM params[]){
    return cipher_get_params(params, &ctr_spec);
}

static int trivium_get_params(OSSL_PARAM params[]){
    return cipher_get_params(params, &trivium_spec);
}

static const OSSL_PARAM *cipher_gettable_ctx_params(void *vctx, void *provctx){
    static const OSSL_PARAM parameters[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
        OSSL_PARAM_END
    };

    (void)vctx;
    (void)provctx;
    return parameters;
}

static const OSSL_PARAM *cipher_settable_ctx_params(void *vctx, void *provctx){
    static const OSSL_PARAM parameters[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_END
    };

    (void)vctx;
    (void)provctx;
    return parameters;
}

static int cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[]){
    cipher_ctx *ctx = vctx;
    const OSSL_PARAM *parameter;
    size_t length;
    unsigned int padding = ctx->padding;

    if (params == NULL) return 1;
    parameter = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (parameter != NULL && (!OSSL_PARAM_get_size_t(parameter, &length) || length != ctx->spec->key_length)) {
        return cipher_error("incorrect key length");
    }
    parameter = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (parameter != NULL && (!OSSL_PARAM_get_size_t(parameter, &length) || length != ctx->spec->iv_length)) {
        return cipher_error("incorrect IV length");
    }
    parameter = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (parameter != NULL && (!OSSL_PARAM_get_uint(parameter, &padding) || padding > 1)) {
        return cipher_error("padding must be 0 or 1");
    }
    if (ctx->started && padding != ctx->padding) {
        return cipher_error("set padding before supplying data");
    }
    ctx->padding = padding;
    return 1;
}

static int set_iv_parameter(OSSL_PARAM *parameter, const uint8_t *iv, size_t length){
    if (parameter->data_type == OSSL_PARAM_OCTET_PTR) {
        return OSSL_PARAM_set_octet_ptr(parameter, iv, length);
    }
    return OSSL_PARAM_set_octet_string(parameter, iv, length);
}

static int cipher_get_ctx_params(void *vctx, OSSL_PARAM params[]){
    cipher_ctx *ctx = vctx;
    OSSL_PARAM *parameter;
    unsigned int num = 0;

    if (params == NULL) return 1;
    if (ctx->spec->mode == EVP_CIPH_CTR_MODE && ctx->stream_position < 16) {
        num = (unsigned int)ctx->stream_position;
    }
    parameter = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (parameter != NULL && !OSSL_PARAM_set_size_t(parameter, ctx->spec->key_length)) return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (parameter != NULL && !OSSL_PARAM_set_size_t(parameter, ctx->spec->iv_length)) return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (parameter != NULL && !OSSL_PARAM_set_uint(parameter, ctx->padding)) return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (parameter != NULL && !OSSL_PARAM_set_uint(parameter, num)) return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (parameter != NULL && !set_iv_parameter(parameter, ctx->original_iv, ctx->spec->iv_length)) return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (parameter != NULL && !set_iv_parameter(parameter, ctx->iv, ctx->spec->iv_length)) return 0;
    return 1;
}

static int cipher_init(void *vctx, const unsigned char *key, size_t key_length,
                        const unsigned char *iv, size_t iv_length, const OSSL_PARAM params[], int encrypting){

    cipher_ctx *ctx = vctx;
    cipher_ctx next = *ctx;

    if (key != NULL && key_length != ctx->spec->key_length) return cipher_error("incorrect key length");
    if (iv != NULL && iv_length != ctx->spec->iv_length) return cipher_error("incorrect IV length");
    next.started = 0;
    if (!cipher_set_ctx_params(&next, params)) return 0;
    if (key != NULL) {
        memcpy(next.key, key, key_length);
        next.key_set = 1;
    }
    if (iv != NULL && iv_length != 0) {
        memcpy(next.original_iv, iv, iv_length);
        next.iv_set = 1;
    }
    memcpy(next.iv, next.original_iv, sizeof(next.iv));
    next.encrypting = encrypting;
    next.pending_length = 0;
    next.stream_position = 16;
    next.counter_exhausted = 0;
    next.finished = 0;
    next.failed = 0;
    next.initialized = 1;

    // key e iv podem chegar em chamadas diferentes
    if (next.key_set) {
        if (next.spec->mode == EVP_CIPH_STREAM_CIPHER) {
            if (next.iv_set) trivium_init(&next.core.trivium, next.key, next.original_iv);
        } else {
            speck128_init(&next.core.speck, next.key);
        }
    }
    *ctx = next;
    OPENSSL_cleanse(&next, sizeof(next));
    return 1;
}

static int cipher_encrypt_init(void *vctx, const unsigned char *key, size_t key_length,
                                const unsigned char *iv, size_t iv_length, const OSSL_PARAM params[]){

    return cipher_init(vctx, key, key_length, iv, iv_length, params, 1);
}

static int cipher_decrypt_init(void *vctx, const unsigned char *key, size_t key_length,
                                const unsigned char *iv, size_t iv_length, const OSSL_PARAM params[]){

    return cipher_init(vctx, key, key_length, iv, iv_length, params, 0);
}

static int cipher_ready(const cipher_ctx *ctx){
    if (!ctx->initialized || !ctx->key_set || !ctx->iv_set) {
        return cipher_error("initialize the cipher with a key and required IV");
    }
    if (ctx->finished || ctx->failed) {
        return cipher_error("reinitialize the cipher before starting another operation");
    }
    return 1;
}

static void process_block(cipher_ctx *ctx, const uint8_t input[16], uint8_t output[16]){
    uint8_t block[16];

    if (ctx->encrypting) {
        memcpy(block, input, sizeof(block));
        if (ctx->spec->mode == EVP_CIPH_CBC_MODE) {
            for (size_t i = 0; i < 16; ++i) block[i] ^= ctx->iv[i];
        }
        speck128_cipher_block(&ctx->core.speck, block, output);
        if (ctx->spec->mode == EVP_CIPH_CBC_MODE)
            memcpy(ctx->iv, output, 16);
    } else {
        speck128_decipher_block(&ctx->core.speck, input, block);
        if (ctx->spec->mode == EVP_CIPH_CBC_MODE) {
            for (size_t i = 0; i < 16; ++i) block[i] ^= ctx->iv[i];
            memcpy(ctx->iv, input, 16);
        }
        memcpy(output, block, 16);
    }
    OPENSSL_cleanse(block, sizeof(block));
}

static int block_update(cipher_ctx *ctx, unsigned char *out, size_t *out_length,
                        size_t out_size, const unsigned char *input, size_t length){

    size_t total;
    size_t blocks;
    size_t written = 0;
    uint8_t *input_copy = NULL;
    size_t original_length = length;

    if (length > SIZE_MAX - ctx->pending_length)
        return cipher_error("input length overflow");
    total = ctx->pending_length + length;
    blocks = total / 16;
    // deixa o ultimo bloco para o final quando ha padding na decifragem
    if (!ctx->encrypting && ctx->padding && total != 0) {
        blocks = (total - 1) / 16;
    }
    if (out_size < blocks * 16 || (blocks != 0 && out == NULL)) {
        return cipher_error("output buffer is too small");
    }

    // copia o input para nao dar overwrite com bytes pendentes
    if (out == input && ctx->pending_length != 0 && length != 0) {
        input_copy = OPENSSL_memdup(input, length);
        if (input_copy == NULL) return 0;
        input = input_copy;
    }
    while (length != 0) {
        size_t take;

        if (ctx->pending_length == 16) {
            process_block(ctx, ctx->pending, out + written);
            written += 16;
            ctx->pending_length = 0;
        }
        take = 16 - ctx->pending_length;
        if (take > length) take = length;
        memcpy(ctx->pending + ctx->pending_length, input, take);
        ctx->pending_length += take;
        input += take;
        length -= take;

        if (ctx->pending_length == 16 && (ctx->encrypting || !ctx->padding)) {
            process_block(ctx, ctx->pending, out + written);
            written += 16;
            ctx->pending_length = 0;
        }
    }
    OPENSSL_clear_free(input_copy, original_length);
    *out_length = written;
    return 1;
}

static int ctr_can_process(const cipher_ctx *ctx, size_t length){
    uint8_t last_counter[16];
    size_t cached = ctx->stream_position < 16 ? 16 - ctx->stream_position : 0;
    size_t remaining;
    size_t blocks;
    size_t carry;

    if (length <= cached)
        return 1;
    remaining = length - cached;
    blocks = remaining / 16 + (remaining % 16 != 0);
    if (ctx->counter_exhausted)
        return cipher_error("CTR counter exhausted");

    // verifica se o contador vai dar a volta antes de escrever
    memcpy(last_counter, ctx->iv, sizeof(last_counter));
    carry = blocks - 1;
    for (int i = 15; i >= 0; --i) {
        unsigned int sum = last_counter[i] + (unsigned int)(carry & 0xff);
        last_counter[i] = (uint8_t)sum;
        carry = (carry >> 8) + (sum >> 8);
    }
    return carry == 0 ? 1 : cipher_error("CTR counter would wrap");
}

static void ctr_update(cipher_ctx *ctx, const uint8_t *input, uint8_t *out, size_t length){
    for (size_t i = 0; i < length; ++i) {
        if (ctx->stream_position == 16) {
            speck128_cipher_block(&ctx->core.speck, ctx->iv, ctx->keystream);
            ctx->stream_position = 0;

            // contador big-endian, soma a partir do ultimo byte
            for (int j = 15; j >= 0; --j) {
                if (++ctx->iv[j] != 0) break;
                if (j == 0) ctx->counter_exhausted = 1;
            }
        }
        out[i] = input[i] ^ ctx->keystream[ctx->stream_position++];
    }
}

static int cipher_update(void *vctx, unsigned char *out, size_t *out_length, size_t out_size,
                            const unsigned char *input, size_t length){

    cipher_ctx *ctx = vctx;
    int result;

    if (out_length == NULL) return cipher_error("missing output length");
    *out_length = 0;
    if (!cipher_ready(ctx)) return 0;
    if (length == 0) return 1;
    if (input == NULL) return cipher_error("missing input buffer");

    if (ctx->spec->block_size == 16) {
        result = block_update(ctx, out, out_length, out_size, input, length);
    } else {
        if (out_size < length || out == NULL) return cipher_error("output buffer is too small");
        if (ctx->spec->mode == EVP_CIPH_CTR_MODE) {
            if (!ctr_can_process(ctx, length)) return 0;
            ctr_update(ctx, input, out, length);
        } else if (!trivium_crypt(&ctx->core.trivium, input, out, length)) {
            return cipher_error("Trivium keystream limit exceeded");
        }
        *out_length = length;
        result = 1;
    }
    if (result) ctx->started = 1;
    return result;
}

static int cipher_final(void *vctx, unsigned char *out, size_t *out_length, size_t out_size){
    cipher_ctx *ctx = vctx;
    uint8_t block[16];

    if (out_length == NULL) return cipher_error("missing output length");
    *out_length = 0;
    if (!cipher_ready(ctx)) return 0;
    if (ctx->spec->block_size == 1 || !ctx->padding) {
        if (ctx->pending_length != 0) {
            ctx->failed = 1;
            return cipher_error("incomplete block with padding disabled");
        }
    } else if (ctx->encrypting) {
        uint8_t padding = (uint8_t)(16 - ctx->pending_length);

        if (out_size < 16 || out == NULL) return cipher_error("output buffer is too small");
        memcpy(block, ctx->pending, ctx->pending_length);
        memset(block + ctx->pending_length, padding, padding);
        process_block(ctx, block, out);
        *out_length = 16;
    } else {
        cipher_ctx next = *ctx;
        unsigned int padding;
        unsigned int invalid;
        size_t length;

        if (ctx->pending_length != 16) {
            ctx->failed = 1;
            return cipher_error("padded ciphertext needs a complete final block");
        }
        process_block(&next, ctx->pending, block);
        padding = block[15];
        invalid = (padding == 0 || padding > 16);
        // verifica os 16 bytes mesmo que ja tenha encontrado um erro
        for (unsigned int i = 0; i < 16; ++i) {
            unsigned int mask = 0u - (unsigned int)(i < padding);
            invalid |= ((unsigned int)block[15 - i] ^ padding) & mask;
        }
        if (invalid) {
            OPENSSL_cleanse(block, sizeof(block));
            OPENSSL_cleanse(&next, sizeof(next));
            ctx->failed = 1;
            return cipher_error("invalid PKCS#7 padding");
        }
        length = 16 - padding;
        if (out_size < length || (length != 0 && out == NULL)) {
            OPENSSL_cleanse(block, sizeof(block));
            OPENSSL_cleanse(&next, sizeof(next));
            return cipher_error("output buffer is too small");
        }
        if (length != 0) memcpy(out, block, length);
        *out_length = length;
        *ctx = next;
        OPENSSL_cleanse(&next, sizeof(next));
    }
    OPENSSL_cleanse(block, sizeof(block));
    OPENSSL_cleanse(ctx->pending, sizeof(ctx->pending));
    ctx->pending_length = 0;
    ctx->finished = 1;
    return 1;
}

static int cipher_raw(void *vctx, unsigned char *out, size_t *out_length, size_t out_size,
                        const unsigned char *input, size_t length){

    cipher_ctx *ctx = vctx;
    cipher_ctx next = *ctx;
    int result;

    // EVP_Cipher nao usa padding
    if (ctx->pending_length != 0 || length % ctx->spec->block_size != 0) {
        if (out_length != NULL) *out_length = 0;
        return cipher_error("raw cipher input must contain complete blocks");
    }
    next.padding = 0;
    result = cipher_update(&next, out, out_length, out_size, input, length);
    if (result) {
        next.padding = ctx->padding;
        *ctx = next;
    }
    OPENSSL_cleanse(&next, sizeof(next));
    return result;
}

const OSSL_DISPATCH speck_ecb_functions[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))ecb_newctx},
    {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))cipher_freectx},
    {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))cipher_dupctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))cipher_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))cipher_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))cipher_update},
    {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))cipher_final},
    {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))cipher_raw},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))ecb_get_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))cipher_gettable_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))cipher_get_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))cipher_set_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))cipher_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))cipher_settable_ctx_params},
    {0, NULL}
};

const OSSL_DISPATCH speck_cbc_functions[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))cbc_newctx},
    {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))cipher_freectx},
    {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))cipher_dupctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))cipher_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))cipher_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))cipher_update},
    {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))cipher_final},
    {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))cipher_raw},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))cbc_get_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))cipher_gettable_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))cipher_get_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))cipher_set_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))cipher_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))cipher_settable_ctx_params},
    {0, NULL}
};

const OSSL_DISPATCH speck_ctr_functions[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))ctr_newctx},
    {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))cipher_freectx},
    {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))cipher_dupctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))cipher_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))cipher_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))cipher_update},
    {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))cipher_final},
    {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))cipher_raw},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))ctr_get_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))cipher_gettable_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))cipher_get_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))cipher_set_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))cipher_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))cipher_settable_ctx_params},
    {0, NULL}
};

const OSSL_DISPATCH trivium_functions[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))trivium_newctx},
    {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))cipher_freectx},
    {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))cipher_dupctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))cipher_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))cipher_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))cipher_update},
    {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))cipher_final},
    {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))cipher_raw},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))trivium_get_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))cipher_gettable_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))cipher_get_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))cipher_set_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))cipher_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))cipher_settable_ctx_params},
    {0, NULL}
};
