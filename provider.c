/* Provider interface follows OpenSSL's public provider-base API:
 * https://docs.openssl.org/3.5/man7/provider-base/
 */
#include "provider_cipher.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static const OSSL_ALGORITHM ciphers[] = {
    {"SPECK128-128-ECB", "provider=ca", speck_ecb_functions, "SPECK128/128 in ECB mode"},
    {"SPECK128-128-CBC", "provider=ca", speck_cbc_functions, "SPECK128/128 in CBC mode"},
    {"SPECK128-128-CTR", "provider=ca", speck_ctr_functions, "SPECK128/128 in CTR mode"},
    {"TRIVIUM", "provider=ca", trivium_functions, "Trivium with an 80-bit key and IV"},
    {NULL, NULL, NULL, NULL}
};

static const OSSL_PARAM *provider_gettable_params(void *provctx){
    static const OSSL_PARAM parameters[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
        OSSL_PARAM_uint(OSSL_PROV_PARAM_STATUS, NULL),
        OSSL_PARAM_END
    };

    (void)provctx;
    return parameters;
}

static int provider_get_params(void *provctx, OSSL_PARAM params[]){
    OSSL_PARAM *parameter;

    (void)provctx;
    parameter = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (parameter != NULL && !OSSL_PARAM_set_utf8_ptr(parameter, "Applied Cryptography provider")) {
        return 0;
    }
    parameter = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (parameter != NULL && !OSSL_PARAM_set_utf8_ptr(parameter, "0.1")) {
        return 0;
    }
    parameter = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (parameter != NULL && !OSSL_PARAM_set_uint(parameter, 1)) {
        return 0;
    }
    return 1;
}

static const OSSL_ALGORITHM *provider_query(void *provctx, int operation, int *no_cache){
    (void)provctx;
    *no_cache = 0;
    return operation == OSSL_OP_CIPHER ? ciphers : NULL;
}

static const OSSL_DISPATCH provider_functions[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))provider_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))provider_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))provider_query},
    {0, NULL}
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                        const OSSL_DISPATCH **out, void **provctx){

    (void)handle;
    (void)in;
    *provctx = NULL;
    *out = provider_functions;
    return 1;
}
