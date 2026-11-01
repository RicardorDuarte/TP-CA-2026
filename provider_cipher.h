#ifndef CA_PROVIDER_CIPHER_H
#define CA_PROVIDER_CIPHER_H

#include <openssl/core.h>

extern const OSSL_DISPATCH speck_ecb_functions[];
extern const OSSL_DISPATCH speck_cbc_functions[];
extern const OSSL_DISPATCH speck_ctr_functions[];
extern const OSSL_DISPATCH trivium_functions[];

#endif
