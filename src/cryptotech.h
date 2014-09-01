#pragma once

#include "pEpEngine.h"

typedef enum _PEP_cryptotech {
    PEP_crypt_none = 0,
    PEP_crypt_OpenPGP = 0x2f,
//    PEP_ctypt_PEP = 0x6f,
//    PEP_crypt_SMIME = 0x10,
//    PEP_crypt_CMS = 0x20,

    PEP_crypt__count
};

typedef PEP_STATUS (*decrypt_and_verify_t)(
    PEP_SESSION session, const char *ctext, size_t csize,
    char **ptext, size_t *psize, stringlist_t **keylist
    );

typedef PEP_STATUS (*verify_text_t)(
    PEP_SESSION session, const char *text, size_t size,
    const char *signature, size_t sig_size, stringlist_t **keylist
    );

typedef PEP_STATUS (*encrypt_and_sign_t)(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    );

typedef struct _PEP_cryptotech_t {
    uint8_t id;
    decrypt_and_verify_t decrypt_and_verify;
    verify_text_t verify_text;
    encrypt_and_sign_t encrypt_and_sign;
} PEP_cryptotech_t;

typedef uint64_t cryptotech_mask;
