#pragma once

#include "pEpEngine.h"

typedef enum _PEP_cryptotech {
    PEP_crypt_none = 0,
    PEP_crypt_OpenPGP,
    //    PEP_ctypt_PEP,
    //    PEP_crypt_SMIME,
    //    PEP_crypt_CMS,

    PEP_crypt__count
} PEP_cryptotech;

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

typedef PEP_STATUS (*delete_keypair_t)(PEP_SESSION session, const char *fpr);

typedef PEP_STATUS (*export_key_t)(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    );

typedef PEP_STATUS (*find_keys_t)(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
    );

typedef PEP_STATUS (*generate_keypair_t)(
        PEP_SESSION session, pEp_identity *identity
    );

typedef PEP_STATUS (*get_key_rating_t)(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    );

typedef PEP_STATUS (*import_key_t)(PEP_SESSION session, const char *key_data,
        size_t size);

typedef PEP_STATUS (*recv_key_t)(PEP_SESSION session, const char *pattern);

typedef PEP_STATUS (*send_key_t)(PEP_SESSION session, const char *pattern);

typedef PEP_STATUS (*renew_key_t)(PEP_SESSION session, const char *fpr,
        const timestamp *ts);

typedef PEP_STATUS (*revoke_key_t)(PEP_SESSION session, const char *fpr,
        const char *reason);

typedef PEP_STATUS (*key_expired_t)(PEP_SESSION session, const char *fpr,
        bool *expired);

typedef struct _PEP_cryptotech_t {
    uint8_t id;
    // the following are default values; comm_type may vary with key length or b0rken crypto
    uint8_t unconfirmed_comm_type;
    uint8_t confirmed_comm_type;
    decrypt_and_verify_t decrypt_and_verify;
    verify_text_t verify_text;
    encrypt_and_sign_t encrypt_and_sign;
    delete_keypair_t delete_keypair;
    export_key_t export_key;
    find_keys_t find_keys;
    generate_keypair_t generate_keypair;
    get_key_rating_t get_key_rating;
    import_key_t import_key;
    recv_key_t recv_key;
    send_key_t send_key;
    renew_key_t renew_key;
    revoke_key_t revoke_key;
    key_expired_t key_expired;
} PEP_cryptotech_t;

typedef uint64_t cryptotech_mask;

PEP_STATUS init_cryptotech(PEP_SESSION session, bool in_first);
void release_cryptotech(PEP_SESSION session, bool out_last);
