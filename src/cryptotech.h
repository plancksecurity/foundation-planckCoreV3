// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef CRYPTOTECH_H
#define CRYPTOTECH_H

#include "pEpEngine.h"
#include "bloblist.h"

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
        const char *dsigtext, size_t dsigsize,
        char **ptext, size_t *psize, stringlist_t **keylist,
        char **filename_ptr 
    );

typedef PEP_STATUS (*verify_text_t)(
        PEP_SESSION session, const char *text, size_t size,
        const char *signature, size_t sig_size, stringlist_t **keylist
    );

typedef PEP_STATUS (*encrypt_and_sign_t)(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );

typedef PEP_STATUS (*encrypt_only_t)(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );

typedef PEP_STATUS (*sign_only_t)(
        PEP_SESSION session, const char* fpr, const char *ptext,
        size_t psize, char **stext, size_t *ssize
    );

typedef PEP_STATUS (*delete_keypair_t)(PEP_SESSION session, const char *fpr);

typedef PEP_STATUS (*export_key_t)(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size,
        bool secret
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
        size_t size, identity_list **private_keys, stringlist_t** imported_keys,
        uint64_t* changed_key_index);

typedef PEP_STATUS (*recv_key_t)(PEP_SESSION session, const char *pattern);

typedef PEP_STATUS (*send_key_t)(PEP_SESSION session, const char *pattern);

typedef PEP_STATUS (*renew_key_t)(PEP_SESSION session, const char *fpr,
        const timestamp *ts);

typedef PEP_STATUS (*revoke_key_t)(PEP_SESSION session, const char *fpr,
        const char *reason);

typedef PEP_STATUS (*key_expired_t)(PEP_SESSION session, const char *fpr,
        const time_t when, bool *expired);

typedef PEP_STATUS (*key_revoked_t)(PEP_SESSION session, const char *fpr,
        bool *revoked);

typedef PEP_STATUS (*key_created_t)(PEP_SESSION session, const char *fpr,
        time_t *created);

typedef PEP_STATUS (*binary_path_t)(const char **path);

typedef PEP_STATUS (*contains_priv_key_t)(PEP_SESSION session, const char *fpr,
        bool *has_private);

typedef PEP_STATUS (*find_private_keys_t)(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
);

typedef PEP_STATUS (*config_cipher_suite_t)(PEP_SESSION session,
        PEP_CIPHER_SUITE suite);

typedef struct _PEP_cryptotech_t {
    uint8_t id;
    // the following are default values; comm_type may vary with key length or b0rken crypto
    uint8_t unconfirmed_comm_type;
    uint8_t confirmed_comm_type;
    decrypt_and_verify_t decrypt_and_verify;
    verify_text_t verify_text;
    encrypt_and_sign_t encrypt_and_sign;
    encrypt_only_t encrypt_only;
    sign_only_t sign_only;    
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
    key_revoked_t key_revoked;
    key_created_t key_created;
    binary_path_t binary_path;
    contains_priv_key_t contains_priv_key;
    find_private_keys_t find_private_keys;
    config_cipher_suite_t config_cipher_suite;
} PEP_cryptotech_t;

extern PEP_cryptotech_t cryptotech[PEP_crypt__count];

typedef uint64_t cryptotech_mask;

PEP_STATUS init_cryptotech(PEP_SESSION session, bool in_first);
void release_cryptotech(PEP_SESSION session, bool out_last);

#endif
