/**
 * @file    cryptotech.h
 * @brief   cryptotech function typedefs and structures for crypto drivers 
 *          to implement and interface with engine
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef CRYPTOTECH_H
#define CRYPTOTECH_H

#include "pEpEngine.h"
#include "bloblist.h"

/**
 *  @enum    PEP_cryptotech
 *  
 *  @brief    TODO
 *  
 */
typedef enum _PEP_cryptotech {
    PEP_crypt_none = 0,
    PEP_crypt_OpenPGP,
    //    PEP_ctypt_PEP,
    //    PEP_crypt_SMIME,
    //    PEP_crypt_CMS,

    PEP_crypt__count
} PEP_cryptotech;

/**
 *  @copydoc decrypt_and_verify()
 *  Signature for crypto drivers to implement for decrypt_and_verify()
 *  @see decrypt_and_verify()
 */
typedef PEP_STATUS (*decrypt_and_verify_t)(
        PEP_SESSION session, const char *ctext, size_t csize,
        const char *dsigtext, size_t dsigsize,
        char **ptext, size_t *psize, stringlist_t **keylist,
        char **filename_ptr 
    );

/**
 *  @copydoc verify_text()
 *  Signature for crypto drivers to implement for verify_text()
 *  @see verify_text()
 */
typedef PEP_STATUS (*verify_text_t)(
        PEP_SESSION session, const char *text, size_t size,
        const char *signature, size_t sig_size, stringlist_t **keylist
    );

/**
 *  @copydoc encrypt_and_sign()
 *  Signature for crypto drivers to implement for encrypt_and_sign()
 *  @see encrypt_and_sign()
 */
typedef PEP_STATUS (*encrypt_and_sign_t)(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );

/**
 *  @copydoc encrypt_only()
 *  Signature for crypto drivers to implement for encrypt_only()
 *  @see encrypt_only()
 */
typedef PEP_STATUS (*encrypt_only_t)(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );

/**
 *  @copydoc sign_only()
 *  Signature for crypto drivers to implement for sign_only()
 *  @see sign_only
 */
typedef PEP_STATUS (*sign_only_t)(
        PEP_SESSION session, const char* fpr, const char *ptext,
        size_t psize, char **stext, size_t *ssize
    );

/**
 *  @copydoc delete_keypair()
 *  Signature for crypto drivers to implement for delete_keypair()
 *  @see delete_keypair()
 */
typedef PEP_STATUS (*delete_keypair_t)(PEP_SESSION session, const char *fpr);

/**
 *  @copydoc export_key()
 *  Signature for crypto drivers to implement for export_key()
 *  @see export_key()
 */
typedef PEP_STATUS (*export_key_t)(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size,
        bool secret
    );

/**
 *  @copydoc find_keys()
 *  Signature for crypto drivers to implement for find_keys()
 *  @see find_keys()
 */
typedef PEP_STATUS (*find_keys_t)(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
    );

/**
 *  @copydoc generate_keypair()
 *  Signature for crypto drivers to implement for generate_keypair()
 *  @see generate_keypair()
 */
typedef PEP_STATUS (*generate_keypair_t)(
        PEP_SESSION session, pEp_identity *identity
    );

/**
 *  @copydoc get_key_rating()
 *  Signature for crypto drivers to implement for get_key_rating()
 *  @see get_key_rating()
 */
typedef PEP_STATUS (*get_key_rating_t)(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    );

/**
 *  @copydoc import_key()
 *  Signature for crypto drivers to implement for import_key()
 *  @see import_key()
 */
typedef PEP_STATUS (*import_key_t)(PEP_SESSION session, const char *key_data,
        size_t size, identity_list **private_keys, stringlist_t** imported_keys,
        uint64_t* changed_key_index);

/**
 *  @copydoc recv_key()
 *  Signature for crypto drivers to implement for recv_key()
 *  @see recv_key()
 */
typedef PEP_STATUS (*recv_key_t)(PEP_SESSION session, const char *pattern);

/**
 *  @copydoc send_key()
 *  Signature for crypto drivers to implement for send_key()
 *  @see send_key()
 */
typedef PEP_STATUS (*send_key_t)(PEP_SESSION session, const char *pattern);

/**
 *  @copydoc renew_key()
 *  Signature for crypto drivers to implement for renew_key()
 *  @see renew_key()
 */
typedef PEP_STATUS (*renew_key_t)(PEP_SESSION session, const char *fpr,
        const timestamp *ts);

/**
 *  @copydoc revoke_key()
 *  Signature for crypto drivers to implement for revoke_key()
 *  @see revoke_key()
 */
typedef PEP_STATUS (*revoke_key_t)(PEP_SESSION session, const char *fpr,
        const char *reason);

/**
 *  @copydoc key_expired()
 *  Signature for crypto drivers to implement for key_expired()
 *  @see key_expired()
 */
typedef PEP_STATUS (*key_expired_t)(PEP_SESSION session, const char *fpr,
        const time_t when, bool *expired);

/**
 *  @copydoc key_revoked()
 *  Signature for crypto drivers to implement for key_revoked()
 *  @see key_revoked()
 */
typedef PEP_STATUS (*key_revoked_t)(PEP_SESSION session, const char *fpr,
        bool *revoked);

/**
 *  @copydoc key_created()
 *  Signature for crypto drivers to implement for key_created()
 *  @see key_created()
 */
typedef PEP_STATUS (*key_created_t)(PEP_SESSION session, const char *fpr,
        time_t *created);

/**
 *  @copydoc binary_path()
 *  Signature for crypto drivers to implement for binary_path()
 *  @see binary_path()
 */
typedef PEP_STATUS (*binary_path_t)(const char **path);

/**
 *  @copydoc contains_priv_key()
 *  Signature for crypto drivers to implement for contains_priv_key()
 *  @see contains_priv_key()
 */
typedef PEP_STATUS (*contains_priv_key_t)(PEP_SESSION session, const char *fpr,
        bool *has_private);

/**
 *  @copydoc find_private_keys()
 *  Signature for crypto drivers to implement for find_private_keys()
 *  @see find_private_keys()
 */
typedef PEP_STATUS (*find_private_keys_t)(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
);

/**
 *  @copydoc config_cipher_suite()
 *  Signature for crypto drivers to implement for config_cipher_suite()
 *  @see config_cipher_suite()
 */
typedef PEP_STATUS (*config_cipher_suite_t)(PEP_SESSION session,
        PEP_CIPHER_SUITE suite);


/**
 *  @struct    PEP_cryptotech_t
 *  
 *  @brief    TODO
 *  
 */
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

/**
 *  <!--       init_cryptotech()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        PEP_SESSION
 *  @param[in]  in_first       bool
 *  
 */
PEP_STATUS init_cryptotech(PEP_SESSION session, bool in_first);
/**
 *  <!--       release_cryptotech()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        PEP_SESSION
 *  @param[in]  out_last       bool
 *  
 */
void release_cryptotech(PEP_SESSION session, bool out_last);

#endif
