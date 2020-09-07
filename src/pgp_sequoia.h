/**
 * @file    src/pgp_sequoia.h
 * @brief   pgp sequoia (FIXME: derived from filename)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#include "pEpEngine.h"

PEP_STATUS pgp_init(PEP_SESSION session, bool in_first);
void pgp_release(PEP_SESSION session, bool out_last);

PEP_STATUS pgp_decrypt_and_verify(
        PEP_SESSION session, const char *ctext, size_t csize,
        const char *dsigtext, size_t dsigsize,
        char **ptext, size_t *psize, stringlist_t **keylist,
        char** filename_ptr
    );

PEP_STATUS pgp_encrypt_and_sign(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );

PEP_STATUS pgp_sign_only(
        PEP_SESSION session, const char* fpr, const char *ptext,
        size_t psize, char **stext, size_t *ssize
    );

PEP_STATUS pgp_encrypt_only(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );


PEP_STATUS pgp_verify_text(
        PEP_SESSION session, const char *text, size_t size,
        const char *signature, size_t sig_size, stringlist_t **keylist
    );

PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr);

PEP_STATUS pgp_export_keydata(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size,
        bool secret
    );

PEP_STATUS pgp_find_keys(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
    );

PEP_STATUS pgp_list_keyinfo(
        PEP_SESSION session, const char* pattern, stringpair_list_t** keyinfo_list
    );

PEP_STATUS pgp_generate_keypair(
        PEP_SESSION session, pEp_identity *identity
    );

PEP_STATUS pgp_get_key_rating(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    );

PEP_STATUS pgp_import_keydata(PEP_SESSION session, const char *key_data,
                              size_t size, identity_list **private_idents,
                              stringlist_t** imported_keys,
                              uint64_t* changed_key_index);

PEP_STATUS pgp_import_private_keydata(PEP_SESSION session, const char *key_data,
                                      size_t size, identity_list **private_idents);

PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern);
PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern);

PEP_STATUS pgp_renew_key(
        PEP_SESSION session,
        const char *fpr,
        const timestamp *ts
    );

PEP_STATUS pgp_revoke_key(
        PEP_SESSION session,
        const char *fpr,
        const char *reason
    );

PEP_STATUS pgp_key_expired(
        PEP_SESSION session,
        const char *fpr,
        const time_t when,
        bool *expired
    );

PEP_STATUS pgp_key_revoked(
        PEP_SESSION session,
        const char *fpr,
        bool *revoked
    );

PEP_STATUS pgp_key_created(
        PEP_SESSION session,
        const char *fpr,
        time_t *created
    );

PEP_STATUS pgp_contains_priv_key(
        PEP_SESSION session, 
        const char *fpr,
        bool *has_private);

PEP_STATUS pgp_find_private_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
);

PEP_STATUS pgp_binary(const char **path);

PEP_STATUS pgp_config_cipher_suite(PEP_SESSION session,
        PEP_CIPHER_SUITE suite);

#define PGP_BINARY_PATH pgp_binary
