#pragma once

#include "pEpEngine.h"

PEP_STATUS pgp_init(PEP_SESSION session, bool in_first);
void pgp_release(PEP_SESSION session, bool out_last);

PEP_STATUS pgp_decrypt_and_verify(
        PEP_SESSION session, const char *ctext, size_t csize,
        char **ptext, size_t *psize, stringlist_t **keylist
    );

PEP_STATUS pgp_encrypt_and_sign(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );

PEP_STATUS pgp_verify_text(
        PEP_SESSION session, const char *text, size_t size,
        const char *signature, size_t sig_size, stringlist_t **keylist
    );

PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr);

PEP_STATUS pgp_export_keydata(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    );

PEP_STATUS pgp_find_keys(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
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
        size_t size);

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
