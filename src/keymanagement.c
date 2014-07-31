#ifndef WIN32 // UNIX
#define _POSIX_C_SOURCE 200809L
#else
#include "platform_windows.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define _EXPORT_PEP_ENGINE_DLL
#include "pEpEngine.h"
#include "keymanagement.h"

#ifndef MIN
#define MIN(A, B) ((B) > (A) ? (A) : (B))
#endif

#ifndef EMPTY
#define EMPTY(STR) ((STR == NULL) || (STR)[0] == 0)
#endif

DYNAMIC_API PEP_STATUS update_identity(
        PEP_SESSION session, pEp_identity * identity
    )
{
    pEp_identity *stored_identity;
    PEP_STATUS status;

    assert(session);
    assert(identity);
    assert(identity->address);

    status = get_identity(session, identity->address, &stored_identity);
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;

    PEP_comm_type _comm_type_key;
    status = get_key_rating(session, stored_identity->fpr, &_comm_type_key);
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;

    if (stored_identity) {
        if (EMPTY(identity->fpr)) {
            identity->fpr = strdup(stored_identity->fpr);
            assert(identity->fpr);
            if (identity->fpr == NULL)
                return PEP_OUT_OF_MEMORY;
            identity->fpr_size = stored_identity->address_size;
        }
        else /* !EMPTY(identity->fpr) */ {
            stringlist_t *keylist;

            status = find_keys(session, identity->fpr, &keylist);
            assert(status != PEP_OUT_OF_MEMORY);
            if (status == PEP_OUT_OF_MEMORY)
                return PEP_OUT_OF_MEMORY;

            if (keylist && keylist->value) {
                if (identity->comm_type == PEP_ct_unknown) {
                    if (strcmp(identity->fpr, stored_identity->fpr) == 0) {
                        identity->comm_type = stored_identity->comm_type;
                    }
                    else {
                        status = get_trust(session, identity);
                        assert(status != PEP_OUT_OF_MEMORY);
                        if (status == PEP_OUT_OF_MEMORY)
                            return PEP_OUT_OF_MEMORY;
                    }
                }
            }
            else
                identity->comm_type = PEP_ct_unknown;

            free_stringlist(keylist);
        }

        if (EMPTY(identity->username)) {
            free(identity->username);
            identity->username = strdup(stored_identity->username);
            assert(identity->username);
            if (identity->username == NULL)
                return PEP_OUT_OF_MEMORY;
            identity->username_size = stored_identity->username_size;
        }

        if (EMPTY(identity->user_id)) {
            free(identity->user_id);
            identity->user_id = strdup(stored_identity->user_id);
            assert(identity->user_id);
            if (identity->user_id == NULL)
                return PEP_OUT_OF_MEMORY;
            identity->user_id_size = stored_identity->user_id_size;
        }

        if (identity->lang[0] == 0) {
            identity->lang[0] = stored_identity->lang[0];
            identity->lang[1] = stored_identity->lang[1];
            identity->lang[2] = 0;
        }
    }
    else /* stored_identity == NULL */ {
        if (identity->fpr && identity->user_id) {
            if (identity->comm_type == PEP_ct_unknown) {
                status = get_trust(session, identity);
                assert(status != PEP_OUT_OF_MEMORY);
                if (status == PEP_OUT_OF_MEMORY)
                    return PEP_OUT_OF_MEMORY;
            }
            if (identity->comm_type != PEP_ct_unknown && EMPTY(identity->username)) {
                free(identity->username);
                identity->username = strdup("anonymous");
                identity->username_size = 10;
            }
        }
        else
            identity->comm_type = PEP_ct_unknown;
    }

    status = PEP_STATUS_OK;

    if (identity->comm_type != PEP_ct_unknown) {
        status = set_identity(session, identity);
        assert(status == PEP_STATUS_OK);
    }

    return status;
}

DYNAMIC_API PEP_STATUS outgoing_comm_type(
        PEP_SESSION session,
        const stringlist_t *addresses,
        PEP_comm_type *comm_type
    )
{
    const stringlist_t *l;

    assert(session);
    assert(addresses);
    assert(addresses->value);
    assert(comm_type);

    *comm_type = PEP_ct_unknown;

    for (l=addresses; l && l->value; l = l->next) {
        PEP_STATUS _status;
        pEp_identity *identity;

        _status = get_identity(session, l->value, &identity);
        assert(_status != PEP_OUT_OF_MEMORY);

        if (identity == NULL) {
            *comm_type = PEP_ct_no_encryption;
            return PEP_STATUS_OK;
        }
        else if (identity->comm_type == PEP_ct_unknown) {
            *comm_type = PEP_ct_no_encryption;
            free_identity(identity);
            return PEP_STATUS_OK;
        }
        else if (*comm_type == PEP_ct_unknown) {
            *comm_type = identity->comm_type;
        }
        else if (*comm_type != identity->comm_type) {
            PEP_comm_type min = MIN(*comm_type, identity->comm_type);
            if (min < PEP_ct_unconfirmed_encryption) {
                *comm_type = PEP_ct_no_encryption;
                free_identity(identity);
                return PEP_STATUS_OK;
            }
            else if (min < PEP_ct_unconfirmed_enc_anon)
                *comm_type = PEP_ct_unconfirmed_encryption;
            else if (min < PEP_ct_confirmed_encryption)
                *comm_type = PEP_ct_unconfirmed_enc_anon;
            else if (min < PEP_ct_confirmed_enc_anon)
                *comm_type = PEP_ct_confirmed_encryption;
            else
                *comm_type = PEP_ct_confirmed_enc_anon;
        }

        free_identity(identity);
    }

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS myself(PEP_SESSION session, pEp_identity * identity)
{
    PEP_STATUS status;
    stringlist_t *keylist;

    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->username);
    assert(identity->user_id);

    identity->comm_type = PEP_ct_pEp;
    identity->me = true;

    pEp_identity *_identity;

    log_event(session, "myself", "debug", identity->address, NULL);
    status = get_identity(session, identity->address, &_identity);
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;

    status = find_keys(session, identity->address, &keylist);
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;

    if (keylist == NULL || keylist->value == NULL) {
        log_event(session, "generating key pair", "debug", identity->address, NULL);
        status = generate_keypair(session, identity);
        assert(status != PEP_OUT_OF_MEMORY);
        if (status != PEP_STATUS_OK) {
            char buf[11];
            snprintf(buf, 11, "%d", status);
            log_event(session, "generating key pair failed", "debug", buf, NULL);
            return status;
        }

        status = find_keys(session, identity->address, &keylist);
        assert(status != PEP_OUT_OF_MEMORY);
        if (status == PEP_OUT_OF_MEMORY)
            return PEP_OUT_OF_MEMORY;

        assert(keylist);
    }

    if (identity->fpr)
        free(identity->fpr);
    identity->fpr = strdup(keylist->value);
    assert(identity->fpr);
    free_stringlist(keylist);
    if (identity->fpr == NULL)
        return PEP_OUT_OF_MEMORY;
    identity->fpr_size = strlen(identity->fpr);

    status = set_identity(session, identity);
    assert(status == PEP_STATUS_OK);

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS do_keymanagement(
        retrieve_next_identity_t retrieve_next_identity,
        void *management
    )
{
    PEP_SESSION session;
    pEp_identity *identity;
    PEP_STATUS status = init(&session);

    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        return status;

    log_event(session, "keymanagement thread started", "pEp engine", NULL, NULL);

    while (identity = retrieve_next_identity(management)) {
        assert(identity->address);
        log_event(session, "do_keymanagement", "debug", identity->address, NULL);
        if (identity->me) {
            status = myself(session, identity);
            assert(status != PEP_OUT_OF_MEMORY);
        } else {
            status = recv_key(session, identity->address);
            assert(status != PEP_OUT_OF_MEMORY);
        }
        free_identity(identity);
    }

    log_event(session, "keymanagement thread shutdown", "pEp engine", NULL, NULL);

    release(session);
    return PEP_STATUS_OK;
}

