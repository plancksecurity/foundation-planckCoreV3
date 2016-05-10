#include "platform.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

#include "pEp_internal.h"
#include "keymanagement.h"

#ifndef EMPTYSTR
#define EMPTYSTR(STR) ((STR) == NULL || (STR)[0] == '\0')
#endif

#define KEY_EXPIRE_DELTA (60 * 60 * 24 * 365)

// Space tolerant and case insensitive fingerprint string compare
static int _same_fpr(
        const char* fpra,
        size_t fpras,
        const char* fprb,
        size_t fprbs
    )
{
    size_t ai = 0;
    size_t bi = 0;
    
    do
    {
        if(fpra[ai] == 0 || fprb[bi] == 0)
        {
            return 0;
        }
        else if(fpra[ai] == ' ')
        {
            ai++;
        }
        else if(fprb[bi] == ' ')
        {
            bi++;
        }
        else if(toupper(fpra[ai]) == toupper(fprb[bi]))
        {
            ai++;
            bi++;
        }
        else
        {
            return 0;
        }
        
    }
    while(ai < fpras && bi < fprbs);
    
    return ai == fpras && bi == fprbs;
}

DYNAMIC_API PEP_STATUS update_identity(
        PEP_SESSION session, pEp_identity * identity
    )
{
    pEp_identity *stored_identity;
    PEP_STATUS status;

    assert(session);
    assert(identity);
    assert(!EMPTYSTR(identity->address));

    if (!(session && identity && !EMPTYSTR(identity->address)))
        return PEP_ILLEGAL_VALUE;

    int _no_user_id = EMPTYSTR(identity->user_id);

    if (_no_user_id)
    {
        free(identity->user_id);

        identity->user_id = calloc(1, identity->address_size + 6);
        if (!identity->user_id)
        {
            return PEP_OUT_OF_MEMORY;
        }
        snprintf(identity->user_id, identity->address_size + 5,
                 "TOFU_%s", identity->address);

        if(identity->user_id)
        {
            identity->user_id_size = strlen(identity->user_id);
        }
    }
    
    status = get_identity(session,
                          identity->address,
                          identity->user_id,
                          &stored_identity);
    
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;

    if (stored_identity) {
        PEP_comm_type _comm_type_key;
        status = get_key_rating(session, stored_identity->fpr, &_comm_type_key);
        assert(status != PEP_OUT_OF_MEMORY);
        if (status == PEP_OUT_OF_MEMORY)
            return PEP_OUT_OF_MEMORY;

        if (EMPTYSTR(identity->username)) {
            free(identity->username);
            identity->username = strndup(stored_identity->username, stored_identity->username_size);
            assert(identity->username);
            if (identity->username == NULL)
                return PEP_OUT_OF_MEMORY;
            identity->username_size = stored_identity->username_size;
        }

        if (EMPTYSTR(identity->fpr)) {
            identity->fpr = strndup(stored_identity->fpr, stored_identity->fpr_size);
            assert(identity->fpr);
            if (identity->fpr == NULL)
                return PEP_OUT_OF_MEMORY;
            identity->fpr_size = stored_identity->fpr_size;
            if (_comm_type_key < PEP_ct_unconfirmed_encryption) {
                identity->comm_type = _comm_type_key;
            }
            else {
                identity->comm_type = stored_identity->comm_type;
            }
        }
        else /* !EMPTYSTR(identity->fpr) */ {
            if (_same_fpr(identity->fpr,
                          identity->fpr_size,
                          stored_identity->fpr,
                          stored_identity->fpr_size)) {
                if (_comm_type_key < PEP_ct_unconfirmed_encryption) {
                    identity->comm_type = _comm_type_key;
                }else{
                    identity->comm_type = stored_identity->comm_type;
                    if (identity->comm_type == PEP_ct_unknown) {
                        identity->comm_type = _comm_type_key;
                    }
                }
            } else {
                status = get_trust(session, identity);
                assert(status != PEP_OUT_OF_MEMORY);
                if (status == PEP_OUT_OF_MEMORY)
                    return PEP_OUT_OF_MEMORY;
                if (identity->comm_type < stored_identity->comm_type)
                    identity->comm_type = PEP_ct_unknown;
            }
        }

        if (identity->lang[0] == 0) {
            identity->lang[0] = stored_identity->lang[0];
            identity->lang[1] = stored_identity->lang[1];
            identity->lang[2] = 0;
        }
    }
    else /* stored_identity == NULL */ {
        if (!EMPTYSTR(identity->fpr)) {
            PEP_comm_type _comm_type_key;

            status = get_key_rating(session, identity->fpr, &_comm_type_key);
            assert(status != PEP_OUT_OF_MEMORY);
            if (status == PEP_OUT_OF_MEMORY)
                return PEP_OUT_OF_MEMORY;

            identity->comm_type = _comm_type_key;
        }
        else /* EMPTYSTR(identity->fpr) */ {
            PEP_STATUS status;
            stringlist_t *keylist;
            char *_fpr = NULL;
            identity->comm_type = PEP_ct_unknown;

            status = find_keys(session, identity->address, &keylist);
            assert(status != PEP_OUT_OF_MEMORY);
            if (status == PEP_OUT_OF_MEMORY)
                return PEP_OUT_OF_MEMORY;

            stringlist_t *_keylist;
            for (_keylist = keylist; _keylist && _keylist->value; _keylist = _keylist->next) {
                PEP_comm_type _comm_type_key;

                status = get_key_rating(session, _keylist->value, &_comm_type_key);
                assert(status != PEP_OUT_OF_MEMORY);
                if (status == PEP_OUT_OF_MEMORY) {
                    free_stringlist(keylist);
                    return PEP_OUT_OF_MEMORY;
                }

                if (identity->comm_type == PEP_ct_unknown) {
                    if (_comm_type_key != PEP_ct_compromized && _comm_type_key != PEP_ct_unknown) {
                        identity->comm_type = _comm_type_key;
                        _fpr = _keylist->value;
                    }
                }
                else {
                    if (_comm_type_key != PEP_ct_compromized && _comm_type_key != PEP_ct_unknown) {
                        if (_comm_type_key > identity->comm_type) {
                            identity->comm_type = _comm_type_key;
                            _fpr = _keylist->value;
                        }
                    }
                }
            }

            if (_fpr) {
                free(identity->fpr);

                identity->fpr = strdup(_fpr);
                if (identity->fpr == NULL) {
                    free_stringlist(keylist);
                    return PEP_OUT_OF_MEMORY;
                }
                identity->fpr_size = strlen(identity->fpr);
            }
            free_stringlist(keylist);
        }
    }

    status = PEP_STATUS_OK;

    if (identity->comm_type != PEP_ct_unknown && !EMPTYSTR(identity->user_id)) {
        assert(!EMPTYSTR(identity->username)); // this should not happen

        if (EMPTYSTR(identity->username)) { // mitigate
            free(identity->username);
            identity->username = strdup("anonymous");
            if (identity->username == NULL)
                return PEP_OUT_OF_MEMORY;
            identity->username_size = 9;
        }

        // Identity doesn't get stored if is was just about checking existing
        // user by address (i.e. no user id but already stored)
        if (!(_no_user_id && stored_identity))
        {
            status = set_identity(session, identity);
            assert(status == PEP_STATUS_OK);
            if (status != PEP_STATUS_OK) {
                return status;
            }
        }
    }

    if (identity->comm_type != PEP_ct_compromized &&
            identity->comm_type < PEP_ct_strong_but_unconfirmed)
        if (session->examine_identity)
            session->examine_identity(identity, session->examine_management);

    return status;
}

DYNAMIC_API PEP_STATUS myself(PEP_SESSION session, pEp_identity * identity)
{
    pEp_identity *stored_identity;
    PEP_STATUS status;
    stringlist_t *keylist = NULL;

    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->username);
    assert(identity->user_id);

    if (!(session && identity && identity->address && identity->username &&
                identity->user_id))
        return PEP_ILLEGAL_VALUE;

    identity->comm_type = PEP_ct_pEp;
    identity->me = true;

    DEBUG_LOG("myself", "debug", identity->address);

    
    status = get_identity(session,
                          identity->address,
                          identity->user_id,
                          &stored_identity);
    
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;
    
    if (stored_identity)
    {
        if (EMPTYSTR(identity->fpr)) {
            identity->fpr = strndup(stored_identity->fpr, stored_identity->fpr_size);
            assert(identity->fpr);
            if (identity->fpr == NULL)
            {
                return PEP_OUT_OF_MEMORY;
            }
            identity->fpr_size = stored_identity->fpr_size;
        }
    }
    else
    {
        free(identity->fpr);
        identity->fpr_size = 0;
        
        status = find_keys(session, identity->address, &keylist);
        assert(status != PEP_OUT_OF_MEMORY);
        if (status == PEP_OUT_OF_MEMORY)
            return PEP_OUT_OF_MEMORY;
        
        if (keylist != NULL && keylist->value != NULL)
        {
            // BUG : Vulnerable to auto-key-import poisoning.
            //       Attacker's key with forged userId could have been
            //       auto imported from already received email and be used here
            
            // TODO : iterate over list to elect best key
            // TODO : discard keys which aren't private
            // TODO : discard keys which aren't either
            //             - own generated key
            //             - own from synchronized device group
            //             - already fully trusted as a public key of known
            //               identity, for that same address
            //               (case of imported key for mailing lists)
            
            identity->fpr = strdup(keylist->value);
            assert(identity->fpr);
            if (identity->fpr == NULL)
            {
                return PEP_OUT_OF_MEMORY;
            }
            identity->fpr_size = strlen(identity->fpr);
        }
        
    }
    
    // TODO : Check key for revoked state
    
    if (EMPTYSTR(identity->fpr) /* or revoked */)
    {
        
        DEBUG_LOG("generating key pair", "debug", identity->address);
        status = generate_keypair(session, identity);
        assert(status != PEP_OUT_OF_MEMORY);
        if (status != PEP_STATUS_OK) {
            char buf[11];
            snprintf(buf, 11, "%d", status);
            DEBUG_LOG("generating key pair failed", "debug", buf);
            return status;
        }
        
        status = find_keys(session, identity->address, &keylist);
        assert(status != PEP_OUT_OF_MEMORY);
        if (status == PEP_OUT_OF_MEMORY)
            return PEP_OUT_OF_MEMORY;
        
        assert(keylist && keylist->value);
        if (keylist == NULL || keylist->value == NULL) {
            return PEP_UNKNOWN_ERROR;
        }
    }
    else
    {
        bool expired;
        status = key_expired(session, identity->fpr, &expired);
        assert(status == PEP_STATUS_OK);
        if (status != PEP_STATUS_OK) {
            goto free_keylist;
        }

        if (status == PEP_STATUS_OK && expired) {
            timestamp *ts = new_timestamp(time(NULL) + KEY_EXPIRE_DELTA);
            renew_key(session, identity->fpr, ts);
            free_timestamp(ts);
        }
    }

    status = set_identity(session, identity);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK) {
        goto free_keylist;
    }

    return PEP_STATUS_OK;

free_keylist:
    free_stringlist(keylist);
    return status;
}

DYNAMIC_API PEP_STATUS register_examine_function(
        PEP_SESSION session, 
        examine_identity_t examine_identity,
        void *management
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    session->examine_management = management;
    session->examine_identity = examine_identity;

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS do_keymanagement(
        retrieve_next_identity_t retrieve_next_identity,
        void *management
    )
{
    PEP_SESSION session;
    pEp_identity *identity;
    PEP_STATUS status;

    assert(retrieve_next_identity);
    assert(management);

    if (!retrieve_next_identity || !management)
        return PEP_ILLEGAL_VALUE;

    status = init(&session);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        return status;

    log_event(session, "keymanagement thread started", "pEp engine", NULL, NULL);

    while ((identity = retrieve_next_identity(management))) 
    {
        assert(identity->address);
        if(identity->address)
        {
            DEBUG_LOG("do_keymanagement", "retrieve_next_identity", identity->address);

            if (identity->me) {
                status = myself(session, identity);
            } else {
                status = recv_key(session, identity->address);
            }

            assert(status != PEP_OUT_OF_MEMORY);
            if(status == PEP_OUT_OF_MEMORY)
                return PEP_OUT_OF_MEMORY;
        }
        free_identity(identity);
    }

    log_event(session, "keymanagement thread shutdown", "pEp engine", NULL, NULL);

    release(session);
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS key_compromized(
        PEP_SESSION session,
        pEp_identity *ident
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(ident);
    assert(!EMPTYSTR(ident->fpr));

    if (!(session && ident && ident->fpr))
        return PEP_ILLEGAL_VALUE;

    if (ident->me)
        revoke_key(session, ident->fpr, NULL);
    status = mark_as_compromized(session, ident->fpr);

    return status;
}

DYNAMIC_API PEP_STATUS key_reset_trust(
        PEP_SESSION session,
        pEp_identity *ident
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(ident);
    assert(!ident->me);
    assert(!EMPTYSTR(ident->fpr));
    assert(!EMPTYSTR(ident->address));
    assert(!EMPTYSTR(ident->user_id));

    if (!(session && ident && !ident->me && ident->fpr && ident->address &&
            ident->user_id))
        return PEP_ILLEGAL_VALUE;

    status = update_identity(session, ident);
    if (status != PEP_STATUS_OK)
        return status;

    if (ident->comm_type == PEP_ct_mistrusted)
        ident->comm_type = PEP_ct_unknown;
    else
        ident->comm_type &= ~PEP_ct_confirmed;

    status = set_identity(session, ident);
    if (status != PEP_STATUS_OK)
        return status;

    if (ident->comm_type == PEP_ct_unknown)
        status = update_identity(session, ident);
    return status;
}

DYNAMIC_API PEP_STATUS trust_personal_key(
        PEP_SESSION session,
        pEp_identity *ident
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(ident);
    assert(!EMPTYSTR(ident->address));
    assert(!EMPTYSTR(ident->user_id));
    assert(!EMPTYSTR(ident->fpr));
    assert(!ident->me);

    if (!ident || EMPTYSTR(ident->address) || EMPTYSTR(ident->user_id) ||
            EMPTYSTR(ident->fpr) || ident->me)
        return PEP_ILLEGAL_VALUE;

    status = update_identity(session, ident);
    if (status != PEP_STATUS_OK)
        return status;

    if (ident->comm_type > PEP_ct_strong_but_unconfirmed) {
        ident->comm_type |= PEP_ct_confirmed;
        status = set_identity(session, ident);
    }
    else {
        // MISSING: S/MIME has to be handled depending on trusted CAs
        status = PEP_CANNOT_SET_TRUST;
    }

    return status;
}

DYNAMIC_API PEP_STATUS own_key_add(PEP_SESSION session, const char *fpr)
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session && fpr && fpr[0]);
    
    if (!(session && fpr && fpr[0]))
        return PEP_ILLEGAL_VALUE;
    
    sqlite3_reset(session->own_key_add);
    sqlite3_bind_text(session->own_key_add, 1, fpr, -1, SQLITE_STATIC);
    
    int result;
    
    result = sqlite3_step(session->own_key_add);
    switch (result) {
        case SQLITE_DONE:
            status = PEP_STATUS_OK;
            break;
            
        default:
            status = PEP_UNKNOWN_ERROR;
    }
    
    sqlite3_reset(session->own_key_add);
    return status;
}

DYNAMIC_API PEP_STATUS own_key_is_listed(
                                           PEP_SESSION session,
                                           const char *fpr,
                                           bool *listed
                                           )
{
    PEP_STATUS status = PEP_STATUS_OK;
    int count;
    
    assert(session && fpr && fpr[0] && listed);
    
    if (!(session && fpr && fpr[0] && listed))
        return PEP_ILLEGAL_VALUE;
    
    *listed = false;
    
    sqlite3_reset(session->own_key_is_listed);
    sqlite3_bind_text(session->own_key_is_listed, 1, fpr, -1, SQLITE_STATIC);
    
    int result;
    
    result = sqlite3_step(session->own_key_is_listed);
    switch (result) {
        case SQLITE_ROW:
            count = sqlite3_column_int(session->own_key_is_listed, 0);
            *listed = count > 0;
            status = PEP_STATUS_OK;
            break;
            
        default:
            status = PEP_UNKNOWN_ERROR;
    }
    
    sqlite3_reset(session->own_key_is_listed);
    return status;
}

DYNAMIC_API PEP_STATUS own_key_retrieve(
                                          PEP_SESSION session,
                                          stringlist_t **own_key
                                          )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session);
    assert(own_key);
    
    if (!(session && own_key))
        return PEP_ILLEGAL_VALUE;
    
    *own_key = NULL;
    stringlist_t *_own_key = new_stringlist(NULL);
    if (_own_key == NULL)
        goto enomem;
    
    sqlite3_reset(session->own_key_retrieve);
    
    int result;
    const char *fpr = NULL;
    
    stringlist_t *_bl = _own_key;
    do {
        result = sqlite3_step(session->own_key_retrieve);
        switch (result) {
            case SQLITE_ROW:
                fpr = (const char *) sqlite3_column_text(session->own_key_retrieve, 0);
                
                _bl = stringlist_add(_bl, fpr);
                if (_bl == NULL)
                    goto enomem;
                
                break;
                
            case SQLITE_DONE:
                break;
                
            default:
                status = PEP_UNKNOWN_ERROR;
                result = SQLITE_DONE;
        }
    } while (result != SQLITE_DONE);
    
    sqlite3_reset(session->own_key_retrieve);
    if (status == PEP_STATUS_OK)
        *own_key = _own_key;
    else
        free_stringlist(_own_key);
    
    goto the_end;
    
enomem:
    free_stringlist(_own_key);
    status = PEP_OUT_OF_MEMORY;
    
the_end:
    return status;
}
