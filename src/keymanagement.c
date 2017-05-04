// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "platform.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

#include "pEp_internal.h"
#include "keymanagement.h"

#include "sync_fsm.h"
#include "blacklist.h"

#ifndef EMPTYSTR
#define EMPTYSTR(STR) ((STR) == NULL || (STR)[0] == '\0')
#endif

#define KEY_EXPIRE_DELTA (60 * 60 * 24 * 365)

PEP_STATUS elect_pubkey(
        PEP_SESSION session, pEp_identity * identity
    )
{
    PEP_STATUS status;
    stringlist_t *keylist = NULL;
    char *_fpr = "";
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

        if (_comm_type_key != PEP_ct_compromized &&
            _comm_type_key != PEP_ct_unknown)
        {
            if (identity->comm_type == PEP_ct_unknown ||
                _comm_type_key > identity->comm_type)
            {
                bool blacklisted;
                status = blacklist_is_listed(session, _keylist->value, &blacklisted);
                if (status == PEP_STATUS_OK && !blacklisted) {
                    identity->comm_type = _comm_type_key;
                    _fpr = _keylist->value;
                }
            }
        }
    }

    
//    if (_fpr) {
    free(identity->fpr);

    identity->fpr = strdup(_fpr);
    if (identity->fpr == NULL) {
        free_stringlist(keylist);
        return PEP_OUT_OF_MEMORY;
    }
//    }
    free_stringlist(keylist);
    return PEP_STATUS_OK;
}

PEP_STATUS _myself(PEP_SESSION session, pEp_identity * identity, bool do_keygen, bool ignore_flags);

DYNAMIC_API PEP_STATUS update_identity(
        PEP_SESSION session, pEp_identity * identity
    )
{
    pEp_identity *stored_identity = NULL;
    pEp_identity *temp_id = NULL;
    PEP_STATUS status;

    assert(session);
    assert(identity);
    assert(!EMPTYSTR(identity->address));

    if (!(session && identity && !EMPTYSTR(identity->address)))
        return PEP_ILLEGAL_VALUE;

    if (identity->me || (identity->user_id && strcmp(identity->user_id, PEP_OWN_USERID) == 0)) {
        identity->me = true;
        return _myself(session, identity, false, true);
    }

    int _no_user_id = EMPTYSTR(identity->user_id);
    int _did_elect_new_key = 0;

    if (_no_user_id)
    {
        status = get_identity(session, identity->address, PEP_OWN_USERID,
                &stored_identity);
        if (status == PEP_STATUS_OK) {
            free_identity(stored_identity);
            return _myself(session, identity, false, true);
        }

        free(identity->user_id);

        identity->user_id = calloc(1, strlen(identity->address) + 6);
        if (!identity->user_id)
        {
            return PEP_OUT_OF_MEMORY;
        }
        snprintf(identity->user_id, strlen(identity->address) + 6,
                 "TOFU_%s", identity->address);
    }
 
    status = get_identity(session,
                          identity->address,
                          identity->user_id,
                          &stored_identity);
    
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        goto exit_free;

    temp_id = identity_dup(identity);
    
    /* We don't take given fpr. 
       In case there's no acceptable stored fpr, it will be elected. */
    free(temp_id->fpr);
    temp_id->fpr = NULL;
    temp_id->comm_type = PEP_ct_unknown;
            
    if (stored_identity) {
        
        bool dont_use_stored_fpr = true;

        /* if we have a stored_identity fpr */
        if (!EMPTYSTR(stored_identity->fpr)) {
            status = blacklist_is_listed(session, stored_identity->fpr, &dont_use_stored_fpr);
            if (status != PEP_STATUS_OK)
                dont_use_stored_fpr = true; 
        }
            

        if (!dont_use_stored_fpr) {
            /* Check stored comm_type */
            PEP_comm_type _comm_type_key;
            status = get_key_rating(session, stored_identity->fpr, &_comm_type_key);
            assert(status != PEP_OUT_OF_MEMORY);
            if (status == PEP_OUT_OF_MEMORY) {
                goto exit_free;
            }
            if (status == PEP_KEY_NOT_FOUND){
                /* stored key was deleted from keyring. any other candidate ?*/
                status = elect_pubkey(session, temp_id);
                if (status != PEP_STATUS_OK) {
                    goto exit_free;
                } else {
                    _did_elect_new_key = 1;
                }
            } else {
                temp_id->fpr = strdup(stored_identity->fpr);
                assert(temp_id->fpr);
                if (temp_id->fpr == NULL) {
                    status = PEP_OUT_OF_MEMORY;
                    goto exit_free;
                }

                if (_comm_type_key < PEP_ct_unconfirmed_encryption) {
                    /* if key not good anymore, 
                       downgrade eventually trusted comm_type */
                    temp_id->comm_type = _comm_type_key;
                } else {
                    /* otherwise take stored comm_type as-is except if 
                       is unknown or is expired (but key not expired anymore) */
                    temp_id->comm_type = stored_identity->comm_type;
                    if (temp_id->comm_type == PEP_ct_unknown ||
                        temp_id->comm_type == PEP_ct_key_expired) {
                        temp_id->comm_type = _comm_type_key;
                    }
                }
            }
        }
        else {
            status = elect_pubkey(session, temp_id);
            if (status != PEP_STATUS_OK){
                goto exit_free;
            } else {
                _did_elect_new_key = 1;
            }
        }
        
        /* ok, from here on out, use temp_id */
        
        
        /* At this point, we either have a non-blacklisted fpr we can work */
        /* with, or we've got nada.                                        */

        if (EMPTYSTR(temp_id->fpr)) {
            /* nada : set comm_type accordingly */
            temp_id->comm_type = PEP_ct_key_not_found;
        }
        
        if (EMPTYSTR(temp_id->username)) {
            free(temp_id->username);
            temp_id->username = strdup(stored_identity->username);
            assert(temp_id->username);
            if (temp_id->username == NULL){
                status = PEP_OUT_OF_MEMORY;
                goto exit_free;
            }
        }

        if (temp_id->lang[0] == 0) {
            temp_id->lang[0] = stored_identity->lang[0];
            temp_id->lang[1] = stored_identity->lang[1];
            temp_id->lang[2] = 0;
        }

        temp_id->flags = stored_identity->flags;
    }
    else /* stored_identity == NULL */ {
        temp_id->flags = 0;

        /* We elect a pubkey */
        status = elect_pubkey(session, temp_id);
        if (status != PEP_STATUS_OK)
            goto exit_free;
        
        /* Work with the elected key */
        if (!EMPTYSTR(temp_id->fpr)) {
            
            PEP_comm_type _comm_type_key = temp_id->comm_type;
            
            _did_elect_new_key = 1;

            // We don't want to lose a previous trust entry!!!
            status = get_trust(session, temp_id);

            bool has_trust_status = (status == PEP_STATUS_OK);

            if (!has_trust_status)
                temp_id->comm_type = _comm_type_key;
        }
    }

    if (temp_id->fpr == NULL) {
        temp_id->fpr = strdup("");
        if (temp_id->fpr == NULL) {
            status = PEP_OUT_OF_MEMORY;
            goto exit_free;
        }
    }
    
    
    status = PEP_STATUS_OK;

    if (temp_id->comm_type != PEP_ct_unknown && !EMPTYSTR(temp_id->user_id)) {

        if (EMPTYSTR(temp_id->username)) { // mitigate
            free(temp_id->username);
            temp_id->username = strdup("anonymous");
            assert(temp_id->username);
            if (temp_id->username == NULL){
                status = PEP_OUT_OF_MEMORY;
                goto exit_free;
            }
        }

        // Identity doesn't get stored if call was just about checking existing
        // user by address (i.e. no user id given but already stored)
        if (!(_no_user_id && stored_identity) || _did_elect_new_key)
        {
            status = set_identity(session, temp_id);
            assert(status == PEP_STATUS_OK);
            if (status != PEP_STATUS_OK) {
                goto exit_free;
            }
        }
    }

    if (temp_id->comm_type != PEP_ct_compromized &&
            temp_id->comm_type < PEP_ct_strong_but_unconfirmed)
        if (session->examine_identity)
            session->examine_identity(temp_id, session->examine_management);
    
    /* ok, we got to the end. So we can assign the output identity */
    free(identity->address);
    identity->address = strdup(temp_id->address);
    free(identity->fpr);
    identity->fpr = strdup(temp_id->fpr);
    free(identity->user_id);
    identity->user_id = strdup(temp_id->user_id);
    free(identity->username);
    identity->username = strdup(temp_id->username ? temp_id->username : "anonymous");
    identity->comm_type = temp_id->comm_type;
    identity->lang[0] = temp_id->lang[0];
    identity->lang[1] = temp_id->lang[1];
    identity->lang[2] = 0;
    identity->me = temp_id->me;
    identity->flags = temp_id->flags;

exit_free :
    free_identity(stored_identity);
    free_identity(temp_id);
    
    return status;
}

PEP_STATUS elect_ownkey(
        PEP_SESSION session, pEp_identity * identity
    )
{
    PEP_STATUS status;
    stringlist_t *keylist = NULL;

    free(identity->fpr);
    identity->fpr = NULL;

    status = find_private_keys(session, identity->address, &keylist);
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;
    
    if (keylist != NULL && keylist->value != NULL)
    {
        char *_fpr = NULL;
        identity->comm_type = PEP_ct_unknown;

        stringlist_t *_keylist;
        for (_keylist = keylist; _keylist && _keylist->value; _keylist = _keylist->next) {
            bool is_own = false;
            
            if (session->use_only_own_private_keys)
            {
                status = own_key_is_listed(session, _keylist->value, &is_own);
                assert(status == PEP_STATUS_OK);
                if (status != PEP_STATUS_OK) {
                    free_stringlist(keylist);
                    return status;
                }
            }

            // TODO : also accept synchronized device group keys ?
            
            if (!session->use_only_own_private_keys || is_own)
            {
                PEP_comm_type _comm_type_key;
                
                status = get_key_rating(session, _keylist->value, &_comm_type_key);
                assert(status != PEP_OUT_OF_MEMORY);
                if (status == PEP_OUT_OF_MEMORY) {
                    free_stringlist(keylist);
                    return PEP_OUT_OF_MEMORY;
                }
                
                if (_comm_type_key != PEP_ct_compromized &&
                    _comm_type_key != PEP_ct_unknown)
                {
                    if (identity->comm_type == PEP_ct_unknown ||
                        _comm_type_key > identity->comm_type)
                    {
                        identity->comm_type = _comm_type_key;
                        _fpr = _keylist->value;
                    }
                }
            }
        }
        
        if (_fpr)
        {
            identity->fpr = strdup(_fpr);
            assert(identity->fpr);
            if (identity->fpr == NULL)
            {
                free_stringlist(keylist);
                return PEP_OUT_OF_MEMORY;
            }
        }
        free_stringlist(keylist);
    }
    return PEP_STATUS_OK;
}

PEP_STATUS _has_usable_priv_key(PEP_SESSION session, char* fpr,
                                bool* is_usable) {
    
    bool dont_use_fpr = true;
    
    PEP_STATUS status = blacklist_is_listed(session, fpr, &dont_use_fpr);
    if (status == PEP_STATUS_OK && !dont_use_fpr) {
        // Make sure there is a *private* key associated with this fpr
        bool has_private = false;
        status = contains_priv_key(session, fpr, &has_private);

        if (status == PEP_STATUS_OK)
            dont_use_fpr = !has_private;
    }
    
    *is_usable = !dont_use_fpr;
    
    return status;
}

PEP_STATUS _myself(PEP_SESSION session, pEp_identity * identity, bool do_keygen, bool ignore_flags)
{
    pEp_identity *stored_identity = NULL;
    PEP_STATUS status;

    assert(session);
    assert(identity);
    assert(!EMPTYSTR(identity->address));

    assert(EMPTYSTR(identity->user_id) ||
           strcmp(identity->user_id, PEP_OWN_USERID) == 0);

    if (!(session && identity && !EMPTYSTR(identity->address) &&
            (EMPTYSTR(identity->user_id) ||
            strcmp(identity->user_id, PEP_OWN_USERID) == 0)))
        return PEP_ILLEGAL_VALUE;

    identity->comm_type = PEP_ct_pEp;
    identity->me = true;
    if(ignore_flags)
        identity->flags = 0;
    else {
        // test_diphoton : dirty hack to prevent more than one sync enabled account
        identity_list *own_identities = NULL;
        if (_own_identities_retrieve(session, &own_identities, PEP_idf_not_for_sync) == PEP_STATUS_OK)
            // if at least one _other_ own address is sync enabled, set exclusion flag
            for (identity_list *_i = own_identities; _i && _i->ident; _i = _i->next) {
                pEp_identity *me = _i->ident;
                if(me->address && strcmp(me->address, identity->address) != 0)
                identity->flags |= PEP_idf_not_for_sync;
                break;
            }
        free_identity_list(own_identities);
    }
    
    if (EMPTYSTR(identity->user_id))
    {
        free(identity->user_id);
        identity->user_id = strdup(PEP_OWN_USERID);
        assert(identity->user_id);
        if (identity->user_id == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    if (EMPTYSTR(identity->username))
    {
        free(identity->username);
        identity->username = strdup("anonymous");
        assert(identity->username);
        if (identity->username == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    DEBUG_LOG("myself", "debug", identity->address);
 
    status = get_identity(session,
                          identity->address,
                          identity->user_id,
                          &stored_identity);
    
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;

    bool dont_use_stored_fpr = true;
    bool dont_use_input_fpr = true;
        
    if (stored_identity)
    {
        if (EMPTYSTR(identity->fpr)) {
            
            bool has_private = false;
            
            status = _has_usable_priv_key(session, stored_identity->fpr, &has_private); 
            
            // N.B. has_private is never true if the returned status is not PEP_STATUS_OK
            if (has_private) {
                identity->fpr = strdup(stored_identity->fpr);
                assert(identity->fpr);
                if (identity->fpr == NULL)
                {
                    return PEP_OUT_OF_MEMORY;
                }
                dont_use_stored_fpr = false;
            }
        }
        
        identity->flags = (identity->flags & 255) | stored_identity->flags;
        free_identity(stored_identity);
    }
    
    if (dont_use_stored_fpr && !EMPTYSTR(identity->fpr))
    {
        // App must have a good reason to give fpr, such as explicit
        // import of private key, or similar.

        // Take given fpr as-is.

        // BUT:
        // First check to see if it's blacklisted or private part is missing?
        bool has_private = false;
        
        status = _has_usable_priv_key(session, identity->fpr, &has_private); 
        
        // N.B. has_private is never true if the returned status is not PEP_STATUS_OK
        if (has_private) {
            dont_use_input_fpr = false;
        }
    }
    
    // Ok, we failed to get keys either way, so let's elect one.
    if (dont_use_input_fpr && dont_use_stored_fpr)
    {
        status = elect_ownkey(session, identity);
        assert(status == PEP_STATUS_OK);
        if (status != PEP_STATUS_OK) {
            return status;
        }

        bool has_private = false;
        if (identity->fpr) {
            // ok, we elected something.
            // elect_ownkey only returns private keys, so we don't check again.
            // Check to see if it's blacklisted
            bool listed;
            status = blacklist_is_listed(session, identity->fpr, &listed); 

            if (status == PEP_STATUS_OK)
                has_private = !listed;
        }
        
        if (has_private) {
            dont_use_input_fpr = false;
        }
        else { // OK, we've tried everything. Time to generate new keys.
            free(identity->fpr); // It can stay in this state (unallocated) because we'll generate a new key 
            identity->fpr = NULL;
        }
    }

    bool revoked = false;
    char *r_fpr = NULL;
    if (!EMPTYSTR(identity->fpr))
    {
        status = key_revoked(session, identity->fpr, &revoked);

        // Forces re-election if key is missing and own-key-only not forced
        if (!session->use_only_own_private_keys && status == PEP_KEY_NOT_FOUND) 
        {
            status = elect_ownkey(session, identity);
            assert(status == PEP_STATUS_OK);
            if (status != PEP_STATUS_OK) {
                return status;
            }
        } 
        else if (status != PEP_STATUS_OK) 
        {
            return status;
        }
    }
   
    bool new_key_generated = false;

    if (EMPTYSTR(identity->fpr) || revoked)
    {        
        if(!do_keygen){
            return PEP_GET_KEY_FAILED;
        }

        if(revoked)
        {
            r_fpr = identity->fpr;
            identity->fpr = NULL;
        }
        
        DEBUG_LOG("generating key pair", "debug", identity->address);
        status = generate_keypair(session, identity);
        assert(status != PEP_OUT_OF_MEMORY);
        if (status != PEP_STATUS_OK) {
            char buf[11];
            snprintf(buf, 11, "%d", status);
            DEBUG_LOG("generating key pair failed", "debug", buf);
            if(revoked && r_fpr)
                free(r_fpr);
            return status;
        }

        new_key_generated = true;
        
        if(revoked)
        {
            status = set_revoked(session, r_fpr,
                                 identity->fpr, time(NULL));
            free(r_fpr);
            if (status != PEP_STATUS_OK) {
                return status;
            }
        }
    }
    else
    {
        bool expired;
        status = key_expired(session, identity->fpr, 
                             time(NULL) + (7*24*3600), // In a week
                             &expired);

        assert(status == PEP_STATUS_OK);
        if (status != PEP_STATUS_OK) {
            return status;
        }

        if (status == PEP_STATUS_OK && expired) {
            timestamp *ts = new_timestamp(time(NULL) + KEY_EXPIRE_DELTA);
            renew_key(session, identity->fpr, ts);
            free_timestamp(ts);
        }
    }

    if (!identity->username)
        identity->username = strdup("");
    
    status = set_identity(session, identity);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK) {
        return status;
    }

    if(new_key_generated)
    {
        // if a state machine for keysync is in place, inject notify
        status = inject_DeviceState_event(session, KeyGen, NULL, NULL);
        if (status == PEP_OUT_OF_MEMORY){
            return PEP_OUT_OF_MEMORY;
        }
    }

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS myself(PEP_SESSION session, pEp_identity * identity)
{
    return _myself(session, identity, true, false);
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

DYNAMIC_API PEP_STATUS key_mistrusted(
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
    {
        revoke_key(session, ident->fpr, NULL);
        myself(session, ident);
    }
    else
    {
        status = mark_as_compromized(session, ident->fpr);
    }

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
//    assert(!ident->me);

    if (!ident || EMPTYSTR(ident->address) || EMPTYSTR(ident->user_id) ||
            EMPTYSTR(ident->fpr)) // || ident->me)
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

PEP_STATUS _own_identities_retrieve(
        PEP_SESSION session,
        identity_list **own_identities,
        identity_flags_t excluded_flags
      )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session && own_identities);
    if (!(session && own_identities))
        return PEP_ILLEGAL_VALUE;
    
    *own_identities = NULL;
    identity_list *_own_identities = new_identity_list(NULL);
    if (_own_identities == NULL)
        goto enomem;
    
    sqlite3_reset(session->own_identities_retrieve);
    
    int result;
    // address, fpr, username, user_id, comm_type, lang, flags
    const char *address = NULL;
    const char *fpr = NULL;
    const char *username = NULL;
    const char *user_id = NULL;
    PEP_comm_type comm_type = PEP_ct_unknown;
    const char *lang = NULL;
    unsigned int flags = 0;
    
    identity_list *_bl = _own_identities;
    do {
        sqlite3_bind_int(session->own_identities_retrieve, 1, excluded_flags);
        result = sqlite3_step(session->own_identities_retrieve);
        switch (result) {
            case SQLITE_ROW:
                address = (const char *)
                    sqlite3_column_text(session->own_identities_retrieve, 0);
                fpr = (const char *)
                    sqlite3_column_text(session->own_identities_retrieve, 1);
                user_id = PEP_OWN_USERID;
                username = (const char *)
                    sqlite3_column_text(session->own_identities_retrieve, 2);
                comm_type = PEP_ct_pEp;
                lang = (const char *)
                    sqlite3_column_text(session->own_identities_retrieve, 3);
                flags = (unsigned int)
                    sqlite3_column_int(session->own_identities_retrieve, 4);

                pEp_identity *ident = new_identity(address, fpr, user_id, username);
                if (!ident)
                    goto enomem;
                ident->comm_type = comm_type;
                if (lang && lang[0]) {
                    ident->lang[0] = lang[0];
                    ident->lang[1] = lang[1];
                    ident->lang[2] = 0;
                }
                ident->me = true;
                ident->flags = flags;

                _bl = identity_list_add(_bl, ident);
                if (_bl == NULL) {
                    free_identity(ident);
                    goto enomem;
                }
                
                break;
                
            case SQLITE_DONE:
                break;
                
            default:
                status = PEP_UNKNOWN_ERROR;
                result = SQLITE_DONE;
        }
    } while (result != SQLITE_DONE);
    
    sqlite3_reset(session->own_identities_retrieve);
    if (status == PEP_STATUS_OK)
        *own_identities = _own_identities;
    else
        free_identity_list(_own_identities);
    
    goto the_end;
    
enomem:
    free_identity_list(_own_identities);
    status = PEP_OUT_OF_MEMORY;
    
the_end:
    return status;
}

DYNAMIC_API PEP_STATUS own_identities_retrieve(
        PEP_SESSION session,
        identity_list **own_identities
      )
{
    return _own_identities_retrieve(session, own_identities, 0);
}

PEP_STATUS _own_keys_retrieve(
        PEP_SESSION session,
        stringlist_t **keylist,
        identity_flags_t excluded_flags
      )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session && keylist);
    if (!(session && keylist))
        return PEP_ILLEGAL_VALUE;
    
    *keylist = NULL;
    stringlist_t *_keylist = NULL;
    
    sqlite3_reset(session->own_keys_retrieve);
    
    int result;
    char *fpr = NULL;
    
    stringlist_t *_bl = _keylist;
    do {
        sqlite3_bind_int(session->own_keys_retrieve, 1, excluded_flags);
        result = sqlite3_step(session->own_keys_retrieve);
        switch (result) {
            case SQLITE_ROW:
                fpr = strdup((const char *) sqlite3_column_text(session->own_keys_retrieve, 0));
                if(fpr == NULL)
                    goto enomem;

                _bl = stringlist_add(_bl, fpr);
                if (_bl == NULL) {
                    free(fpr);
                    goto enomem;
                }
                if (_keylist == NULL)
                    _keylist = _bl;
                
                break;
                
            case SQLITE_DONE:
                break;
                
            default:
                status = PEP_UNKNOWN_ERROR;
                result = SQLITE_DONE;
        }
    } while (result != SQLITE_DONE);
    
    sqlite3_reset(session->own_keys_retrieve);
    if (status == PEP_STATUS_OK)
        *keylist = _keylist;
    else
        free_stringlist(_keylist);
    
    goto the_end;
    
enomem:
    free_stringlist(_keylist);
    status = PEP_OUT_OF_MEMORY;
    
the_end:
    return status;
}

DYNAMIC_API PEP_STATUS own_keys_retrieve(PEP_SESSION session, stringlist_t **keylist)
{
    return _own_keys_retrieve(session, keylist, 0);
}

// TODO: Unused for now, but should be used when sync receive old keys (ENGINE-145)
DYNAMIC_API PEP_STATUS set_own_key(
       PEP_SESSION session,
       const char *address,
       const char *fpr
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session &&
           address && address[0] &&
           fpr && fpr[0]
          );
    
    if (!(session &&
          address && address[0] &&
          fpr && fpr[0]
         ))
        return PEP_ILLEGAL_VALUE;
    
    sqlite3_reset(session->set_own_key);
    sqlite3_bind_text(session->set_own_key, 1, address, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->set_own_key, 2, fpr, -1, SQLITE_STATIC);

    int result;
    
    result = sqlite3_step(session->set_own_key);
    switch (result) {
        case SQLITE_DONE:
            status = PEP_STATUS_OK;
            break;
            
        default:
            status = PEP_UNKNOWN_ERROR;
    }
    
    sqlite3_reset(session->set_own_key);
    return status;
}

PEP_STATUS contains_priv_key(PEP_SESSION session, const char *fpr,
                             bool *has_private) {

    assert(session);
    assert(fpr);
    assert(has_private);
    
    if (!(session && fpr && has_private))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].contains_priv_key(session, fpr, has_private);
}
