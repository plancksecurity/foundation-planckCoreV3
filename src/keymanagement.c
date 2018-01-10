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


static bool key_matches_address(PEP_SESSION session, const char* address,
                                const char* fpr) {
    if (!session || !address || !fpr)
        return false;
    
    bool retval = false;
    stringlist_t *keylist = NULL;
    PEP_STATUS status = find_keys(session, address, &keylist);
    if (status == PEP_STATUS_OK && keylist) {
        stringlist_t* curr = keylist;
        while (curr) {
            if (curr->value) {
                if (strcasecmp(curr->value, fpr)) {
                    retval = true;
                    break;
                }
            }
            curr = curr->next;
        }
    }
    
    free_stringlist(keylist);
    return retval;                             
}

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

static PEP_STATUS validate_fpr(PEP_SESSION session, 
                               pEp_identity* ident) {
    
    if (!session || !ident || !ident->fpr)
        return PEP_ILLEGAL_VALUE;    
        
    char* fpr = ident->fpr;
    
    PEP_STATUS status = get_trust(session, ident);
    if (status != PEP_STATUS_OK)
        return ADD_TO_LOG(status);
    
    PEP_comm_type ct = ident->comm_type;

    if (ct == PEP_ct_unknown) {
        // If status is bad, it's ok, we get the rating
        // we should use then (PEP_ct_unknown)
        get_key_rating(session, fpr, &ct);
    }
    
    bool revoked, expired;
    bool blacklisted = false;
    
    status = key_revoked(session, fpr, &revoked);    
        
    if (status != PEP_STATUS_OK) {
        return ADD_TO_LOG(status);
    }
    
    if (!revoked) {
        status = key_expired(session, fpr, 
                             time(NULL), // NOW. For _myself, this is different.
                             &expired);
    
        assert(status == PEP_STATUS_OK);
        if (status != PEP_STATUS_OK)
            return ADD_TO_LOG(status);

        if ((ct | PEP_ct_confirmed) == PEP_ct_OpenPGP) {
            status = blacklist_is_listed(session, 
                                         fpr, 
                                         &blacklisted);
                                         
            if (status != PEP_STATUS_OK)
                return ADD_TO_LOG(status);
        }
    }
            
    if (ident->me && (ct == PEP_ct_pEp) && !revoked && expired) {
        // extend key
        timestamp *ts = new_timestamp(time(NULL) + KEY_EXPIRE_DELTA);
        status = renew_key(session, fpr, ts);
        free_timestamp(ts);

        if (status == PEP_STATUS_OK) {
            // if key is valid (second check because pEp key might be extended above)
            //      Return fpr        
            status = key_expired(session, fpr, time(NULL), &expired);            
            if (status != PEP_STATUS_OK)
                 return ADD_TO_LOG(status);
            // communicate key(?)
        }        
    }
    
    if (revoked)
        ct = PEP_ct_key_revoked;
    else if (expired)
        ct = PEP_ct_key_expired;        
    else if (blacklisted) {
        ident->comm_type = ct = PEP_ct_key_not_found;
        free(ident->fpr);
            ident->fpr = strdup("");
        status = PEP_KEY_UNSUITABLE;
    }
    
    switch (ct) {
        case PEP_ct_key_expired:
        case PEP_ct_key_revoked:
        case PEP_ct_key_b0rken:
            // delete key from being default key for all users/identities
            status = remove_fpr_as_default(session, fpr);
            status = update_trust_for_fpr(session, 
                                          fpr, 
                                          ct);
            free(ident->fpr);
            ident->fpr = strdup("");
            ident->comm_type = PEP_ct_key_not_found;            
            status = PEP_KEY_UNSUITABLE;
        default:
            break;
    }            

    return status;
}

// Only call on retrieval of previously stored identity!
// Also, we presume that if the stored_identity was sent in
// without an fpr, there wasn't one in the trust DB for this
// identity.
PEP_STATUS get_valid_pubkey(PEP_SESSION session,
                            pEp_identity* stored_identity,
                            bool* is_identity_default,
                            bool* is_user_default,
                            bool* is_address_default) {
    
    PEP_STATUS status = PEP_STATUS_OK;

    if (!stored_identity || !stored_identity->user_id
        || !is_identity_default || !is_user_default || !is_address_default)
        return PEP_ILLEGAL_VALUE;
        
    *is_identity_default = *is_user_default = *is_address_default = false;
    
    char* stored_fpr = stored_identity->fpr;
    // Input: stored identity retrieved from database
    // if stored identity contains a default key
    if (stored_fpr) {
        status = validate_fpr(session, stored_identity);    
        if (status == PEP_STATUS_OK && stored_identity->fpr) {
            *is_identity_default = *is_address_default = true;
            return status;
        }
    }
    // if no valid default stored identity key found
    free(stored_identity->fpr);
    stored_identity->fpr = NULL;
    
    // try to get default key for user_data
    sqlite3_reset(session->get_user_default_key);
    sqlite3_bind_text(session->get_user_default_key, 1, stored_identity->user_id, 
                      -1, SQLITE_STATIC);
    
    const int result = sqlite3_step(session->get_user_default_key);
    char* user_fpr = NULL;
    if (result == SQLITE_ROW) {
        const char* u_fpr =
            (char *) sqlite3_column_text(session->get_user_default_key, 0);
        if (u_fpr)
            user_fpr = strdup(u_fpr);
    }
    sqlite3_reset(session->get_user_default_key);
    
    if (user_fpr) {             
        // There exists a default key for user, so validate
        stored_identity->fpr = user_fpr;
        status = validate_fpr(session, stored_identity);
        if (status == PEP_STATUS_OK && stored_identity->fpr) {
            *is_user_default = true;
            *is_address_default = key_matches_address(session, 
                                                      stored_identity->address,
                                                      stored_identity->fpr);
            return status;
        }        
    }
    
    status = elect_pubkey(session, stored_identity);
    if (status == PEP_STATUS_OK)
        validate_fpr(session, stored_identity);    
    
    switch (stored_identity->comm_type) {
        case PEP_ct_key_revoked:
        case PEP_ct_key_b0rken:
        case PEP_ct_key_expired:
        case PEP_ct_compromized:
        case PEP_ct_mistrusted:
            // this only happens when it's all there is
            status = PEP_KEY_NOT_FOUND;
            free(stored_identity->fpr);
            stored_identity->fpr = NULL;
            stored_identity->comm_type = PEP_ct_unknown;
            break;
        default:
            // FIXME: blacklisting?
            break;
    }
    return status;
}

PEP_STATUS _myself(PEP_SESSION session, pEp_identity * identity, bool do_keygen, bool ignore_flags);

static void transfer_ident_lang_and_flags(pEp_identity* new_ident,
                                          pEp_identity* stored_ident) {
    if (new_ident->lang[0] == 0) {
      new_ident->lang[0] = stored_ident->lang[0];
      new_ident->lang[1] = stored_ident->lang[1];
      new_ident->lang[2] = 0;
    }

    new_ident->flags = stored_ident->flags;
    new_ident->me = new_ident->me || stored_ident->me;
}

static PEP_STATUS prepare_updated_identity(PEP_SESSION session,
                                                 pEp_identity* return_id,
                                                 pEp_identity* stored_ident,
                                                 bool store) {
    
    if (!session || !return_id || !stored_ident)
        return PEP_ILLEGAL_VALUE;
    
    PEP_STATUS status;
    
    bool is_identity_default, is_user_default, is_address_default;
    status = get_valid_pubkey(session, stored_ident,
                                &is_identity_default,
                                &is_user_default,
                                &is_address_default);
                                
    if (status == PEP_STATUS_OK && stored_ident->fpr && *(stored_ident->fpr) != '\0') {
    // set identity comm_type from trust db (user_id, FPR)
        status = get_trust(session, stored_ident);
        if (status == PEP_CANNOT_FIND_IDENTITY) {
            // This is OK - there is no trust DB entry, but we
            // found a key. We won't store this, but we'll
            // use it.
            PEP_comm_type ct = PEP_ct_unknown;
            status = get_key_rating(session, stored_ident->fpr, &ct);
            stored_ident->comm_type = ct;
        }
        if (status != PEP_STATUS_OK) {
            return status; // FIXME - free mem
        }
        free (return_id->fpr);
        return_id->fpr = strdup(stored_ident->fpr);
        return_id->comm_type = stored_ident->comm_type;            
    }
    else {
        free(return_id->fpr);
        return_id->fpr = NULL;
        return_id->comm_type = PEP_ct_key_not_found;
        return status; // Couldn't find a key.
    }
                
    // We patch the DB with the input username, but if we didn't have
    // one, we pull it out of storage if available.
    // (also, if the input username is "anonymous" and there exists
    //  a DB username, we replace)
    if (stored_ident->username) {
        if (return_id->username && 
            (strcasecmp(return_id->username, "anonymous") == 0)) {
            free(return_id->username);
            return_id->username = NULL;
        }
        if (!return_id->username)
            return_id->username = strdup(stored_ident->username);
    }
        
    // Call set_identity() to store
    if ((is_identity_default || is_user_default) &&
         is_address_default) {                 
         // if we got an fpr which is default for either user
         // or identity AND is valid for this address, set in DB
         // as default
         status = set_identity(session, return_id);
    }
    else {
        // Store without default fpr/ct, but return the fpr and ct 
        // for current use
        char* save_fpr = return_id->fpr;
        PEP_comm_type save_ct = return_id->comm_type;
        return_id->fpr = NULL;
        return_id->comm_type = PEP_ct_unknown;
        status = set_identity(session, return_id);
        return_id->fpr = save_fpr;
        return_id->comm_type = save_ct;
    }
    
    transfer_ident_lang_and_flags(return_id, stored_ident);
    
    return status;
}


DYNAMIC_API PEP_STATUS update_identity(
        PEP_SESSION session, pEp_identity * identity
    )
{
    PEP_STATUS status;

    assert(session);
    assert(identity);
    assert(!EMPTYSTR(identity->address));

    if (!(session && identity && !EMPTYSTR(identity->address)))
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);

    char* own_id = NULL;
    status = get_own_userid(session, &own_id);    

    // Is this me, temporary or not? If so, _myself() is the right call.
    if (identity->me || 
       (own_id && identity->user_id && (strcmp(own_id, identity->user_id) == 0))) 
    {
        status = _myself(session, identity, false, true);
        free(own_id);
        return status;
    }

    // We have, at least, an address.
    // Retrieve stored identity information!    
    pEp_identity* stored_ident = NULL;

    if (identity->user_id) {            
        // (we're gonna update the trust/fpr anyway, so we user the no-fpr-from-trust-db variant)
        //      * do get_identity() to retrieve stored identity information
        status = get_identity_without_trust_check(session, identity->address, identity->user_id, &stored_ident);

        // Before we start - if there was no stored identity, we should check to make sure we don't
        // have a stored identity with a temporary user_id that differs from the input user_id. This
        // happens in multithreaded environments sometimes.
        if (!stored_ident) {
            identity_list* id_list = NULL;
            status = get_identities_by_address(session, identity->address, &id_list);

            if (id_list) {
                identity_list* id_curr = id_list;
                while (id_curr) {
                    pEp_identity* this_id = id_curr->ident;
                    if (this_id) {
                        char* this_uid = this_id->user_id;
                        if (this_uid && (strstr(this_uid, "TOFU_") == this_uid)) {
                            // FIXME: should we also be fixing pEp_own_userId in this
                            // function here?
                            
                            // if usernames match, we replace the userid. Or if the temp username
                            // is anonymous.
                            if (!this_id->username ||
                                strcasecmp(this_id->username, "anonymous") == 0 ||
                                (identity->username && 
                                 strcasecmp(identity->username, 
                                            this_id->username) == 0)) {
                                
                                // Ok, we have a temp ID. We have to replace this
                                // with the real ID.
                                status = replace_userid(session, 
                                                        this_uid, 
                                                        identity->user_id);
                                if (status != PEP_STATUS_OK) {
                                    free_identity_list(id_list);
                                    return status;
                                }
                                    
                                free(this_uid);
                                
                                // Reflect the change we just made to the DB
                                this_id->user_id = strdup(identity->user_id);
                                stored_ident = this_id;
                                // FIXME: free list.
                                break;                                
                            }                            
                        } 
                    }
                    id_curr = id_curr->next;
                }
            }
        } 
                
        if (status == PEP_STATUS_OK && stored_ident) { 
            //  * if identity available
            //      * patch it with username
            //          (note: this will happen when 
            //           setting automatically below...)
            //      * elect valid key for identity
            //    * if valid key exists
            //        * set return value's fpr
            status = prepare_updated_identity(session,
                                              identity,
                                              stored_ident, true);
        }
        //  * else (identity unavailable)
        else {
            status = PEP_STATUS_OK;
            
            //  if we only have user_id and address and identity not available
            //      * return error status (identity not found)
            if (!(identity->username))
                status = PEP_CANNOT_FIND_IDENTITY;
            
            // Otherwise, if we had user_id, address, and username:
            //    * create identity with user_id, address, username
            //      (this is the input id without the fpr + comm type!)
            free(identity->fpr);
            identity->fpr = NULL;
            identity->comm_type = PEP_ct_unknown;
            
            //    * We've already checked and retrieved
            //      any applicable temporary identities above. If we're 
            //      here, none of them fit.
            //    * call set_identity() to store
            if (status == PEP_STATUS_OK) {
                status = set_identity(session, identity);
                if (status == PEP_STATUS_OK) {
                    elect_pubkey(session, identity);
                }
            }
            //  * Return: created identity
        }        
    }
    else if (identity->username) {
        /*
         * Temporary identity information with username supplied
            * Input: address, username (no others)
         */
        identity_list* id_list = NULL;
        status = get_identities_by_address(session, identity->address, &id_list);

        //  * Search for an identity with non-temporary user_id with that mapping
        if (id_list) {
            identity_list* id_curr = id_list;
            while (id_curr) {
                pEp_identity* this_id = id_curr->ident;
                if (this_id) {
                    char* this_uid = this_id->user_id;
                    if (this_uid && (strstr(this_uid, "TOFU_") != this_uid)) {
                        // FIXME: should we also be fixing pEp_own_userId in this
                        // function here?
                        
                        // if usernames match, we replace the userid.
                        if (identity->username && 
                            strcasecmp(identity->username, 
                                       this_id->username) == 0) {
                            
                            // Ok, we have a real ID. Copy it!
                            identity->user_id = strdup(this_uid);
                            
                            if (!identity->user_id)
                                status = PEP_OUT_OF_MEMORY;
                            stored_ident = this_id;
                            
                            break;                                
                        }                            
                    } 
                }
                id_curr = id_curr->next;
            }
        }

        if (stored_ident) {
            status = prepare_updated_identity(session,
                                              identity,
                                              stored_ident, true);
        }
        else {
            // create temporary identity, store it, and Return this
            // This means TOFU_ user_id
            identity->user_id = calloc(1, strlen(identity->address) + 6);
            if (!identity->user_id)
                return PEP_OUT_OF_MEMORY;

            snprintf(identity->user_id, strlen(identity->address) + 6,
                     "TOFU_%s", identity->address);        
            
            free(identity->fpr);
            identity->fpr = NULL;
            identity->comm_type = PEP_ct_unknown;
             
            //    * We've already checked and retrieved
            //      any applicable temporary identities above. If we're 
            //      here, none of them fit.
            //    * call set_identity() to store
            status = set_identity(session, identity);
            if (status == PEP_STATUS_OK) {
                elect_pubkey(session, identity);
            }
        }
    }
    else {
        /*
         * Temporary identity information without username suplied
            * Input: address (no others)
         */
        identity_list* id_list = NULL;
        status = get_identities_by_address(session, identity->address, &id_list);

        //    * Search for identity with this address
        if (id_list && !(id_list->next)) { // exactly one            
            //    * If exactly one found
            //      * elect valid key for identity (see below)
            //      * Return this identity
            stored_ident = id_list->ident;
            
            if (stored_ident)
                status = prepare_updated_identity(session, identity,
                                                  stored_ident, false);
            else
                status = PEP_CANNOT_FIND_IDENTITY;
        }
        else // too little info
            status = PEP_CANNOT_FIND_IDENTITY; 
    }
    
    // FIXME: This is legacy. I presume it's a notification for the caller...
    // Revisit once I can talk to Volker
    if (identity->comm_type != PEP_ct_compromized &&
        identity->comm_type < PEP_ct_strong_but_unconfirmed)
    if (session->examine_identity)
        session->examine_identity(identity, session->examine_management);

    return ADD_TO_LOG(status);
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
            
            status = own_key_is_listed(session, _keylist->value, &is_own);
            assert(status == PEP_STATUS_OK);
            if (status != PEP_STATUS_OK) {
                free_stringlist(keylist);
                return status;
            }
            
            if (is_own)
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
    
    return ADD_TO_LOG(status);
}

PEP_STATUS _myself(PEP_SESSION session, pEp_identity * identity, bool do_keygen, bool ignore_flags)
{
    pEp_identity *stored_identity = NULL;
    PEP_STATUS status;

    assert(session);
    assert(identity);
    assert(!EMPTYSTR(identity->address));

    char* own_id = NULL;
    status = get_own_userid(session, &own_id);


    assert(EMPTYSTR(identity->user_id) ||
           (own_id && strcmp(identity->user_id, own_id) == 0) ||
           !own_id);

    if (!(session && identity && !EMPTYSTR(identity->address) &&
            (EMPTYSTR(identity->user_id) ||
            (own_id && strcmp(identity->user_id, own_id) == 0) ||
             !own_id)))
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);

    // IF WE DON'T HAVE AN OWN_ID, WE IGNORE REFERENCES TO THIS ADDRESS IN THE
    // DB, AS IT IS NOT AN OWN_IDENTITY AND HAS NO INFORMATION WE NEED OR WHAT TO
    // SET FOR MYSELF
    identity->comm_type = PEP_ct_pEp;
    identity->me = true;
    if(ignore_flags)
        identity->flags = 0;
    
    if (EMPTYSTR(identity->user_id))
    {
        free(identity->user_id);
        identity->user_id = (own_id ? own_id : strdup(PEP_OWN_USERID));
        assert(identity->user_id);
        if (identity->user_id == NULL)
            return PEP_OUT_OF_MEMORY;
    }
    else if (own_id) {
        if (strcmp(identity->user_id, own_id) != 0) {
            if (strcmp(own_id, PEP_OWN_USERID) == 0) {
                // replace own_id in DB
                status = replace_userid(session, PEP_OWN_USERID,
                                        identity->user_id);
                if (status != PEP_STATUS_OK)
                    return status;
            }
            else {
                return PEP_CANNOT_SET_IDENTITY; // FIXME: Better error
            }
        }
    }

    if (EMPTYSTR(identity->username))
    {
        free(identity->username);
        identity->username = strdup("Anonymous");
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
            return ADD_TO_LOG(status);
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

        if (status != PEP_STATUS_OK) 
        {
            return ADD_TO_LOG(status);
        }
    }
   
    if (EMPTYSTR(identity->fpr) || revoked)
    {
        if(!do_keygen){
            return ADD_TO_LOG(PEP_GET_KEY_FAILED);
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
            return ADD_TO_LOG(status);
        }

        
        if(revoked)
        {
            status = set_revoked(session, r_fpr,
                                 identity->fpr, time(NULL));
            free(r_fpr);
            if (status != PEP_STATUS_OK) {
                return ADD_TO_LOG(status);
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
            return ADD_TO_LOG(status);
        }

        if (status == PEP_STATUS_OK && expired) {
            timestamp *ts = new_timestamp(time(NULL) + KEY_EXPIRE_DELTA);
            renew_key(session, identity->fpr, ts);
            free_timestamp(ts);
        }
    }

    if (!(identity->username))
        identity->username = strdup("");
    
    status = set_identity(session, identity);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK) {
        return status;
    }

    return ADD_TO_LOG(PEP_STATUS_OK);
}

DYNAMIC_API PEP_STATUS initialise_own_identities(PEP_SESSION session,
                                                 identity_list* my_idents) {
    PEP_STATUS status = PEP_STATUS_OK;
    if (!session)
        return PEP_ILLEGAL_VALUE;
        
    char* stored_own_userid = NULL;
    get_own_userid(session, &stored_own_userid);
    
    identity_list* ident_curr = my_idents;
    while (ident_curr) {
        pEp_identity* ident = ident_curr->ident;
        if (!ident)
            return PEP_ILLEGAL_VALUE;
            
        if (stored_own_userid) {
            if (!ident->user_id) 
                ident->user_id = strdup(stored_own_userid);
            else if (strcmp(stored_own_userid, ident->user_id) != 0)
                return PEP_ILLEGAL_VALUE;
        }
        else if (!ident->user_id) {
            stored_own_userid = PEP_OWN_USERID;
            ident->user_id = strdup(PEP_OWN_USERID);
        }
        
        ident->me = true; // Just in case.
        
        // Ok, do it...
        status = set_identity(session, ident);
        if (status != PEP_STATUS_OK)
            return status;
        
        ident_curr = ident_curr->next;
    }
    
    return status;
}

DYNAMIC_API PEP_STATUS myself(PEP_SESSION session, pEp_identity * identity)
{
    return ADD_TO_LOG(_myself(session, identity, true, false));
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
        // for undo
        if (session->cached_mistrusted)
            free(session->cached_mistrusted);
        session->cached_mistrusted = identity_dup(ident);
        status = mark_as_compromized(session, ident->fpr);
    }

    return status;
}

DYNAMIC_API PEP_STATUS undo_last_mistrust(PEP_SESSION session) {
    assert(session);
    
    if (!session)
        return PEP_ILLEGAL_VALUE;
    
    PEP_STATUS status = PEP_STATUS_OK;
        
    pEp_identity* cached_ident = session->cached_mistrusted;
    
    if (!cached_ident)
        status = PEP_CANNOT_FIND_IDENTITY;
    else {
        status = set_identity(session, cached_ident);            
        free_identity(session->cached_mistrusted);
    }
    
    session->cached_mistrusted = NULL;

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

    if (!ident || EMPTYSTR(ident->address) || EMPTYSTR(ident->user_id) ||
            EMPTYSTR(ident->fpr))
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
                user_id = (const char *)
                    sqlite3_column_text(session->own_identities_retrieve, 2);
                username = (const char *)
                    sqlite3_column_text(session->own_identities_retrieve, 3);
                comm_type = PEP_ct_pEp;
                lang = (const char *)
                    sqlite3_column_text(session->own_identities_retrieve, 4);
                flags = (unsigned int)
                    sqlite3_column_int(session->own_identities_retrieve, 5);

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

// FIXME: should it be be used when sync receive old keys ? (ENGINE-145)
DYNAMIC_API PEP_STATUS set_own_key(
       PEP_SESSION session,
       const char *address,
       const char *fpr
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session &&
           address &&
           fpr && fpr[0]
          );
    
    if (!(session &&
          address &&
          fpr && fpr[0]
         ))
        return PEP_ILLEGAL_VALUE;
            
            
    // First see if we have it in own identities already, AND we retrieve
    // our own user_id
    pEp_identity* my_id = NULL;
    identity_list* my_identities = NULL;
    char* my_user_id = NULL;
    status = own_identities_retrieve(session, &my_identities);
    
    if (status == PEP_STATUS_OK) {
        if (my_identities) {
            if (!(my_identities->ident && my_identities->ident->user_id))
                return PEP_ILLEGAL_VALUE;

            my_user_id = strdup(my_identities->ident->user_id);

            if (!my_user_id) 
                return PEP_OUT_OF_MEMORY;
            
            // Probably cheaper than all the strcmps if there are many,
            // plus this avoids the capitalisation and . problems:
            
            status = get_identity(session, my_user_id, address, &my_id);
            
            if (status == PEP_STATUS_OK && my_id) {
                if (my_id->fpr && strcasecmp(my_id->fpr, fpr) == 0) {
                    // We're done. It was already here.
                    // FIXME: Do we check trust/revocation/?
                    goto pep_free;
                }            
            }
            
            // Otherwise, we see if there's a binding for this user_id/key
            // in the trust DB
            
            // If there's an id w/ user_id + address
            if (my_id) {
                free(my_id->fpr);
                my_id->fpr = my_user_id;
                my_id->comm_type = PEP_ct_pEp;
                my_id->me = true; // just in case? 
            }
            else { // Else, we need a new identity
                my_id = new_identity(address, fpr, my_user_id, NULL); 
                if (status != PEP_STATUS_OK)
                    goto pep_free; 
                my_id->me = true;
                my_id->comm_type = PEP_ct_pEp;
            }
        }
        else {
            // I think the prerequisite should be that at least one own identity
            // already in the DB, so REALLY look at this.
            return PEP_CANNOT_FIND_IDENTITY;
        }
        
        status = set_identity(session, my_id);
    }  
    
pep_free:
    free(my_id);
    free(my_user_id);
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
