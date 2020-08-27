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
#include "KeySync_fsm.h"

#include "blacklist.h"

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

// Does not return PASSPHRASE errors
PEP_STATUS elect_pubkey(
        PEP_SESSION session, pEp_identity * identity, bool check_blacklist
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
    
    if (!keylist || !keylist->value)
        identity->comm_type = PEP_ct_key_not_found;    
    else {
        stringlist_t *_keylist;
        for (_keylist = keylist; _keylist && _keylist->value; _keylist = _keylist->next) {
            PEP_comm_type _comm_type_key;

            status = get_key_rating(session, _keylist->value, &_comm_type_key);
            assert(status != PEP_OUT_OF_MEMORY);
            if (status == PEP_OUT_OF_MEMORY) {
                free_stringlist(keylist);
                return PEP_OUT_OF_MEMORY;
            }

            if (_comm_type_key != PEP_ct_compromised &&
                _comm_type_key != PEP_ct_unknown)
            {
                if (identity->comm_type == PEP_ct_unknown ||
                    _comm_type_key > identity->comm_type)
                {
                    bool blacklisted = false;
                    bool mistrusted = false;
                    status = is_mistrusted_key(session, _keylist->value, &mistrusted);
                    if (status == PEP_STATUS_OK && check_blacklist)
                        status = blacklist_is_listed(session, _keylist->value, &blacklisted);
                    if (status == PEP_STATUS_OK && !mistrusted && !blacklisted) {
                        identity->comm_type = _comm_type_key;
                        _fpr = _keylist->value;
                    }
                }
            }
        }
    }
    free(identity->fpr);

    if (!_fpr || _fpr[0] == '\0')
        identity->fpr = NULL;
    else {    
        identity->fpr = strdup(_fpr);
        if (identity->fpr == NULL) {
            free_stringlist(keylist);
            return PEP_OUT_OF_MEMORY;
        }
    }
    
    free_stringlist(keylist);
    return PEP_STATUS_OK;
}


// own_must_contain_private is usually true when calling;
// we only set it to false when we have the idea of
// possibly having an own pubkey that we need to check on its own
// N.B. Checked for PASSPHRASE errors - will now return them always
// False value of "renew_private" prevents their possibility, though.
PEP_STATUS validate_fpr(PEP_SESSION session, 
                        pEp_identity* ident,
                        bool check_blacklist,
                        bool own_must_contain_private,
                        bool renew_private) {
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    if (!session || !ident || !ident->fpr || !ident->fpr[0])
        return PEP_ILLEGAL_VALUE;    
        
    char* fpr = ident->fpr;
    
    bool has_private = false;
    status = contains_priv_key(session, fpr, &has_private);
    
    // N.B. Will not contain PEP_PASSPHRASE related returns here
    if (ident->me && own_must_contain_private) {
        if (status != PEP_STATUS_OK || !has_private)
            return PEP_KEY_UNSUITABLE;
    }
    else if (status != PEP_STATUS_OK && has_private) // should never happen
        has_private = false;
    
    status = get_trust(session, ident);
    if (status != PEP_STATUS_OK)
        ident->comm_type = PEP_ct_unknown;
            
    PEP_comm_type ct = ident->comm_type;

    if (ct == PEP_ct_unknown) {
        // If status is bad, it's ok, we get the rating
        // we should use then (PEP_ct_unknown)
        get_key_rating(session, fpr, &ct);
        ident->comm_type = ct;
    }
    else if (ct == PEP_ct_key_expired || ct == PEP_ct_key_expired_but_confirmed) {
        PEP_comm_type ct_expire_check = PEP_ct_unknown;
        get_key_rating(session, fpr, &ct_expire_check);
        if (ct_expire_check >= PEP_ct_strong_but_unconfirmed) {
            ident->comm_type = ct_expire_check;
            if (ct == PEP_ct_key_expired_but_confirmed)
                ident->comm_type |= PEP_ct_confirmed;
            ct = ident->comm_type;
            // We need to fix this trust in the DB.
            status = set_trust(session, ident);
        }
    }
    
    
    bool pEp_user = false;
    
    is_pEp_user(session, ident, &pEp_user);

    if (pEp_user) {
        switch (ct) {
            case PEP_ct_OpenPGP:
            case PEP_ct_OpenPGP_unconfirmed:
                ct += 0x47; // difference between PEP and OpenPGP values;
                ident->comm_type = ct;
                break;
            default:
                break;
        }
    }
    
    bool revoked, expired;
    bool blacklisted = false;
    
    // Should not need to decrypt key material
    status = key_revoked(session, fpr, &revoked);    
        
    if (status != PEP_STATUS_OK) {
        return status;
    }
    
    if (!revoked) {
        time_t exp_time = (ident->me ? 
                           time(NULL) + (7*24*3600) : time(NULL));

        // Should not need to decrypt key material                           
        status = key_expired(session, fpr, 
                             exp_time,
                             &expired);
        
        assert(status == PEP_STATUS_OK);
        if (status != PEP_STATUS_OK)
            return status;

        if (check_blacklist && IS_PGP_CT(ct) &&
            !ident->me) {
            status = blacklist_is_listed(session, 
                                         fpr, 
                                         &blacklisted);
                                         
            if (status != PEP_STATUS_OK)
                return status;
        }
    }
            
    // Renew key if it's expired, our own, has a private part,
    // isn't too weak, and we didn't say "DON'T DO THIS"
    if (renew_private && ident->me && has_private && 
        (ct >= PEP_ct_strong_but_unconfirmed) && 
        !revoked && expired) {
        // extend key
        timestamp *ts = new_timestamp(time(NULL) + KEY_EXPIRE_DELTA);
        status = renew_key(session, fpr, ts);
        free_timestamp(ts);

        if (status == PEP_PASSPHRASE_REQUIRED || status == PEP_WRONG_PASSPHRASE)
            return status;
            
        if (status == PEP_STATUS_OK) {
            // if key is valid (second check because pEp key might be extended above)
            //      Return fpr        
            status = key_expired(session, fpr, time(NULL), &expired);            
            if (status != PEP_STATUS_OK)
                return status;
                
            if (expired) {
                if (ident->comm_type & PEP_ct_confirmed || (ident->comm_type == PEP_ct_key_expired_but_confirmed))
                    ident->comm_type = PEP_ct_key_expired_but_confirmed;
                else
                    ident->comm_type = PEP_ct_key_expired;
                return status;
            }
            // communicate key(?)
        }        
    }
     
    if (revoked) 
        ct = PEP_ct_key_revoked;
    else if (expired) {
        if (ident->comm_type & PEP_ct_confirmed || (ident->comm_type == PEP_ct_key_expired_but_confirmed))
            ct = PEP_ct_key_expired_but_confirmed;
        else
            ct = PEP_ct_key_expired;
    }
    else if (blacklisted) { // never true for .me
        ident->comm_type = ct = PEP_ct_key_not_found;
        free(ident->fpr);
            ident->fpr = strdup("");
        status = PEP_KEY_BLACKLISTED;
    }
    
    switch (ct) {
        case PEP_ct_key_expired:
        case PEP_ct_key_expired_but_confirmed:
        case PEP_ct_key_revoked:
        case PEP_ct_key_b0rken:
            // delete key from being default key for all users/identities
            status = remove_fpr_as_default(session, fpr);
            status = update_trust_for_fpr(session, 
                                          fpr, 
                                          ct);
        case PEP_ct_mistrusted:                                  
            free(ident->fpr);
            ident->fpr = NULL;
            ident->comm_type = ct;            
            status = PEP_KEY_UNSUITABLE;
        default:
            break;
    }            

    return status;
}

PEP_STATUS get_all_keys_for_user(PEP_SESSION session, 
                                 const char* user_id,
                                 stringlist_t** keys) {

    if (!session || EMPTYSTR(user_id) || !keys)
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = PEP_STATUS_OK;
        
    *keys = NULL;
    stringlist_t* _kl = NULL;
    
    sqlite3_reset(session->get_all_keys_for_user);
    sqlite3_bind_text(session->get_all_keys_for_user, 1, user_id, -1, SQLITE_STATIC);

    int result = -1;
    
    while ((result = sqlite3_step(session->get_all_keys_for_user)) == SQLITE_ROW) {
        const char* keyres = (const char *) sqlite3_column_text(session->get_all_keys_for_user, 0);
        if (keyres) {
            if (_kl)
                stringlist_add(_kl, keyres);
            else
                _kl = new_stringlist(keyres);
        }
    }
    
    if (!_kl)
        return PEP_KEY_NOT_FOUND;
        
    *keys = _kl;
    
    sqlite3_reset(session->get_all_keys_for_user);

    return status;
}

PEP_STATUS get_user_default_key(PEP_SESSION session, const char* user_id,
                                char** default_key) {
    assert(session);
    assert(user_id);
    
    if (!session || !user_id)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
            
    // try to get default key for user_data
    sqlite3_reset(session->get_user_default_key);
    sqlite3_bind_text(session->get_user_default_key, 1, user_id, 
                      -1, SQLITE_STATIC);
    
    const int result = sqlite3_step(session->get_user_default_key);
    char* user_fpr = NULL;
    if (result == SQLITE_ROW) {
        const char* u_fpr =
            (char *) sqlite3_column_text(session->get_user_default_key, 0);
        if (u_fpr)
            user_fpr = strdup(u_fpr);
    }
    else
        status = PEP_GET_KEY_FAILED;
        
    sqlite3_reset(session->get_user_default_key);
    
    *default_key = user_fpr;
    return status;     
}

// Only call on retrieval of previously stored identity!
// Also, we presume that if the stored_identity was sent in
// without an fpr, there wasn't one in the trust DB for this
// identity.
//
// Will now NOT return passphrase errors, as we tell 
// validate_fpr NOT to renew it. And we specifically suppress them 
// with "PEP_KEY_UNSUITABLE"
//
PEP_STATUS get_valid_pubkey(PEP_SESSION session,
                         pEp_identity* stored_identity,
                         bool* is_identity_default,
                         bool* is_user_default,
                         bool* is_address_default,
                         bool check_blacklist) {
    
    PEP_STATUS status = PEP_STATUS_OK;

    if (!stored_identity || EMPTYSTR(stored_identity->user_id)
        || !is_identity_default || !is_user_default || !is_address_default)
        return PEP_ILLEGAL_VALUE;
        
    *is_identity_default = *is_user_default = *is_address_default = false;

    PEP_comm_type first_reject_comm_type = PEP_ct_key_not_found;
    PEP_STATUS first_reject_status = PEP_KEY_NOT_FOUND;
    
    char* stored_fpr = stored_identity->fpr;
    
    // Input: stored identity retrieved from database
    // if stored identity contains a default key; if so, we return from here
    if (!EMPTYSTR(stored_fpr)) {
        
        // Won't ask for passphrase, won't return PASSPHRASE status
        // Because of non-renewal
        status = validate_fpr(session, stored_identity, check_blacklist, true, false);
        switch (status) {
            case PEP_STATUS_OK:
                if (!EMPTYSTR(stored_identity->fpr)) {
                    *is_identity_default = *is_address_default = true;
                    return status;                    
                }
                break;
            case PEP_KEY_NOT_FOUND:
                break;
            default:    
                first_reject_status = status;
                first_reject_comm_type = stored_identity->comm_type;            
        }    
    } 
    // if no valid default stored identity key found
    free(stored_identity->fpr);
    stored_identity->fpr = NULL;
    
    char* user_fpr = NULL;
    status = get_user_default_key(session, stored_identity->user_id, &user_fpr);
    
    if (!EMPTYSTR(user_fpr)) {             
        // There exists a default key for user, so validate
        stored_identity->fpr = user_fpr;
        
        // Won't ask for passphrase, won't return PASSPHRASE status
        // Because of non-renewal
        status = validate_fpr(session, stored_identity, check_blacklist, true, false);

        switch (status) {
            case PEP_STATUS_OK:
                if (!EMPTYSTR(stored_identity->fpr)) {
                    *is_user_default = true;
                    *is_address_default = key_matches_address(session, 
                                                              stored_identity->address,
                                                              stored_identity->fpr);
                    return status;
                }
                break;
            case PEP_KEY_NOT_FOUND:
                break;
            default: 
                if (first_reject_status != PEP_KEY_NOT_FOUND) {
                    first_reject_status = status;
                    first_reject_comm_type = stored_identity->comm_type;            
                }    
        }    
    }

    // If we got here, there's no usable default.
    
    // status = elect_pubkey(session, stored_identity, check_blacklist);
    // if (status == PEP_STATUS_OK) {
    //     if (!EMPTYSTR(stored_identity->fpr)) {
    //         // Won't ask for passphrase, won't return PASSPHRASE status
    //         // Because of non-renewal            
    //         status = validate_fpr(session, stored_identity, false, true, false); // blacklist already filtered of needed
    //     }    
    // }    
    // else if (status != PEP_KEY_NOT_FOUND && first_reject_status != PEP_KEY_NOT_FOUND) {
    //     first_reject_status = status;
    //     first_reject_comm_type = stored_identity->comm_type;
    // }
    
    switch (first_reject_comm_type) {
        case PEP_ct_key_revoked:
        case PEP_ct_key_b0rken:
        case PEP_ct_key_expired:
        case PEP_ct_key_expired_but_confirmed:
        case PEP_ct_compromised:
        case PEP_ct_mistrusted:
            // this only happens when it's all there is
            status = first_reject_status;
            free(stored_identity->fpr);
            stored_identity->fpr = NULL;
            stored_identity->comm_type = first_reject_comm_type;
            break;    
        default:
            if (check_blacklist && status == PEP_KEY_BLACKLISTED) {
                free(stored_identity->fpr);
                stored_identity->fpr = NULL;
                stored_identity->comm_type = PEP_ct_key_not_found;
            }
            break;
    }
    
    // should never happen, but we will MAKE sure
    if (PASS_ERROR(status)) 
        status = PEP_KEY_UNSUITABLE; // renew it on your own time, baby
        
    return status;
}

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

static void adjust_pEp_trust_status(PEP_SESSION session, pEp_identity* identity) {
    assert(session);
    assert(identity);
    
    if (identity->comm_type < PEP_ct_strong_but_unconfirmed ||
        (identity->comm_type | PEP_ct_confirmed) == PEP_ct_pEp)
        return;
    
    bool pEp_user;
    
    is_pEp_user(session, identity, &pEp_user);
    
    if (pEp_user) {
        PEP_comm_type confirmation_status = identity->comm_type & PEP_ct_confirmed;
        identity->comm_type = PEP_ct_pEp_unconfirmed | confirmation_status;
        if (identity->major_ver == 0) {
            identity->major_ver = 2;
            identity->minor_ver = 0;
        }    
    }
}


// NEVER called on an own identity. 
// But we also make sure get_valid_pubkey 
// and friends NEVER return with a password error.
// (get_valid_pubkey tells validate_fpr not to try renewal)
// Will not return PASSPHRASE errors.
static PEP_STATUS prepare_updated_identity(PEP_SESSION session,
                                                 pEp_identity* return_id,
                                                 pEp_identity* stored_ident,
                                                 bool store) {
    
    if (!session || !return_id || !stored_ident)
        return PEP_ILLEGAL_VALUE;
    
    PEP_STATUS status;
    
    bool is_identity_default, is_user_default, is_address_default;
    bool no_stored_default = EMPTYSTR(stored_ident->fpr);

    status = get_valid_pubkey(session, stored_ident,
                                &is_identity_default,
                                &is_user_default,
                                &is_address_default,
                                false);

    bool is_pEp = false;

    switch (status) {
        case PEP_STATUS_OK:
            if (!EMPTYSTR(stored_ident->fpr)) {
                // set identity comm_type from trust db (user_id, FPR)
                status = get_trust(session, stored_ident);
                if (status == PEP_CANNOT_FIND_IDENTITY || stored_ident->comm_type == PEP_ct_unknown) {
                    // This is OK - there is no trust DB entry, but we
                    // found a key. We won't store this, but we'll
                    // use it.
                    PEP_comm_type ct = PEP_ct_unknown;
                    status = get_key_rating(session, stored_ident->fpr, &ct);
                    stored_ident->comm_type = ct;
                }
            }
            else if (stored_ident->comm_type == PEP_ct_unknown)
                stored_ident->comm_type = PEP_ct_key_not_found;
            break;    
        default:    
            is_pEp_user(session, stored_ident, &is_pEp);
            if (is_pEp) {
                switch (stored_ident->comm_type) {
                    case PEP_ct_key_expired:
                    case PEP_ct_key_expired_but_confirmed:
                        store = false;
                        break;
                    default:
                        break;
                }
            }

            free(stored_ident->fpr);
            stored_ident->fpr = NULL;
            stored_ident->comm_type = PEP_ct_key_not_found;        
    }

    free(return_id->fpr);
    return_id->fpr = NULL;
    if (status == PEP_STATUS_OK && !EMPTYSTR(stored_ident->fpr))
        return_id->fpr = strdup(stored_ident->fpr);
        
    return_id->comm_type = stored_ident->comm_type;
                    
    // We patch the DB with the input username, but if we didn't have
    // one, we pull it out of storage if available.
    if (!EMPTYSTR(stored_ident->username)) {
        if (!EMPTYSTR(return_id->username) && 
            (strcasecmp(return_id->username, return_id->address) == 0)) {
            free(return_id->username);
            return_id->username = NULL;
        }
        if (EMPTYSTR(return_id->username)) {
            free(return_id->username);
            return_id->username = strdup(stored_ident->username);
        }
    }
    else {
        if (EMPTYSTR(return_id->username))
            return_id->username = strdup(return_id->address);
    }
    
    return_id->me = stored_ident->me;
    
    return_id->major_ver = stored_ident->major_ver;
    return_id->minor_ver = stored_ident->minor_ver;

    // FIXME: Do we ALWAYS do this? We probably should...
    if (EMPTYSTR(return_id->user_id)) {
        free(return_id->user_id);
        return_id->user_id = strdup(stored_ident->user_id);
    } 
    
    adjust_pEp_trust_status(session, return_id);
   
    // Call set_identity() to store
    if (store && (is_identity_default || is_user_default) &&
         is_address_default) {                 
         // if we got an fpr which is default for either user
         // or identity AND is valid for this address, set in DB
         // as default
         status = set_identity(session, return_id);
    } 
    else if (store && no_stored_default && !EMPTYSTR(return_id->fpr) 
             && return_id->comm_type != PEP_ct_key_revoked
             && return_id->comm_type != PEP_ct_key_expired
             && return_id->comm_type != PEP_ct_key_expired_but_confirmed
             && return_id->comm_type != PEP_ct_mistrusted 
             && return_id->comm_type != PEP_ct_key_b0rken) { 
        // We would have stored this anyway for a first-time elected key. We just have an ident w/ no default already.
        status = set_identity(session, return_id);
    }
    else { // this is a key other than the default, but there IS a default (FIXME: fdik, do we really want behaviour below?)
        // Store without default fpr/ct, but return the fpr and ct 
        // for current use
        char* save_fpr = return_id->fpr;
        PEP_comm_type save_ct = return_id->comm_type;
        return_id->fpr = NULL;
        return_id->comm_type = PEP_ct_unknown;
        if (store) {
            PEP_STATUS save_status = status;
            status = set_identity(session, return_id);
            if (save_status != PEP_STATUS_OK)
                status = save_status;
        }        
        return_id->fpr = save_fpr;
        return_id->comm_type = save_ct;
    }
    
    transfer_ident_lang_and_flags(return_id, stored_ident);
    return_id->enc_format = stored_ident->enc_format;    
        
    if (return_id->comm_type == PEP_ct_unknown)
        return_id->comm_type = PEP_ct_key_not_found;
    
    return status;
}

// Should not return PASSPHRASE errors because we force 
// calls that can cause key renewal not to.
DYNAMIC_API PEP_STATUS update_identity(
        PEP_SESSION session, pEp_identity * identity
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(identity);
    assert(!EMPTYSTR(identity->address));

    if (!(session && identity && !EMPTYSTR(identity->address)))
        return PEP_ILLEGAL_VALUE;

    //
    // Record some information about the input identity so that we don't keep 
    // evaluating it
    //
    bool is_own_user = identity->me;    
    bool input_has_user_id = !EMPTYSTR(identity->user_id);
    bool input_has_username = !EMPTYSTR(identity->username);
    bool input_has_real_id = input_has_user_id ? (strstr(identity->user_id, "TOFU_") != identity->user_id) : false;
    bool input_name_is_addr = input_has_username ? strcmp(identity->username, identity->address) == 0 : false;
    bool weak_input_name = input_name_is_addr || !input_has_username;

    char* default_own_id = NULL;
    pEp_identity* stored_ident = NULL;

    status = get_default_own_userid(session, &default_own_id);    
    if (status == PEP_STATUS_OK || status == PEP_CANNOT_FIND_IDENTITY)
        status = PEP_STATUS_OK;
    else
        goto pEp_free;        

    // To be clear, if an own identity comes in here, the only way we will accept 
    // it is if the caller did not KNOW this, as indicated by the lack of a known 
    // own user_id and identity->me being false.
    // 
    // IF either of these are set, then the call will fail. If, however, we get
    // an identity which simply has the own address on it, we'll kindly call a read-only
    // version of myself.
    if (!is_own_user) {
        if (default_own_id) {
            if (input_has_user_id) {
                if (strcmp(default_own_id, identity->user_id) == 0) {
                    is_own_user = true;
                }
                else {
                    char* alias = NULL;
                    if (get_userid_alias_default(session, identity->user_id, &alias) == PEP_STATUS_OK) {
                        if (alias && strcmp(default_own_id, alias) == 0)
                            is_own_user = true;
                        free(alias);    
                    }
                }
            }
            else {
                // Check if own address. For now, this is a special case;
                // we try to require apps to send in user_ids, but must prevent
                // writes to an own identity from within THIS function
                // NOTE: These semantics MAY CHANGE.
                bool _own_addr = false;
                is_own_address(session, identity->address, &_own_addr);
                
                if (_own_addr) {
                    free(identity->user_id);
                    identity->user_id = strdup(default_own_id);
                    // Do not renew, do not generate
                    return _myself(session, identity, false, false, false, true);
                }    
            }
        }
        // Otherwise, we don't even HAVE an own user yet, so we're ok.
    }    
    if (is_own_user) {
        free(default_own_id);
        return PEP_ILLEGAL_VALUE;
    }

    // We have, at least, an address.
    // Retrieve stored identity information!    

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // If we can get a starting identity from the database, do it. If we have a user_id (thank you, users),
    // this is pretty simple.
    // 
    // Otherwise, we double-check that someone didn't pass in an own address (hey, if you don't give us a
    // user_id, we're have to guess somehow, and treating own identities like partner identities is dangerous).
    //////////////////////////////////////////////////////////////////////////////////////////////////////

    if (input_has_user_id) {            
        // (we're gonna update the trust/fpr anyway, so we use the no-fpr-from-trust-db variant)
        //      * do get_identity() to retrieve stored identity information
        status = get_identity_without_trust_check(session, identity->address, identity->user_id, &stored_ident);
    }
    else { // see if we perhaps own this user
        if (default_own_id) {
            status = get_identity(session, 
                                  identity->address, 
                                  default_own_id, 
                                  &stored_ident);
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // If we're unable to get a starting stored ID, we now need to try to get IDs which match the address.
    // Should we find them, we go through the list and try to find an acceptable one by evaluating the 
    // following properties (not in order of priority, and not for every case - the logic here is a mess):
    //
    // 1. Did the input have a user_id?
    // 2. Did the input hava a username?
    // 3. Is the input user_id a real id?
    // 4. Is the stored user_id a real id?
    // 5. Does the stored user_id have a username?
    // 6. Do the names match?
    //
    // Based on this, if we find an acceptable candidate, we do one:
    //
    // 1. Replace the global DB user_id with the input user_id and patch the stored identity's user_id 
    //    (this may be different than 1, though in practice it seems we always do both)
    // 2. Patch the output identity's user_id from the stored identity
    //
    // If we find none, in the case if the has-username-but-no-user_id input case, we'll try a TOFU id
    // fetch before giving up on stored identity candidates.
    //
    // Acceptable candidates are then passed to prepare_update_identity which will patch usernames and
    // find any applicable keys.
    //
    // Unacceptable candidates will then have minimal record information entered depending on how much 
    // came in in the input, TOFU user_ids created when needed, and a new record placed in the DB
    // accordingly.
    //

    if (!stored_ident) {
        identity_list* id_list = NULL;
        status = get_identities_by_address(session, identity->address, &id_list);
        if (id_list) {
            identity_list* stored_curr = id_list;

            // Ok, here's where we search for stored identities and try to find a candidate.
            while (stored_curr) {
                // Ok, this is where the above code fun begins. Let's get some information about the identity.
                pEp_identity* candidate = stored_curr->ident;
                if (candidate) {
                    char* candidate_id = candidate->user_id;

                    // this_uid should never be NULL, as this is half of the ident
                    // DB primary key
                    assert(!EMPTYSTR(candidate_id));

                    // grab some information about the stored identity
                    bool candidate_has_real_id = strstr(candidate_id, "TOFU_") != candidate_id;
                    bool candidate_has_username = !EMPTYSTR(candidate->username);
                    bool candidate_name_is_addr = candidate_has_username ? strcmp(candidate->address, candidate->username) == 0 : false;
                    bool weak_candidate_name = !candidate_has_username || candidate_name_is_addr;

                    bool names_match = (weak_candidate_name && weak_input_name) ||
                                           ((input_has_username && candidate_has_username) && 
                                           (strcmp(identity->username, candidate->username) == 0));
                        
                    // This is where the optimisation gets a little weird:
                    //
                    // Decide whether to accept and patch the database and stored id from the input,
                    // Accept and patch the input id from the database, or reject and go to the next
                    // one in the list
                    //
                    
                    // This is unnecessary, but I think the terms need to be descriptive where possible
                    bool input_addr_only = !input_has_username && !input_has_user_id;
                    bool candidate_id_best = candidate_has_real_id && !input_has_real_id;
                    bool input_id_best = input_has_real_id && !candidate_has_real_id;
                    bool patch_input_id_conditions = input_has_user_id || names_match || weak_candidate_name;
                    if (input_addr_only || (candidate_id_best && patch_input_id_conditions)) {
                        identity->user_id = strdup(candidate_id);
                        assert(identity->user_id);
                        if (!identity->user_id)
                            goto enomem;

                        stored_ident = identity_dup(candidate);
                        break;
                    }
                    else if (input_id_best && (names_match || (input_has_username && weak_candidate_name))) {
                        // Replace the TOFU db in the database with the input ID globally
                        status = replace_userid(session, 
                                                candidate_id, 
                                                identity->user_id);
                        if (status != PEP_STATUS_OK) {
                            free_identity_list(id_list);
                            free(default_own_id);
                            return status;
                        }

                        // Reflect the change we just made to the DB
                        free(candidate->user_id);
                        candidate->user_id = strdup(identity->user_id);
                        stored_ident = identity_dup(candidate);

                        break;
                    } // End else if
                    // Else, we reject this candidate and try the next one, if there is one.
                    stored_curr = stored_curr->next;
                }
                // Ok, we've checked all of the candidates, and if there's a stored identity, there's a duplicate.
                // Freeeeeeee...
                free_identity_list(id_list);
            }
        }
        // If, by here, there is no user id on the identity, we put one on there.
        // We've found any non-TOFU one we're going to find, so if this is empty,
        // We don't have a stored ident.
        if (EMPTYSTR(identity->user_id)) {
            identity->user_id = calloc(1, strlen(identity->address) + 6);
            if (!identity->user_id)
                goto enomem;

            snprintf(identity->user_id, strlen(identity->address) + 6,
                     "TOFU_%s", identity->address);                    
            
            // Try one last time to see if there is an ident for us with a TOFU id, if there was no ID but there
            // was a usernames
            if (input_has_username) {
                status = get_identity(session, 
                                      identity->address, 
                                      identity->user_id, 
                                      &stored_ident);
            }
        }
    }        

    //
    // Either update the identity (and possibly DB to reflect stored ident information, or
    // create a new identity and store it.
    //
    if (status == PEP_STATUS_OK && stored_ident) { 
        //  An identity was available.
        //  Call will patch the username where needed and 
        //  get a valid default key (for ident or user)
        status = prepare_updated_identity(session,
                                          identity,
                                          stored_ident, true);
    }
    else { // No stored ident. We're done.
        // If we needed TOFU, we've taken care of the ID above.
        if (EMPTYSTR(identity->username)) { // currently, not after messing around
            free(identity->username);
            identity->username = strdup(identity->address);
            if (!identity->username)
                goto enomem;
        }

        free(identity->fpr);
        identity->fpr = NULL;
        identity->comm_type = PEP_ct_unknown;
        adjust_pEp_trust_status(session, identity);
        status = set_identity(session, identity);
    }
    
    // VB says, and I quote, "that is not implemented and no one is using it right now"
    // about this bit. So, um, you're forewarned.
    if (identity->comm_type != PEP_ct_compromised &&
        identity->comm_type < PEP_ct_strong_but_unconfirmed)
        if (session->examine_identity)
            session->examine_identity(identity, session->examine_management);

    goto pEp_free;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_free:
    free(default_own_id);
    free_identity(stored_ident);
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
                
                if (_comm_type_key != PEP_ct_compromised &&
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
    
    bool has_private = false;
    PEP_STATUS status = contains_priv_key(session, fpr, &has_private);
    
    *is_usable = has_private;
    
    return status;
}

PEP_STATUS _myself(PEP_SESSION session, 
                   pEp_identity * identity, 
                   bool do_keygen,
                   bool do_renew, 
                   bool ignore_flags,
                   bool read_only)
{

    PEP_STATUS status;

    assert(session);
    assert(identity);
    assert(!EMPTYSTR(identity->address));

    if (!session || EMPTYSTR(identity->address))
        return PEP_ILLEGAL_VALUE;

    // this is leading to crashes otherwise

    if (!(identity->user_id && identity->user_id[0])) {
        free(identity->user_id);
        identity->user_id = strdup(PEP_OWN_USERID);
        assert(identity->user_id);
        if (!identity->user_id)
            return PEP_OUT_OF_MEMORY;
    }

    pEp_identity *stored_identity = NULL;
    char* revoked_fpr = NULL; 
    bool valid_key_found = false;
        
    char* default_own_id = NULL;
    status = get_default_own_userid(session, &default_own_id);
    
    // Deal with non-default user_ids.
    // FIXME: if non-default and read-only, reject totally?
    if (default_own_id && strcmp(default_own_id, identity->user_id) != 0) {
        if (read_only) {
            free(identity->user_id);
            identity->user_id = strdup(default_own_id);
            assert(identity->user_id);
            if (!identity->user_id)
                return PEP_OUT_OF_MEMORY;
        }
        else {
            status = set_userid_alias(session, default_own_id, identity->user_id);
            // Do we want this to be fatal? For now, we'll do it...
            if (status != PEP_STATUS_OK)
                goto pEp_free;
                
            free(identity->user_id);
            identity->user_id = strdup(default_own_id);
            assert(identity->user_id);
            if (identity->user_id == NULL) {
                status = PEP_OUT_OF_MEMORY;
                goto pEp_free;
            }
        }
    }

    // NOTE: IF WE DON'T YET HAVE AN OWN_ID, WE IGNORE REFERENCES TO THIS ADDRESS IN THE
    // DB (WHICH MAY HAVE BEEN SET BEFORE MYSELF WAS CALLED BY RECEIVING AN EMAIL FROM
    // THIS ADDRESS), AS IT IS NOT AN OWN_IDENTITY AND HAS NO INFORMATION WE NEED OR WHAT TO
    // SET FOR MYSELF
    
    // Ok, so now, set up the own_identity:
    identity->comm_type = PEP_ct_pEp;
    identity->me = true;
    if(ignore_flags)
        identity->flags = 0;
    
    // Let's see if we have an identity record in the DB for 
    // this user_id + address
//    DEBUG_LOG("myself", "debug", identity->address);
 
    // This will grab the actual flags from the db
    status = get_identity(session,
                          identity->address,
                          identity->user_id,
                          &stored_identity);

    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_free;
    }

    // Set usernames - priority is input username > stored name > address
    // If there's an input username, we always patch the username with that
    // input.
    // N.B. there was an || read_only here, but why? read_only ONLY means 
    // we don't write to the DB! So... removed. But how this managed to work 
    // before I don't know.
    if (EMPTYSTR(identity->username)) {
        bool stored_uname = (stored_identity && !EMPTYSTR(stored_identity->username));
        char* uname = (stored_uname ? stored_identity->username : identity->address);
        if (uname) {
            free(identity->username);
            identity->username = strdup(uname);
            assert(identity->username);
            if (identity->username == NULL) {
                status = PEP_OUT_OF_MEMORY;
                goto pEp_free;
            }
        }
    }

    // ignore input fpr

    if (identity->fpr) {
        free(identity->fpr);
        identity->fpr = NULL;
    }

    // check stored identity
    if (stored_identity) {
        if (!EMPTYSTR(stored_identity->fpr)) {
            // Fall back / retrieve
            status = validate_fpr(session, stored_identity, false, true, do_renew);
        
            switch (status) {
                // Only possible if we called this with do_renew = true
                case PEP_OUT_OF_MEMORY:
                case PEP_PASSPHRASE_REQUIRED:
                case PEP_WRONG_PASSPHRASE:
                    goto pEp_free;
                    
                case PEP_STATUS_OK:    
                    if (stored_identity->comm_type >= PEP_ct_strong_but_unconfirmed) {
                        identity->fpr = strdup(stored_identity->fpr);
                        assert(identity->fpr);
                        if (!identity->fpr) {
                            status = PEP_OUT_OF_MEMORY;
                            goto pEp_free;
                        }
                        valid_key_found = true;            
                    }
                    else {
                        bool revoked = false;
                        status = key_revoked(session, stored_identity->fpr, &revoked);
                        if (status)
                            goto pEp_free;
                        if (revoked) {
                            revoked_fpr = strdup(stored_identity->fpr);
                            assert(revoked_fpr);
                            if (!revoked_fpr) {
                                status = PEP_OUT_OF_MEMORY;
                                goto pEp_free;
                            }
                        }
                    }
                    break;
                default:
                    break;
            }        
        }
        // reconcile language, flags
        transfer_ident_lang_and_flags(identity, stored_identity);
    }
    
    // Nothing left to do but generate a key
    if (!valid_key_found) {
        if (!do_keygen || read_only)
            status = PEP_GET_KEY_FAILED;
        else {
// /            DEBUG_LOG("Generating key pair", "debug", identity->address);

            free(identity->fpr);
            identity->fpr = NULL;
            status = generate_keypair(session, identity);
            assert(status != PEP_OUT_OF_MEMORY);

            if (status == PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED)
                goto pEp_free;
                
            if (status != PEP_STATUS_OK) {
                char buf[11];
                snprintf(buf, 11, "%d", status); // uh, this is kludgey. FIXME
//                DEBUG_LOG("Generating key pair failed", "debug", buf);
            }        
            else {
                valid_key_found = true;
                if (revoked_fpr) {
                    status = set_revoked(session, revoked_fpr,
                                         stored_identity->fpr, time(NULL));
                    assert(status == PEP_STATUS_OK);                     
                }
            }
        }
    }

    if (valid_key_found) {
        identity->comm_type = PEP_ct_pEp;
        status = PEP_STATUS_OK;
    }
    else {
        free(identity->fpr);
        identity->fpr = NULL;
        identity->comm_type = PEP_ct_unknown;
    }
    
    unsigned int major_ver = 0;
    unsigned int minor_ver = 0;
    pEp_version_major_minor(PEP_VERSION, &major_ver, &minor_ver);
    identity->major_ver = major_ver;
    identity->minor_ver = minor_ver;
    
    // We want to set an identity in the DB even if a key isn't found, but we have to preserve the status if
    // it's NOT ok
    if (!read_only) {
        PEP_STATUS set_id_status = set_identity(session, identity);
        if (set_id_status == PEP_STATUS_OK)
            set_id_status = set_as_pEp_user(session, identity);

        status = (status == PEP_STATUS_OK ? set_id_status : status);
    }
    
pEp_free:    
    free(default_own_id);
    free(revoked_fpr);                     
    free_identity(stored_identity);
    return status;
}

DYNAMIC_API PEP_STATUS myself(PEP_SESSION session, pEp_identity * identity)
{
    return _myself(session, identity, true, true, false, false);
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
    // FIXME_NOW: ensure_decrypt callback???
    PEP_STATUS status = init(&session, NULL, NULL, NULL);
    assert(!status);
    if (status)
        return status;

    assert(session && retrieve_next_identity);
    if (!(session && retrieve_next_identity))
        return PEP_ILLEGAL_VALUE;

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

    bool has_private = false;
    
    status = contains_priv_key(session, ident->fpr, &has_private);        

    if (status != PEP_STATUS_OK && status != PEP_KEY_NOT_FOUND)
        return status;
        
    // See if key is revoked already
    if (has_private) {
        bool revoked = false;
        status = key_revoked(session, ident->fpr, &revoked);

        if (!revoked)
            revoke_key(session, ident->fpr, NULL);
    }
    else {
        if (ident->fpr) {
            // Make sure there was a default in the DB for this identity;
            // if not, set one, even though we're going to mistrust this. Otherwise,
            // cannot reset.
            pEp_identity* stored_ident = NULL;
            get_identity(session, ident->address, ident->user_id, &stored_ident);
            bool set_in_db = true;
            if (!stored_ident)
                stored_ident = identity_dup(ident);
            else if (!stored_ident->fpr)
                stored_ident->fpr = strdup(ident->fpr);
            else
                set_in_db = false;
                        
            if (set_in_db)
                status = set_identity(session, stored_ident);    
            
            free_identity(stored_ident);
            if (status != PEP_STATUS_OK)
                return status;
        }
    }            
            
    // double-check to be sure key is even in the DB
    if (ident->fpr)
        status = set_pgp_keypair(session, ident->fpr);

    // We set this temporarily but will grab it back from the cache afterwards
    ident->comm_type = PEP_ct_mistrusted;
    status = set_trust(session, ident);
    
    if (status == PEP_STATUS_OK)
        // cascade that mistrust for anyone using this key
        status = mark_as_compromised(session, ident->fpr);
    if (status == PEP_STATUS_OK)
        status = add_mistrusted_key(session, ident->fpr);
            
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
    assert(!EMPTYSTR(ident->fpr));
    assert(!EMPTYSTR(ident->address));
    assert(!EMPTYSTR(ident->user_id));

    if (!(session && ident && ident->fpr && ident->fpr[0] != '\0' && ident->address &&
            ident->user_id))
        return PEP_ILLEGAL_VALUE;

    // we do not change the input struct at ALL.
    pEp_identity* input_copy = identity_dup(ident);
    
    pEp_identity* tmp_ident = NULL;
    
    status = get_trust(session, input_copy);
    
    if (status != PEP_STATUS_OK)
        goto pEp_free;
        
    PEP_comm_type new_trust = PEP_ct_unknown;
    status = get_key_rating(session, ident->fpr, &new_trust);
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    bool pEp_user = false;
    
    status = is_pEp_user(session, ident, &pEp_user);
    
    if (pEp_user && new_trust >= PEP_ct_unconfirmed_encryption)
        input_copy->comm_type = PEP_ct_pEp_unconfirmed;
    else
        input_copy->comm_type = new_trust;
        
    status = set_trust(session, input_copy);
    
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    bool mistrusted_key = false;
        
    status = is_mistrusted_key(session, ident->fpr, &mistrusted_key);

    if (status != PEP_STATUS_OK)
        goto pEp_free;
    
    if (mistrusted_key)
        status = delete_mistrusted_key(session, ident->fpr);

    if (status != PEP_STATUS_OK)
        goto pEp_free;
        
    tmp_ident = new_identity(ident->address, NULL, ident->user_id, NULL);

    if (!tmp_ident)
        return PEP_OUT_OF_MEMORY;
    
    if (is_me(session, tmp_ident))
        status = myself(session, tmp_ident);
    else
        status = update_identity(session, tmp_ident);
    
    if (status != PEP_STATUS_OK)
        goto pEp_free;
    
    // remove as default if necessary
    if (!EMPTYSTR(tmp_ident->fpr) && strcmp(tmp_ident->fpr, ident->fpr) == 0) {
        free(tmp_ident->fpr);
        tmp_ident->fpr = NULL;
        tmp_ident->comm_type = PEP_ct_unknown;
        status = set_identity(session, tmp_ident);
        if (status != PEP_STATUS_OK)
            goto pEp_free;
    }
    
    char* user_default = NULL;
    get_main_user_fpr(session, tmp_ident->user_id, &user_default);
    
    if (!EMPTYSTR(user_default)) {
        if (strcmp(user_default, ident->fpr) == 0)
            status = refresh_userid_default_key(session, ident->user_id);
        if (status != PEP_STATUS_OK)
            goto pEp_free;    
    }
            
pEp_free:
    free_identity(tmp_ident);
    free_identity(input_copy);
    return status;
}

// Technically speaking, this should not EVER
// return PASSPHRASE errors, because 
// this is never for an own identity (enforced), and thus 
// validate_fpr will not call renew_key.
// If it ever does, the status gets propagated, but 
// it is distinctly not OK.
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

    if (is_me(session, ident))
        return PEP_ILLEGAL_VALUE;
        
    char* ident_default_fpr = NULL;

    // Before we do anything, be sure the input fpr is even eligible to be trusted
    PEP_comm_type input_default_ct = PEP_ct_unknown;
    status = get_key_rating(session, ident->fpr, &input_default_ct);
    if (input_default_ct < PEP_ct_strong_but_unconfirmed)
        return PEP_KEY_UNSUITABLE;

    status = set_pgp_keypair(session, ident->fpr);
    if (status != PEP_STATUS_OK)
        return status;

    pEp_identity* ident_copy = identity_dup(ident);
    char* cached_fpr = NULL;

    // for setting up a temp trusted identity for the input fpr
    pEp_identity* tmp_id = NULL;

    // For later, in case we need to check the user default key
    pEp_identity* tmp_user_ident = NULL;
        
    // Save the input fpr, which we already tested as non-NULL
    cached_fpr = strdup(ident->fpr);

    // Set up a temp trusted identity for the input fpr without a comm type;
    tmp_id = new_identity(ident->address, ident->fpr, ident->user_id, NULL);
    
    status = validate_fpr(session, tmp_id, false, true, false);
        
    if (status == PEP_STATUS_OK) {
        // Validate fpr gets trust DB or, when that fails, key comm type. we checked
        // above that the key was ok. (not revoked or expired), but we want the max.
        tmp_id->comm_type = _MAX(tmp_id->comm_type, input_default_ct) | PEP_ct_confirmed;

        // Get the default identity without setting the fpr                                       
        status = update_identity(session, ident_copy);
            
        ident_default_fpr = (EMPTYSTR(ident_copy->fpr) ? NULL : strdup(ident_copy->fpr));

        if (status == PEP_STATUS_OK) {
            bool trusted_default = false;

            // If there's no default, or the default is different from the input...
            if (EMPTYSTR(ident_default_fpr) || strcmp(cached_fpr, ident_default_fpr) != 0) {
                
                // If the default fpr (if there is one) is trusted and key is strong enough,
                // don't replace, we just set the trusted bit on this key for this user_id...
                // (If there's no default fpr, this won't be true anyway.)
                if ((ident_copy->comm_type >= PEP_ct_strong_but_unconfirmed && 
                    (ident_copy->comm_type & PEP_ct_confirmed))) {                        

                    trusted_default = true;
                                    
                    status = set_trust(session, tmp_id);
                    input_default_ct = tmp_id->comm_type;                    
                }
                else {
                    free(ident_copy->fpr);
                    ident_copy->fpr = strdup(cached_fpr);
                    ident_copy->comm_type = tmp_id->comm_type;
                    status = set_identity(session, ident_copy); // replace identity default
                    if (status == PEP_STATUS_OK) {
                        if ((ident_copy->comm_type | PEP_ct_confirmed) == PEP_ct_pEp)
                            status = set_as_pEp_user(session, ident_copy);
                    }            
                }
            }
            else { // we're setting this on the default fpr
                ident->comm_type = tmp_id->comm_type;
                status = set_identity(session, ident);
                trusted_default = true;
            }
            if (status == PEP_STATUS_OK && !trusted_default) {
                // Ok, there wasn't a trusted default, so we replaced. Thus, we also
                // make sure there's a trusted default on the user_id. If there
                // is not, we make this the default.
                char* user_default = NULL;
                status = get_main_user_fpr(session, ident->user_id, &user_default);
            
                if (status == PEP_STATUS_OK && user_default) {
                    tmp_user_ident = new_identity(ident->address, 
                                                  user_default, 
                                                  ident->user_id, 
                                                  NULL);
                    if (!tmp_user_ident)
                        status = PEP_OUT_OF_MEMORY;
                    else {
                        status = validate_fpr(session, tmp_user_ident, false, true, false);
                        
                        if (status != PEP_STATUS_OK ||
                            tmp_user_ident->comm_type < PEP_ct_strong_but_unconfirmed ||
                            !(tmp_user_ident->comm_type & PEP_ct_confirmed)) 
                        {
                            char* trusted_fpr = (trusted_default ? ident_default_fpr : cached_fpr);
                            status = replace_main_user_fpr(session, ident->user_id, trusted_fpr);
                        } 
                    }
                }
            }
        }
    }    

    free(ident_default_fpr);
    free(cached_fpr);
    free_identity(tmp_id);
    free_identity(ident_copy);
    free_identity(tmp_user_ident);
    return status;
}

DYNAMIC_API PEP_STATUS trust_own_key(
        PEP_SESSION session,
        pEp_identity* ident
    ) 
{
    assert(session);
    assert(ident);
    assert(!EMPTYSTR(ident->address));
    assert(!EMPTYSTR(ident->user_id));
    assert(!EMPTYSTR(ident->fpr));
    
    if (!ident || EMPTYSTR(ident->address) || EMPTYSTR(ident->user_id) ||
            EMPTYSTR(ident->fpr))
        return PEP_ILLEGAL_VALUE;

    if (!is_me(session, ident))
        return PEP_ILLEGAL_VALUE;

    // don't check blacklist or require a private key
    PEP_STATUS status = validate_fpr(session, ident, false, false, true);

    if (status != PEP_STATUS_OK)
        return status;

    status = set_pgp_keypair(session, ident->fpr);
    if (status != PEP_STATUS_OK)
        return status;
            
    if (ident->comm_type < PEP_ct_strong_but_unconfirmed)
        return PEP_KEY_UNSUITABLE;

    ident->comm_type |= PEP_ct_confirmed;
    
    status = set_trust(session, ident);

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

    sqlite3_bind_int(session->own_identities_retrieve, 1, excluded_flags);

    do {
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
        identity_flags_t excluded_flags,
        bool private_only
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
    
    stringlist_t *_bl = _keylist;
    sqlite3_bind_int(session->own_keys_retrieve, 1, excluded_flags);

    do {        
        result = sqlite3_step(session->own_keys_retrieve);
        switch (result) {
            case SQLITE_ROW:
                _bl = stringlist_add(_bl, (const char *)
                        sqlite3_column_text(session->own_keys_retrieve, 0));
                if (_bl == NULL)
                    goto enomem;
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
    if (status == PEP_STATUS_OK) {
        dedup_stringlist(_keylist);
        if (private_only) {
            stringlist_t* _kl = _keylist;
            stringlist_t* _kl_prev = NULL;
            while (_kl) {
                bool has_private = false;
                contains_priv_key(session, _kl->value, &has_private);
                if (!has_private) {
                    stringlist_t* _kl_tmp = _kl;
                    if (_kl_prev)
                        _kl_prev->next = _kl->next;
                    else 
                        _keylist = _kl->next;
                        
                    _kl = _kl->next;
                    
                    _kl_tmp->next = NULL;
                    free_stringlist(_kl_tmp);
                    continue;
                }
                _kl_prev = _kl;
                _kl = _kl->next;
            }
        }
        *keylist = _keylist;
    }
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
    return _own_keys_retrieve(session, keylist, 0, true);
}

// Returns PASSPHRASE errors when necessary
DYNAMIC_API PEP_STATUS set_own_key(
       PEP_SESSION session,
       pEp_identity *me,
       const char *fpr
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session && me);
    assert(!EMPTYSTR(fpr));
    assert(!EMPTYSTR(me->address));
    assert(!EMPTYSTR(me->user_id));
    assert(!EMPTYSTR(me->username));

    if (!session || !me || EMPTYSTR(fpr) || EMPTYSTR(me->address) ||
            EMPTYSTR(me->user_id) || EMPTYSTR(me->username))
        return PEP_ILLEGAL_VALUE;

    if (me->fpr == fpr)
        me->fpr = NULL;

    // renew if needed, but do not generate
    status = _myself(session, me, false, true, true, false);
    // we do not need a valid key but dislike other errors
    if (status != PEP_STATUS_OK && status != PEP_GET_KEY_FAILED && status != PEP_KEY_UNSUITABLE)
        return status;
    status = PEP_STATUS_OK;

    bool private = false;
    status = contains_priv_key(session, fpr, &private);
    
    if (status != PEP_STATUS_OK)
        return status;
        
    if (!private)
        return PEP_KEY_UNSUITABLE;
 
    if (me->fpr)
        free(me->fpr);
    me->fpr = strdup(fpr);
    assert(me->fpr);
    if (!me->fpr)
        return PEP_OUT_OF_MEMORY;

    status = validate_fpr(session, me, false, true, true);
    if (status)
        return status;

    me->comm_type = PEP_ct_pEp;
    status = set_identity(session, me);
    if (status == PEP_STATUS_OK)
        signal_Sync_event(session, Sync_PR_keysync, SynchronizeGroupKeys, NULL);

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

PEP_STATUS add_mistrusted_key(PEP_SESSION session, const char* fpr)
{
    int result;

    assert(!EMPTYSTR(fpr));
    
    if (!(session) || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;

    sqlite3_reset(session->add_mistrusted_key);
    sqlite3_bind_text(session->add_mistrusted_key, 1, fpr, -1,
            SQLITE_STATIC);

    result = sqlite3_step(session->add_mistrusted_key);
    sqlite3_reset(session->add_mistrusted_key);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PGP_KEYPAIR; // FIXME: Better status?

    return PEP_STATUS_OK;
}

PEP_STATUS delete_mistrusted_key(PEP_SESSION session, const char* fpr)
{
    int result;

    assert(!EMPTYSTR(fpr));
    
    if (!(session) || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;

    sqlite3_reset(session->delete_mistrusted_key);
    sqlite3_bind_text(session->delete_mistrusted_key, 1, fpr, -1,
            SQLITE_STATIC);

    result = sqlite3_step(session->delete_mistrusted_key);
    sqlite3_reset(session->delete_mistrusted_key);

    if (result != SQLITE_DONE)
        return PEP_UNKNOWN_ERROR; // FIXME: Better status?

    return PEP_STATUS_OK;
}

PEP_STATUS is_mistrusted_key(PEP_SESSION session, const char* fpr,
                             bool* mistrusted)
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(!EMPTYSTR(fpr));

    if (!(session && fpr))
        return PEP_ILLEGAL_VALUE;

    *mistrusted = false;

    sqlite3_reset(session->is_mistrusted_key);
    sqlite3_bind_text(session->is_mistrusted_key, 1, fpr, -1, SQLITE_STATIC);

    int result;

    result = sqlite3_step(session->is_mistrusted_key);
    switch (result) {
    case SQLITE_ROW:
        *mistrusted = sqlite3_column_int(session->is_mistrusted_key, 0);
        status = PEP_STATUS_OK;
        break;

    default:
        status = PEP_UNKNOWN_ERROR;
    }

    sqlite3_reset(session->is_mistrusted_key);
    return status;
}

static PEP_STATUS _wipe_default_key_if_invalid(PEP_SESSION session,
                                         pEp_identity* ident) {
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    if (!ident->user_id)
        return PEP_ILLEGAL_VALUE;
        
    if (!ident->fpr)
        return status;
    
    char* cached_fpr = strdup(ident->fpr);
    if (!ident->fpr)
        return PEP_OUT_OF_MEMORY;
        
    PEP_STATUS keystatus = validate_fpr(session, ident, true, false, true);
    if (PASS_ERROR(status))
        return status;
        
    switch (keystatus) {
        case PEP_STATUS_OK:
            // Check for non-renewable expiry and 
            // if so, fallthrough
            if (ident->comm_type != PEP_ct_key_expired_but_confirmed &&
                    ident->comm_type != PEP_ct_key_expired) {
                break;
            }        
        case PEP_KEY_UNSUITABLE:
        case PEP_KEY_BLACKLISTED:
            // Remove key as default for all identities and users 
            status = remove_fpr_as_default(session, cached_fpr);
            break;   
        default:
            break;
    }     
    free(cached_fpr);
    
    // This may have been for a user default, not an identity default.
    if (status == PEP_STATUS_OK && !(EMPTYSTR(ident->address)))
        status = myself(session, ident);
            
    return status;                                        
}

DYNAMIC_API PEP_STATUS clean_own_key_defaults(PEP_SESSION session) {
    identity_list* idents = NULL;
    PEP_STATUS status = own_identities_retrieve(session, &idents);
    if (status != PEP_STATUS_OK)
        return status;
        
    if (!idents)
        return PEP_STATUS_OK;

    if (!idents->ident && !idents->next) {
        free_identity_list(idents);
        return PEP_STATUS_OK;
    } // Kludge: FIX own_identities_retrieve. Should return NULL, not empty list    
        
    identity_list* curr = idents;
    
    for ( ; curr ; curr = curr->next) {
        pEp_identity* ident = curr->ident;
        if (!ident)
            continue;
        
        status = _wipe_default_key_if_invalid(session, ident);    
        if (PASS_ERROR(status))
            return status;
    }   
    
    free_identity_list(idents);
    
    // Also remove invalid default user key
    char* own_id = NULL;

    status = get_default_own_userid(session, &own_id);

    if (status != PEP_STATUS_OK)
        return status;

    if (own_id) {
        char* user_default_key = NULL;
        status = get_user_default_key(session, own_id, &user_default_key);
        if (status != PEP_STATUS_OK) {
            free(own_id);
            if (status == PEP_KEY_NOT_FOUND)
                status = PEP_STATUS_OK;
            else
                return status;
        }
        else if (user_default_key) {
            pEp_identity* empty_user = new_identity(NULL, user_default_key, own_id, NULL);
            status = _wipe_default_key_if_invalid(session, empty_user);       
            if (PASS_ERROR(status))
                return status;
                    
            free(user_default_key);
        }
        free(own_id);    
    }
    return status;
}
