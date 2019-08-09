// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "dynamic_api.h"
#include "message_api.h"
#include "key_reset.h"


#include <string.h>
#include <stdlib.h>

PEP_STATUS has_key_reset_been_sent(
        PEP_SESSION session, 
        const char* user_id, 
        const char* revoked_fpr,
        bool* contacted)
{
    assert(session);
    assert(contacted);
    assert(user_id);
    assert(revoked_fpr);
    assert(!EMPTYSTR(user_id));

    if (!session || !contacted || EMPTYSTR(revoked_fpr) || EMPTYSTR(user_id))
        return PEP_ILLEGAL_VALUE;
    
    *contacted = false;
                    
    char* alias_default = NULL;
    
    PEP_STATUS status = get_userid_alias_default(session, user_id, &alias_default);
    
    if (status == PEP_CANNOT_FIND_ALIAS || EMPTYSTR(alias_default)) {
        free(alias_default);
        alias_default = strdup(user_id);
    }
    
    sqlite3_reset(session->was_id_for_revoke_contacted);
    sqlite3_bind_text(session->was_id_for_revoke_contacted, 1, revoked_fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->was_id_for_revoke_contacted, 2, user_id, -1,
            SQLITE_STATIC);        
    int result = Sqlite3_step(session->was_id_for_revoke_contacted);
    switch (result) {
        case SQLITE_ROW: {
            *contacted = (sqlite3_column_int(session->was_id_for_revoke_contacted, 0) != 0);
            break;
        }
        default:
            sqlite3_reset(session->was_id_for_revoke_contacted);
            free(alias_default);
            return PEP_UNKNOWN_DB_ERROR;
    }

    sqlite3_reset(session->was_id_for_revoke_contacted);
    return PEP_STATUS_OK;
}

//static const char *sql_set_revoke_contact_as_notified =
//    "insert or replace into revocation_contact_list(fpr, contact_id) values (?1, ?2) ;";

PEP_STATUS set_reset_contact_notified(
        PEP_SESSION session,
        const char* revoke_fpr,
        const char* contact_id
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session && !EMPTYSTR(revoke_fpr) && !EMPTYSTR(contact_id));
    
    if (!session || EMPTYSTR(revoke_fpr) || EMPTYSTR(contact_id))
        return PEP_ILLEGAL_VALUE;
    
    sqlite3_reset(session->set_revoke_contact_as_notified);
    sqlite3_bind_text(session->set_revoke_contact_as_notified, 1, revoke_fpr, -1, 
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_revoke_contact_as_notified, 2, contact_id, -1,
            SQLITE_STATIC);

    int result;
    
    result = Sqlite3_step(session->set_revoke_contact_as_notified);
    switch (result) {
        case SQLITE_DONE:
            status = PEP_STATUS_OK;
            break;
            
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }
    
    sqlite3_reset(session->set_revoke_contact_as_notified);
    return status;    
}


PEP_STATUS receive_key_reset(PEP_SESSION session,
                             message* reset_msg) {

    if (!session || !reset_msg)
        return PEP_ILLEGAL_VALUE;

    pEp_identity* sender_id = reset_msg->from;
                
    if (!sender_id)
        return PEP_MALFORMED_KEY_RESET_MSG;
        
    PEP_STATUS status = update_identity(session, sender_id);
    if (!sender_id->user_id)
        return PEP_UNKNOWN_ERROR;
        
    if (is_me(session, sender_id))
        return PEP_ILLEGAL_VALUE;    
        
    if (!reset_msg->longmsg || strncmp(reset_msg->longmsg, "OLD: ", 5) != 0) 
        return PEP_MALFORMED_KEY_RESET_MSG;

    status = PEP_STATUS_OK;
    char* old_fpr = NULL;
    char* new_fpr = NULL;
    
    stringlist_t* keylist = NULL;
    pEp_identity* temp_ident = identity_dup(sender_id);
    if (!temp_ident) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_free;
    }        
            
    char* rest = NULL;
    char* p = strtok_r(reset_msg->longmsg, "\r\n", &rest);
    if (!EMPTYSTR(p + 5))
        old_fpr = strdup(p + 5);
    else {
        status = PEP_MALFORMED_KEY_RESET_MSG;
        goto pEp_free;
    }
    
    bool own_key = false;
    status = is_own_key(session, old_fpr, &own_key);
    
    if (own_key) {
        // Nope, no one can make us our own default. If we want to do that,
        // that's keysync, NOT key reset.
        status = PEP_ILLEGAL_VALUE;
        goto pEp_free;
    }
            
    p = strtok_r(NULL, "\r\n", &rest); 
    if (strncmp(p, "NEW: ", 5) != 0  || EMPTYSTR(p + 5)) {
        status = PEP_MALFORMED_KEY_RESET_MSG;
        goto pEp_free;
    }

    new_fpr = strdup(p + 5);
        
    // Reset the original key
    status = key_reset(session, old_fpr, temp_ident);
    if (status != PEP_STATUS_OK)
        goto pEp_free;
        
    status = find_keys(session, new_fpr, &keylist);
    if (status != PEP_STATUS_OK)
        goto pEp_free;
        
    if (!keylist) {
        status = PEP_KEY_NOT_FOUND;
        goto pEp_free;
    }

    // alright, we've checked as best we can. Let's set that baby.
    sender_id->fpr = new_fpr;
    
    // This only sets as the default, does NOT TRUST IN ANY WAY
    sender_id->comm_type = sender_id->comm_type & (~PEP_ct_confirmed);
    status = set_identity(session, sender_id);
    
    sender_id->fpr = NULL; // ownership for free
pEp_free:    
    free_stringlist(keylist);    
    free(old_fpr);
    free(new_fpr);
    free_identity(temp_ident);
    return status;
}

PEP_STATUS create_standalone_key_reset_message(PEP_SESSION session,
                                               message** dst, 
                                               pEp_identity* recip,
                                               const char* old_fpr,
                                               const char* new_fpr) {
                                                   
    if (!dst || !recip->user_id || !recip->address)
        return PEP_ILLEGAL_VALUE;

    if (!old_fpr || !new_fpr)
        return PEP_ILLEGAL_VALUE;
        
    *dst = NULL;
    // Get own identity user has corresponded with
    pEp_identity* own_identity = NULL;
    
    PEP_STATUS status = get_own_ident_for_contact_id(session,
                                                     recip,
                                                     &own_identity);                                                       
    if (status != PEP_STATUS_OK)
        return status;
        
    message* reset_message = new_message(PEP_dir_outgoing);
    reset_message->from = own_identity;
    reset_message->to = new_identity_list(identity_dup(recip)); // ?
    
    const char* oldtag = "OLD: ";
    const char* newtag = "\nNEW: ";
    const size_t taglens = 11;
    size_t full_len = taglens + strlen(old_fpr) + strlen(new_fpr) + 2; // \n and \0
    char* longmsg = calloc(full_len, 1);
    strlcpy(longmsg, oldtag, full_len);
    strlcat(longmsg, old_fpr, full_len);
    strlcat(longmsg, newtag, full_len);
    strlcat(longmsg, new_fpr, full_len);
    strlcat(longmsg, "\n", full_len);
    reset_message->longmsg = longmsg; 
    reset_message->shortmsg = strdup("Key reset");    
    
    message* output_msg = NULL;
    
    status = encrypt_message(session, reset_message, NULL,
                             &output_msg, PEP_enc_PGP_MIME,
                             PEP_encrypt_flag_key_reset_only);

    if (status == PEP_STATUS_OK)
        *dst = output_msg;
        
    free_message(reset_message);
    return status;
}

PEP_STATUS send_key_reset_to_recents(PEP_SESSION session,
                                     const char* old_fpr, 
                                     const char* new_fpr) {
    assert(old_fpr);
    assert(new_fpr);
    assert(session);
    assert(session->messageToSend);
    
    if (!session || !old_fpr || !new_fpr)
        return PEP_ILLEGAL_VALUE;

    messageToSend_t send_cb = session->messageToSend;
    if (!send_cb)
        return PEP_SYNC_NO_MESSAGE_SEND_CALLBACK;
        
    identity_list* recent_contacts = NULL;
    message* reset_msg = NULL;

    PEP_STATUS status = get_last_contacted(session, &recent_contacts);
    
    if (status != PEP_STATUS_OK)
        goto pEp_free;
                    
    identity_list* curr_id_ptr = recent_contacts;

    for (curr_id_ptr = recent_contacts; curr_id_ptr; curr_id_ptr = curr_id_ptr->next) {
        pEp_identity* curr_id = curr_id_ptr->ident;
        
        if (!curr_id)
            break;
    
        const char* user_id = curr_id->user_id;
        
        // Should be impossible, but?
        if (!user_id)
            continue;
        
        // Check if it's us - if so, pointless...
        if (is_me(session, curr_id))
            continue;
            
        // Check if they've already been told - this shouldn't be the case, but...
        bool contacted = false;
        status = has_key_reset_been_sent(session, user_id, old_fpr, &contacted);
        if (status != PEP_STATUS_OK)
            goto pEp_free;
    
        if (contacted)
            continue;
            
        // if not, make em a message    
        reset_msg = NULL;
        
        status = create_standalone_key_reset_message(session,
                                                     &reset_msg,
                                                     curr_id,
                                                     old_fpr,
                                                     new_fpr);

        if (status == PEP_CANNOT_FIND_IDENTITY) { // this is ok, just means we never mailed them 
            status = PEP_STATUS_OK;
            continue; 
        }
            
        if (status != PEP_STATUS_OK) {
            free(reset_msg);
            goto pEp_free;
        }
        
        // insert into queue
        status = send_cb(reset_msg);

        if (status != PEP_STATUS_OK) {
            free(reset_msg);
            goto pEp_free;            
        }
            
        // Put into notified DB
        status = set_reset_contact_notified(session, old_fpr, user_id);
        if (status != PEP_STATUS_OK)
            goto pEp_free;            
    }
    
pEp_free:
    free_identity_list(recent_contacts);
    return status;
}

DYNAMIC_API PEP_STATUS key_reset_identity(
        PEP_SESSION session,
        pEp_identity* ident,
        const char* fpr        
    )
{
    if (!session || !ident || (ident && (EMPTYSTR(ident->user_id) || EMPTYSTR(ident->address))))
        return PEP_ILLEGAL_VALUE;
    
    return key_reset(session, fpr, ident);    
}

DYNAMIC_API PEP_STATUS key_reset_user(
        PEP_SESSION session,
        const char* user_id,
        const char* fpr        
    )
{
    if (!session || EMPTYSTR(user_id))
        return PEP_ILLEGAL_VALUE;

    pEp_identity* input_ident = new_identity(NULL, NULL, user_id, NULL);
    if (!input_ident)
        return PEP_OUT_OF_MEMORY;
        
    if (is_me(session, input_ident) && EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = key_reset(session, fpr, input_ident);
    free_identity(input_ident);
    return status;
}

DYNAMIC_API PEP_STATUS key_reset_all_own_keys(PEP_SESSION session) {
    return key_reset(session, NULL, NULL);
}

// Notes to integrate into header:
// IF there is an ident, it must have a user_id.
PEP_STATUS key_reset(
        PEP_SESSION session,
        const char* key_id,
        pEp_identity* ident
    )
{
    if (!session || (ident && EMPTYSTR(ident->user_id)))
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = PEP_STATUS_OK;
        
    char* fpr_copy = NULL;
    char* own_id = NULL;
    char* user_id = NULL;
    char* new_key = NULL;
    pEp_identity* tmp_ident = NULL;
    identity_list* key_idents = NULL;
    stringlist_t* keys = NULL;
    
    if (!EMPTYSTR(key_id)) {
        fpr_copy = strdup(key_id);
        if (!fpr_copy)
            return PEP_OUT_OF_MEMORY;
    }

    // This is true when we don't have a user_id and address and the fpr isn't specified
    bool reset_all_for_user = !fpr_copy && (!ident || EMPTYSTR(ident->address));

    // FIXME: does this need to be done everywhere?> I think not.
    if (ident) {
        user_id = strdup(ident->user_id);
        if (!user_id) {
            status = PEP_OUT_OF_MEMORY;
            goto pEp_free;
        }
    }
    else {
        status = get_default_own_userid(session, &user_id);
        if (status != PEP_STATUS_OK || !user_id)
            goto pEp_free;                    
    }
    
    // FIXME: Make sure this can't result in a double-free in recursive calls
    tmp_ident = (ident ? identity_dup(ident) : new_identity(NULL, NULL, user_id, NULL));
    
    if (reset_all_for_user) {
        status = get_all_keys_for_user(session, user_id, &keys);
        // TODO: free
        if (status == PEP_STATUS_OK) {
            stringlist_t* curr_key;
            
            for (curr_key = keys; curr_key && curr_key->value; curr_key = curr_key->next) {
                // FIXME: Is the ident really necessary?
                status = key_reset(session, curr_key->value, tmp_ident);
                if (status != PEP_STATUS_OK)
                    break;
            }
        }
        goto pEp_free;
    }                   
    else {
        // tmp_ident => tmp_ident->user_id (was checked)
        //
        // !(EMPTYSTR(fpr) && (!tmp_ident || EMPTYSTR(tmp_ident->address)))
        // => fpr || (tmp_ident && tmp_ident->address)
        //
        // so: We have an fpr or we have an ident with user_id and address
        //     or both
        if (!fpr_copy) {
            // We are guaranteed to have an ident w/ id + addr here.
            // Get the default key.
            pEp_identity* stored_ident = NULL;
            status = get_identity(session, tmp_ident->address, 
                                  tmp_ident->user_id, &stored_ident);

            // FIXME FIXME FIXME
            if (status == PEP_STATUS_OK) {
                // transfer ownership
                fpr_copy = stored_ident->fpr;
                stored_ident->fpr = NULL;
                free_identity(stored_ident);                
            }
            
            if (!fpr_copy || status == PEP_CANNOT_FIND_IDENTITY) {
                // There's no identity default. Try resetting user default
                status = get_user_default_key(session, tmp_ident->user_id, &fpr_copy);
            }            
            
            if (!fpr_copy || status != PEP_STATUS_OK) // No default to free. We're done here.
                goto pEp_free;            
        }
        
        // Ok - now we have at least an ident with user_id and an fpr.
        // Now it matters if we're talking about ourselves or a partner.
        bool is_own_private = false;
        if (is_me(session, tmp_ident)) {
            bool own_key = false;            
            status = is_own_key(session, fpr_copy, &own_key);

            if (status != PEP_STATUS_OK)
                goto pEp_free;
            if (!own_key) {
                status = PEP_ILLEGAL_VALUE;
                goto pEp_free;
            }

            status = contains_priv_key(session, fpr_copy, &is_own_private);
            if (status != PEP_STATUS_OK && status != PEP_KEY_NOT_FOUND)
                goto pEp_free;
        }
        
        // Up to this point, we haven't cared about whether or not we 
        // had a full identity. Now we have to deal with that in the 
        // case of own identities with private keys.
        
        if (is_own_private) {
            
            // If there's no address, we want to reset this key for every identity 
            // it's a part of. Since this means generating new keys, we have to 
            // grab all the identities associated with it.
            if (EMPTYSTR(tmp_ident->address)) {
                status = get_identities_by_main_key_id(session, fpr_copy, &key_idents);
                
                if (status != PEP_CANNOT_FIND_IDENTITY) {
                    if (status == PEP_STATUS_OK) {
                        // now have ident list, or should
                        identity_list* curr_ident;
                        
                        for (curr_ident = key_idents; curr_ident && curr_ident->ident; 
                                                        curr_ident = curr_ident->next) {
                            
                            pEp_identity* this_identity = curr_ident->ident;
                            // Do the full reset on this identity        
                            status = key_reset(session, fpr_copy, this_identity);
                            
                            // Ident list gets freed below, do not free here!

                            if (status != PEP_STATUS_OK)
                                break;
                            
                        }
                    }
                    // Ok, we've either now reset for each own identity with this key, or 
                    // we got an error and want to bail anyway.
                    goto pEp_free;
                }    
            }
            
            // Create revocation
            status = revoke_key(session, fpr_copy, NULL);
            
            // If we have a full identity, we have some cleanup and generation tasks here
            if (!EMPTYSTR(tmp_ident->address)) {
                // generate new key
                if (status == PEP_STATUS_OK) {
                    tmp_ident->fpr = NULL;
                    status = generate_keypair(session, tmp_ident);
                }
                if (status == PEP_STATUS_OK) {
                    new_key = strdup(tmp_ident->fpr);
                    status = set_own_key(session, tmp_ident, new_key);
                }
                // mistrust fpr from trust
                tmp_ident->fpr = fpr_copy;
                
                tmp_ident->comm_type = PEP_ct_mistrusted;
                status = set_trust(session, tmp_ident);
                tmp_ident->fpr = NULL;
                
                // Done with old use of ident.
                if (status == PEP_STATUS_OK) {
                    // Update fpr for outgoing
                    status = myself(session, tmp_ident);
                }
            }    
            
            if (status == PEP_STATUS_OK)
                // cascade that mistrust for anyone using this key
                status = mark_as_compromised(session, fpr_copy);
                
            if (status == PEP_STATUS_OK)
                status = remove_fpr_as_default(session, fpr_copy);
            if (status == PEP_STATUS_OK)
                status = add_mistrusted_key(session, fpr_copy);

            // If there's a new key, do the DB linkage with the revoked one, and 
            // send the key reset mail opportunistically to recently contacted
            // partners
            if (new_key) {
                // add to revocation list 
                if (status == PEP_STATUS_OK) 
                    status = set_revoked(session, fpr_copy, new_key, time(NULL));            
                // for all active communication partners:
                //      active_send revocation
                if (status == PEP_STATUS_OK)
                    status = send_key_reset_to_recents(session, fpr_copy, new_key);        
            }        
        } // end is_own_private
        else {
            // This is a public key (or a private key that isn't ours, which means
            // we want it gone anyway)
            //
            // Delete this key from the keyring.
            status = delete_keypair(session, fpr_copy);
        }

        // REGARDLESS OF WHO OWNS THE KEY, WE NOW NEED TO REMOVE IT AS A DEFAULT.
        PEP_STATUS cached_status = status;
        // remove fpr from all identities
        // remove fpr from all users
        status = remove_fpr_as_default(session, fpr_copy);
        // delete key from DB - this does NOT touch the keyring!
        // Note: for own priv keys, we cannot do this. But we'll never encrypt to/from it.
        if (status == PEP_STATUS_OK && !is_own_private) {
            status = remove_key(session, fpr_copy);
        }
        if (status == PEP_STATUS_OK)
            status = cached_status;
    }           
        
pEp_free:
    if (!ident)
        free_identity(tmp_ident);
    free(fpr_copy);
    free(own_id);
    free_identity_list(key_idents);
    free_stringlist(keys);
    free(new_key);    
    return status;
}
