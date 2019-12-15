// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "dynamic_api.h"
#include "message_api.h"
#include "key_reset.h"
#include "distribution_codec.h"
#include "map_asn1.h"
#include "../asn.1/Distribution.h"

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
    int result = sqlite3_step(session->was_id_for_revoke_contacted);
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
    
    result = sqlite3_step(session->set_revoke_contact_as_notified);
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
    status = key_reset(session, old_fpr, temp_ident, NULL, NULL);
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
    
    char* key_data = NULL;
    size_t* key_data_size = 0;
    status = export_key(session, old_fpr, &key_data, &key_data_size);
    if (status || !key_data || !key_data_size)
        return PEP_KEY_NOT_FOUND;

    bloblist_t* bl = NULL;
    
    // Better add old revoked key 
    status = package_key_attachment(key_data, 
                                    key_data_size,
                                    "file://revoked.key", 
                                    &bl);   

    if (!bl)
        status = PEP_OUT_OF_MEMORY;

    key_data = NULL;
        
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
    
    return key_reset(session, fpr, ident, NULL, NULL);    
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
        
    PEP_STATUS status = key_reset(session, fpr, input_ident, NULL, NULL);
    free_identity(input_ident);
    return status;
}

DYNAMIC_API PEP_STATUS key_reset_all_own_keys(PEP_SESSION session) {
    return key_reset(session, NULL, NULL, NULL, NULL);
}

// Notes to integrate into header:
// IF there is an ident, it must have a user_id.
PEP_STATUS key_reset(
        PEP_SESSION session,
        const char* key_id,
        pEp_identity* ident,
        identity_list** own_identities,
        stringlist_t** own_revoked_fprs
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
                status = key_reset(session, curr_key->value, tmp_ident, own_identities, own_revoked_fprs);
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
                            status = key_reset(session, fpr_copy, this_identity, own_identities, own_revoked_fprs);
                            
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
            
            // Base case for is_own_private starts here
            
            status = revoke_key(session, fpr_copy, NULL);
            
            // If we have a full identity, we have some cleanup and generation tasks here
            if (!EMPTYSTR(tmp_ident->address)) {
                // generate new key
                if (status == PEP_STATUS_OK) {
                    tmp_ident->fpr = NULL;
                    status = myself(session, tmp_ident);
                }
                if (status == PEP_STATUS_OK && tmp_ident->fpr && strcmp(fpr_copy, tmp_ident->fpr) != 0) {
                    new_key = strdup(tmp_ident->fpr);
//                    status = set_own_key(session, tmp_ident, new_key);
                }

                if (own_revoked_fprs) {
                    // We can dedup this later
                    if (!(*own_revoked_fprs))
                        *own_revoked_fprs = new_stringlist(NULL);
                    
                    char* revkey = strdup(fpr_copy);
                    if (!revkey) {
                        status = PEP_OUT_OF_MEMORY;
                        goto pEp_free;
                    }
                    stringlist_add(*own_revoked_fprs, revkey);                
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
                
                if (status == PEP_STATUS_OK && own_identities) {
                    if (!(*own_identities))
                        *own_identities = new_identity_list(NULL);
                    
                    pEp_identity* new_ident = identity_dup(tmp_ident);
                    if (!new_ident) {
                        status = PEP_OUT_OF_MEMORY;
                        goto pEp_free;
                    }
                    identity_list_add(*own_identities, new_ident);            
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
            // if it's mistrusted, make it not be so.
            bool mistrusted_key = false;
            is_mistrusted_key(session, fpr_copy, &mistrusted_key);

            if (mistrusted_key)
                delete_mistrusted_key(session, fpr_copy);
            
            if (tmp_ident->user_id)
                status = clear_trust_info(session, tmp_ident->user_id, fpr_copy);

            // This is a public key (or a private key that isn't ours, which means
            // we want it gone anyway)
            //
            // Delete this key from the keyring.
            // FIXME: when key election disappears, so should this!
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

PEP_STATUS initiate_group_key_reset(PEP_SESSION session, 
                                    keyreset_command_list** commands,
                                    stringlist_t** new_key_material) {
    
    if (!session || !old_new_fpr_pairs || !new_keys)
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = get_all_keys_for_user(session, user_id, &keys);

    if (!status)
        return status;
    
    keyreset_command_list* new_cmd_list = new_keyreset_command_list(NULL);
        
    // TODO: free
    stringlist_t* curr_key;
    
    for (curr_key = keys; curr_key && curr_key->value; curr_key = curr_key->next) {
        char* curr_fpr = curr_key->value;
        status = get_identities_by_main_key_id(session, curr_key->value, &key_idents);
                    
        if (status != PEP_CANNOT_FIND_IDENTITY) {
            if (status == PEP_STATUS_OK) {
                                
                // now have ident list, or should
                identity_list* curr_ident;
                for (curr_ident = key_idents; curr_ident && curr_ident->ident; 
                                  curr_ident = curr_ident->next) {
                
                    pEp_identity* this_identity = curr_ident->ident;
                    
                    // 0. Make sure this is a group key to begin with
                    if (!(curr_ident->flags & PEP_idf_devicegroup))
                        continue;

                    // 1. Preserve this sad old identity so we can look on it 
                    //    fondly later and tell people who needs to replace what 
                    pEp_identity* replacement_id = identity_dup(curr_ident->ident);
                        
                    if (!replacement_id)
                        return PEP_OUT_OF_MEMORY;
                        
                    // 2. Get this identity a new key, woman! (ROAR!)
                    status = generate_keypair(session, this_identity);
                    
                    if (!status)
                        return status;
                        
                    char* new_fpr = strdup(this_identity->fpr);
                    if (!new_fpr)
                        return PEP_OUT_OF_MEMORY;
                        
                    // 3. bind the old and new
                    keyreset_command* new_cmd = new_keyreset_command(replacement_id, new_fpr);
                    if (!new_cmd)
                        return PEP_OUT_OF_MEMORY;
                        
                    keyreset_command_list_add(new_cmd_list, new_cmd);    
                    
                    // 4. Get the new key material
                    char* keydata = NULL;
                    size_t keysize = 0;

                    status = export_key(session, this_identity->fpr, &keydata, &keysize);
                    if (!status)
                        return status;
                        
                    if (keydata)
                        stringlist_add(new_keys, keydata);
                    
                    status = export_secret_key(session, this_identity->fpr, &keydata, &keysize);
                    if (!status)
                        return status;
                        
                    if (keydata)
                        stringlist_add(new_keys, keydata);
                    
                    // on to the next identity for this key
                        
                } // end loop through idents for this key
            } // end if identities found without error 
        } // end if identitiies found for current key
    } // end loop through keys  
    
    // Ok - we have it all. Now, let's package up the message and put 
    // it into the queue.
    message* grp_reset_msg = NULL;
    status = create_group_key_reset_message(session, 
                                            &grp_reset_msg, 
                                            new_cmd_list,
                                            new_keys); // ??
    
    // Ok, here's the real fun - now we have to revoke for each 
    // identity, set the replacement, and notify.
    
    keyreset_command_list* curr_cmd = new_cmd_list;
    for ( ; curr_cmd && curr_cmd->command; curr_cmd = curr_cmd->next) {
        pEp_identity* ident = curr_cmd->command->ident;

        // 1. Revoke 
        status = revoke_key(session, ident->fpr, NULL);

        // 2. record replacement 
        if (status == PEP_STATUS_OK) 
            status = set_revoked(session, ident->fpr, ident->new_key, time(NULL));            
    
        // 3. send revocation for recent partners
        if (status == PEP_STATUS_OK)
            status = send_key_reset_to_recents(session, ident->fpr, ident->new_key);            
    }
    
    return status;
}

PEP_STATUS create_group_key_reset_message(PEP_SESSION session,
                                          message** dst, 
                                          keyreset_command_list* commands,
                                          stringlist_t* new_key_material) {
                                                   
    if (!dst || !commands || !new_key_material)
        return PEP_ILLEGAL_VALUE;

    if (!commands->command || !commands->command->ident)
        return PEP_ILLEGAL_VALUE;
        
    *dst = NULL;

    // the keyreset_command_list contains own grouped identities - we 
    // only need to take one, so we arbitrarily take the first.
    
    // Get own identity user has corresponded with
    pEp_identity* own_identity = identity_dup(commands->command->ident);

    if (!own_identity)
        return PEP_OUT_OF_MEMORY;
        
    message* reset_message = new_message(PEP_dir_outgoing);
    reset_message->from = own_identity;
    reset_message->to = new_identity_list(identity_dup(own_identity)); // ?
    
    reset_message->shortmsg = strdup("p≡p key reset message - please ignore");
    assert(msg->shortmsg);
    if (!msg->shortmsg)
        goto enomem;

    reset_message->longmsg = strdup("This message is part of p≡p's key reset protocol.\n\n"
                                    "You can safely ignore it. It will be deleted automatically.\n");

    add_opt_field(reset_message, "pEp-auto-consume", "yes");
    msg->in_reply_to = stringlist_add(reset_message->in_reply_to, "pEp-auto-consume@pEp.foundation");

    assert(reset_message->longmsg);
    if (!reset_message->longmsg)
        goto enomem;

    // Add keys
    stringlist_t* sl = *new_key_material;
    char* keydata = calloc(1,1);
    size_t key_data_size = 1;
    
    while (sl && sl->value) {
        char *_key_data = sl->value;
        assert(_key_data);
        if (!_key_data)
            return PEP_ILLEGAL_VALUE;
            
        size_t _size = strlen(_key_data);
        assert(_size);
            
        // We take ownership of the key material and remove the node.
        char *n = realloc(key_data, key_data_size + _size);
        if (!n)
            return PEP_OUT_OF_MEMORY;
    
        key_data = n;
        key_data_size += _size;
        strlcat(key_data, _key_data, key_data_size);

        stringlist_t* tmp = sl;
        sl = sl->next;
        tmp->next = NULL;
        stringlist_delete(tmp);            
    }    
    
    bloblist_t* bl = NULL;
    status = package_key_attachment(key_data, 
                                    key_data_size,
                                    "file://groupreset.key", 
                                    &bl);   
                                        
    if (!bl)
        status = PEP_OUT_OF_MEMORY;

    reset_message->attachments = bl;

    key_data = NULL;

    // Add identities 
    char* payload = NULL;
    size_t size = 0;
    
    status = key_reset_commands_to_PER(commands, &payload, &size);    
    if (!status)
        return status;
        
    if (commands && (!payload || size = 0))
        return PEP_UNKNOWN_ERROR;
        
    bl = bloblist_add(reset_message->attachments, payload, size,
                      "application/pEp.keyreset", "ignore_this_attachment.pEp");
            
    message* output_msg = NULL;
    
    status = encrypt_message(session, reset_message, NULL,
                             &output_msg, PEP_enc_PGP_MIME,
                             PEP_encrypt_flag_group_key_reset);

    if (status == PEP_STATUS_OK)
        *dst = output_msg;
        
    free_message(reset_message);
    
    return status;
}

PEP_STATUS process_group_key_reset(PEP_SESSION session, 
                                   keyreset_command_list* commands) {
    if (!session || !old_idents || !new_keys)
        return PEP_ILLEGAL_VALUE;

    char* user_id = NULL;
    PEP_STATUS status = get_default_own_userid(session, &user_id);
    if (status != PEP_STATUS_OK || !user_id)
        goto pEp_free;   
    
    // identity_list* curr_ident = old_idents;
    // stringlist_t* curr_fpr = new_keys;

    keyreset_command_list* curr_cmd = commands;
    
    for ( ; curr_cmd && curr_cmd->command; curr_ident = curr_cmd->next) {
        keyreset_command* command = curr_cmd->command;
        if (!command->ident || !command->new_key)
            return PEP_UNKNOWN_ERROR;
            
        pEp_identity* this_id = command->ident;
        pEp_identity* this_key = command->new_key;
            
        // 0. check that we even have this identity and the new key
        bool ident_exists = NULL;
        status = exists_identity(session, this_id, &ident_exists);
        
        if (status)
            return status;
            
        if (!ident_exists)
            continue;
        
        stringlist_t* keylist = NULL;
        status = find_key(session, this_key, &keylist);
        if (status)
            return status;
        if (!keylist)
            return PEP_KEY_NOT_FOUND;
        
        // 1. replace its main key (what other checks do we want?)
        status = replace_fpr_for_identity(session, user_id, address, this_key);

        if (!status)
            return status;
            
        // 2. ???
        
        // 3. revoke old key
        status = revoke_key(session, this_id->fpr, NULL);
                                                    
        this_id->comm_type = PEP_ct_mistrusted;
        status = set_trust(session, this_id);
                    
        if (status == PEP_STATUS_OK)
            // cascade that mistrust for anyone using this key
            status = mark_as_compromised(session, this_key);
                
        if (status == PEP_STATUS_OK)
            status = remove_fpr_as_default(session, this_key);
        if (status == PEP_STATUS_OK)
            status = add_mistrusted_key(session, this_key);

        // add to revocation list 
        if (status == PEP_STATUS_OK) 
            status = set_revoked(session, this_key, new_key, time(NULL));            
        
        // 4. Profit!
    }           
    return commands;
}

/*
PEP_STATUS key_reset_own_and_deliver_revocations(PEP_SESSION session, 
                                                 identity_list** own_identities, 
                                                 stringlist_t** revocations, 
                                                 stringlist_t** keys) {

    if (!(session && own_identities && revocations && keys))
        return PEP_ILLEGAL_VALUE;
        
    stringlist_t* revoked_fprs = NULL;
    identity_list* affected_idents = NULL;
        
    PEP_STATUS status = key_reset(session, NULL, NULL, &affected_idents, &revoked_fprs);                                                 

    // FIXME: free things
    if (status != PEP_STATUS_OK)
        return status;
    
    dedup_stringlist(revoked_fprs);

    *revocations = collect_key_material(session, revoked_fprs);
    stringlist_t* keydata = NULL;
    
    if (affected_idents) {
        keydata = new_stringlist(NULL);
        identity_list* curr_ident = affected_idents;
        while (curr_ident) {
            if (curr_ident->ident && curr_ident->ident->fpr) {
                char* key_material = NULL;
                size_t datasize = 0;
                status = export_private_keys(session, curr_ident->ident->fpr, &key_material, &datasize);
                if (status) {
                    free_stringlist(keydata);
                    return status;
                }
                if (datasize > 0 && key_material)
                    stringlist_add(keydata, key_material);
            }
            curr_ident = curr_ident->next;
        }
    }
    
    *own_identities = affected_idents;
    *keys = keydata;
    
    free(revoked_fprs);
    return PEP_STATUS_OK;
}
*/

Distribution_t *Distribution_from_keyreset_command_list(
        const keyreset_command_list *command_list,
        Distribution_t *dist
    )
{
    bool allocated = !dist;

    assert(command_list);
    if (!command_list)
        return NULL;

    if (allocated)
        dist = (Distribution_t *) calloc(1, sizeof(Distribution_t));

    assert(dist);
    if (!dist)
        goto enomem;

    dist->present = Distribution_PR_keyreset;
    dist->choice.keyreset.present = KeyReset_PR_commands;

    for (const keyreset_command_list *cl = command_list; cl && cl->command; cl = cl->next) {
        Command_t *c = (Command_t *) calloc(1, sizeof(Command_t));
        assert(c);
        if (!c)
            goto enomem;

        if (!Identity_from_Struct(cl->command->ident, &c->ident)) {
            free(c);
            goto enomem;
        }

        if (OCTET_STRING_fromString(&c->newkey, cl->command->new_key)) {
            ASN_STRUCT_FREE(asn_DEF_Command, c);
            goto enomem;
        }

        if (ASN_SEQUENCE_ADD(&dist->choice.keyreset.choice.commands.commandlist, c)) {
            ASN_STRUCT_FREE(asn_DEF_Command, c);
            goto enomem;
        }
    }

    return dist;

enomem:
    ASN_STRUCT_FREE(asn_DEF_Distribution, dist);
    return NULL;
}

PEP_STATUS key_reset_commands_to_PER(const keyreset_command_list *command_list, char **cmds, size_t *size)
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(command_list && cmds);
    if (!(command_list && cmds))
        return PEP_ILLEGAL_VALUE;

    *cmds = NULL;
    *size = 0;

    // convert from pEp engine struct

    Distribution_t *dist = Distribution_from_keyreset_command_list(command_list, NULL);
    assert(dist);
    if (!dist)
        goto enomem;

    // encode

    char *_cmds;
    size_t _size;
    status = encode_Distribution_message(dist, &_cmds, &_size);
    if (status)
        goto the_end;

    // return result

    *cmds = _cmds;
    *size = _size;
    goto the_end;

enomem:
    status = PEP_OUT_OF_MEMORY;

the_end:
    ASN_STRUCT_FREE(asn_DEF_Distribution, dist);
    return status;
}

keyreset_command_list * Distribution_to_keyreset_command_list(
        Distribution_t *dist,
        keyreset_command_list *command_list
    )
{
    bool allocated = !command_list;

    assert(dist);
    if (!dist)
        return NULL;

    if (allocated)
        command_list = new_keyreset_command_list(NULL);
    if (!command_list)
        goto enomem;

    struct Commands__commandlist *cl = &dist->choice.keyreset.choice.commands.commandlist;
    keyreset_command_list *_result = command_list;
    for (int i=0; i<cl->list.count; i++) {
        pEp_identity *ident = Identity_to_Struct(&cl->list.array[i]->ident, NULL);
        if (!ident)
            goto enomem;

        const char *new_key = (const char *) cl->list.array[i]->newkey.buf;

        keyreset_command *command = new_keyreset_command(ident, new_key);
        if (!command) {
            free_identity(ident);
            goto enomem;
        }

        _result = keyreset_command_list_add(_result, command);
        free_identity(ident);
        if (!_result)
            goto enomem;
    }

    return command_list;

enomem:
    if (allocated)
        free_keyreset_command_list(command_list);
    return NULL;
}

PEP_STATUS PER_to_key_reset_commands(const char *cmds, size_t size, keyreset_command_list **command_list)
{
    assert(command_list && cmds);
    if (!(command_list && cmds))
        return PEP_ILLEGAL_VALUE;

    *command_list = NULL;

    // decode

    Distribution_t *dist = NULL;
    PEP_STATUS status = decode_Distribution_message(cmds, size, &dist);
    if (status)
        goto the_end;

    // check if these are key reset commands or not

    assert(dist && dist->present == Distribution_PR_keyreset
            && dist->choice.keyreset.present == KeyReset_PR_commands);

    if (!(dist && dist->present == Distribution_PR_keyreset
            && dist->choice.keyreset.present == KeyReset_PR_commands)) {
        status = PEP_ILLEGAL_VALUE;
        goto the_end;
    }

    // convert to pEp engine struct

    keyreset_command_list *result = Distribution_to_keyreset_command_list(dist, NULL);
    if (!result)
        goto enomem;

    // return result

    *command_list = result;
    goto the_end;

enomem:
    status = PEP_OUT_OF_MEMORY;
    free_keyreset_command_list(result);

the_end:
    ASN_STRUCT_FREE(asn_DEF_Distribution, dist);
    return status;
}
