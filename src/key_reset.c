// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "dynamic_api.h"
#include "message_api.h"
#include "key_reset.h"
#include "distribution_codec.h"
#include "map_asn1.h"
#include "keymanagement.h"
#include "baseprotocol.h"
#include "../asn.1/Distribution.h"
#include "Sync_impl.h" // this seems... bad

#include <string.h>
#include <stdlib.h>

// FIXME: these should be taken from sync/Distribution.fsm

#define KEY_RESET_MAJOR_VERSION 1L
#define KEY_RESET_MINOR_VERSION 0L

static PEP_STATUS _generate_keyreset_command_message(PEP_SESSION session,
                                                     const pEp_identity* from_ident,
                                                     const pEp_identity* to_ident,
                                                     const char* old_fpr,
                                                     const char* new_fpr,
                                                     bool is_private,
                                                     message** dst) {
                                                                                                                  
    if (!session || !from_ident || !old_fpr || !new_fpr || !dst)
        return PEP_ILLEGAL_VALUE;

    // safe cast
    if (!is_me(session, (pEp_identity*)from_ident))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
        
    *dst = NULL;
    
    stringlist_t* keydata = NULL;
    
    message* msg = NULL;
    
    // Ok, generate payload here...
    pEp_identity* outgoing_ident = identity_dup(from_ident);
    if (!outgoing_ident)
        return PEP_OUT_OF_MEMORY;
    free(outgoing_ident->fpr);
    outgoing_ident->fpr = strdup(old_fpr);
    if (!outgoing_ident->fpr)
        return PEP_OUT_OF_MEMORY;
        
    // Need payload now
    keyreset_command* kr_command = new_keyreset_command(outgoing_ident, new_fpr);
    keyreset_command_list* kr_list = new_keyreset_command_list(kr_command);
    char* payload = NULL;
    size_t size = 0;
    status = key_reset_commands_to_PER(kr_list, &payload, &size);
    status = base_prepare_message(session, outgoing_ident, to_ident,
                                  BASE_KEYRESET, payload, size, NULL,
                                  &msg);
    if (status) {
        free(msg);
        return status;
    }    
    if (!msg)
        return PEP_OUT_OF_MEMORY;
    if (!msg->attachments)
        return PEP_UNKNOWN_ERROR;
    
    char* key_material = NULL;
    size_t datasize = 0;
    status = export_key(session, new_fpr, &key_material, &datasize);

    if (datasize > 0 && key_material) { 
        if (status) {
            free_stringlist(keydata);
            return status;
        }
        stringlist_add(keydata, key_material);
                        
        key_material = NULL;
        datasize = 0;    
        if (is_private) {
            status = export_secret_key(session, new_fpr, &key_material, &datasize);    
            if (status) {
                free_stringlist(keydata);
                return status;
            }
            if (datasize > 0 && key_material)
                stringlist_add(keydata, key_material);
        }    
    }    
    // Attach to message
    stringlist_t* curr_key = keydata;
    for ( ; curr_key && curr_key->value; curr_key = curr_key->next) {
        bloblist_add(msg->attachments, curr_key->value, size, "application/pgp-keys",
                                                              "file://pEpkey.asc");
    }
    if (msg)
        *dst = msg;
    return status;
}

PEP_STATUS has_key_reset_been_sent(
        PEP_SESSION session, 
        const char* from_addr,
        const char* user_id, 
        const char* revoked_fpr,
        bool* contacted)
{
    assert(session);
    assert(contacted);
    assert(user_id);
    assert(revoked_fpr);
    assert(!EMPTYSTR(user_id));

    if (!session || !contacted || EMPTYSTR(from_addr) || EMPTYSTR(revoked_fpr) || EMPTYSTR(user_id))
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
    sqlite3_bind_text(session->was_id_for_revoke_contacted, 2, from_addr, -1,
            SQLITE_STATIC);        
    sqlite3_bind_text(session->was_id_for_revoke_contacted, 3, user_id, -1,
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

PEP_STATUS set_reset_contact_notified(
        PEP_SESSION session,
        const char* own_address,
        const char* revoke_fpr,
        const char* contact_id
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session && !EMPTYSTR(own_address) && !EMPTYSTR(revoke_fpr) && !EMPTYSTR(contact_id));
    
    if (!session || EMPTYSTR(own_address) || EMPTYSTR(revoke_fpr) || EMPTYSTR(contact_id))
        return PEP_ILLEGAL_VALUE;
    
    sqlite3_reset(session->set_revoke_contact_as_notified);
    sqlite3_bind_text(session->set_revoke_contact_as_notified, 1, revoke_fpr, -1, 
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_revoke_contact_as_notified, 2, own_address, -1, 
            SQLITE_STATIC);            
    sqlite3_bind_text(session->set_revoke_contact_as_notified, 3, contact_id, -1,
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

// FIXME: fpr ownership
PEP_STATUS receive_key_reset(PEP_SESSION session,
                             message* reset_msg) {

    if (!session || !reset_msg || !reset_msg->_sender_fpr)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    stringlist_t* keylist = NULL;
    
    char* sender_fpr = reset_msg->_sender_fpr;

    bool revoked = false;

    // Check to see if sender fpr is revoked already - if this was 
    // from us, we won't have done it yet for obvious reasons (i.e. 
    // we need to verify it's from us before we accept someone telling
    // us to reset our private key), and if this was from someone else,
    // a key reset message will be signed by their new key, because 
    // we presume the old one was compromised (and we remove trust from 
    // the replacement key until verified)
    status = key_revoked(session, sender_fpr, &revoked); 
    
    if (status != PEP_STATUS_OK)
        return status;

    // Bail if revoked
    if (revoked) {
        return PEP_ILLEGAL_VALUE; // could be an attack            
    }
    // Otherwise, bail
    else {
        bool mistrusted = false;
        status = is_mistrusted_key(session, sender_fpr, &mistrusted);
        
        if (status != PEP_STATUS_OK)
            return status;
        
        if (mistrusted)
            return PEP_ILLEGAL_VALUE;
    }

    
    // Parse reset message
    
    pEp_identity* sender_id = reset_msg->from;
                            
    if (!sender_id)
        return PEP_MALFORMED_KEY_RESET_MSG;

    if (is_me(session, sender_id)) {
        // first off, we need to make sure we're up-to-date
        status = myself(session, sender_id);        
    }
    else {    
        status = update_identity(session, sender_id);
        if (!sender_id->user_id)
            return PEP_UNKNOWN_ERROR;
    }
    
    bool sender_own_key = false;
    bool from_me = is_me(session, sender_id);
    
    if (is_me(session, sender_id)) {
        // Do own-reset-checks
        status = is_own_key(session, sender_fpr, &sender_own_key);
        
        if (status != PEP_STATUS_OK)
            return status;
        
        // Should we mistrust the sender_fpr here??
        if (!sender_own_key) 
            return PEP_ILLEGAL_VALUE; // actually, this is an attack                
        
        // Make sure it's a TRUSTED own key
        char* keyholder = sender_id->fpr;
        
        sender_id->fpr = sender_fpr;                     
        status = get_trust(session, sender_id);
        sender_id->fpr = keyholder;
            
        if (sender_id->comm_type < PEP_ct_pEp)
            return PEP_ILLEGAL_VALUE;
    }
        
    status = PEP_STATUS_OK;
    char* old_fpr = NULL;
    char* new_fpr = NULL;
    
    size_t size = 0;
    const char* payload = NULL;

    char* not_used_fpr = NULL;
    status = base_extract_message(session,
                                  reset_msg,
                                  BASE_KEYRESET,
                                  &size,
                                  &payload,
                                  &not_used_fpr);
                                  
    if (status != PEP_STATUS_OK)
        return status;
        
    if (!payload || size == 0)
        return PEP_MALFORMED_KEY_RESET_MSG;
        
    keyreset_command_list* resets = NULL; 
    
    status = PER_to_key_reset_commands(payload, size, &resets);

    if (status != PEP_STATUS_OK)
        return status;
        
    if (!resets)
        return PEP_MALFORMED_KEY_RESET_MSG;

    keyreset_command_list* curr_cl = resets;

    // Ok, go through the list of reset commands. Right now, this 
    // is actually only one, but could be more later.
    for ( ; curr_cl && curr_cl->command; curr_cl = curr_cl->next) {    
        keyreset_command* curr_cmd = curr_cl->command;
        if (!curr_cmd || !curr_cmd->ident || !curr_cmd->ident->fpr ||
            !curr_cmd->ident->address) {
            return PEP_MALFORMED_KEY_RESET_MSG;        
        }
        pEp_identity* curr_ident = curr_cmd->ident;
        
        old_fpr = curr_ident->fpr;
        new_fpr = curr_cmd->new_key;

        // Make sure that this key is at least one we associate 
        // with the sender. FIXME: check key election interaction
        // N.B. If we ever allow ourselves to send resets to ourselves
        // for not-own stuff, this will have to be revised
        
        status = find_keys(session, new_fpr, &keylist);
        if (status != PEP_STATUS_OK)
            goto pEp_free;
        if (!keylist) {
            status = PEP_MALFORMED_KEY_RESET_MSG;
            goto pEp_free;
        }
        
        // We need to update the identity to get the user_id
        curr_ident->fpr = NULL; // ensure old_fpr is preserved
        free(curr_ident->user_id);
        curr_ident->user_id = NULL;
        status = update_identity(session, curr_ident);
        
        // Ok, now check the old fpr to see if we have an entry for it
        // temp fpr set for function call
        curr_ident->fpr = old_fpr;
        status = get_trust(session, curr_ident);
        if (status != PEP_STATUS_OK)
            return status;
        
        PEP_comm_type ct_result = curr_ident->comm_type;

        // Basically, see if fpr is even in the database
        // for this user - we'll get PEP_ct_unknown if it isn't
        if (ct_result == PEP_ct_unknown)
            return PEP_KEY_NOT_RESET;
        
        // Alright, so we have a key to reset. Good.
        
        // If this is a non-own user, for NOW, we presume key reset 
        // by email for non-own keys is ONLY in case of revoke-and-replace. 
        // This means we have, at a *minimum*, an object that once 
        // required the initial private key in order to replace that key 
        // with another.
        //
        // The limitations on what this guarantees are known - this does 
        // not prevent, for example, replay attacks from someone with 
        // access to the original revocation cert are possible if they 
        // get to us before we receive this object from the original sender.
        // The best we can do in this case is to NOT trust the new key.
        // It will be used by default, but if the original was trusted,
        // the rating will visibly change for the sender, and even if it was 
        // not, if we do use it, the sender can report unreadable mails to us 
        // and detect it that way. FIXME: We may need to have some kind 
        // of even alert the user when such a change occurs for their contacts
        //
        // If this is from US, we already made sure that the sender_fpr 
        // was a valid own key, so we don't consider it here.
        if (!from_me) {
            revoked = false;
            status = key_revoked(session, old_fpr, &revoked); 

            if (!revoked)
                return PEP_KEY_NOT_RESET;            

            // Also don't let someone change the replacement fpr 
            // if the replacement fpr was also revoked - we really need 
            // to detect that something fishy is going on at this point
            // FIXME: ensure that PEP_KEY_NOT_RESET responses to 
            // automated key reset functions are propagated upward - 
            // app should be made aware if someone is trying to reset someone 
            // else's key and it's failing for some reason.
            revoked = false;
            status = key_revoked(session, new_fpr, &revoked); 

            if (revoked)
                return PEP_KEY_NOT_RESET;                        
        }
        
        // temp fpr set for function call
        // curr_ident->fpr = (char*)sender_fpr;
        // status = get_trust(session, curr_ident);
        // 
        // PEP_comm_type ct_result = curr_ident->comm_type;
        // 
        // // Basically, see if fpr is even in the database
        // // for this user - we'll get PEP_ct_unknown if it isn't
        // if (ct_result < PEP_ct_strong_but_unconfirmed)
        //     return PEP_KEY_NOT_RESET;            
        // Now check the fpr we're trying to change (old_fpr), which we reset a few lines above -
        // again, if it doesn't belong to the user, we won't use it.
        // status = get_trust(session, curr_ident);
        // 
        // if (status != PEP_STATUS_OK)
        //     return status;            
        // 
        // if (curr_ident->comm_type < PEP_ct_strong_but_unconfirmed)
        //     return PEP_KEY_NOT_RESET;
            
        // Hooray! We apparently now are dealing with keys 
        // belonging to the user from a message at least marginally
        // from the user
        if (!sender_own_key) {
            // Clear all info (ALSO REMOVES OLD KEY RIGHT NOW!!!)            
            status = key_reset(session, old_fpr, curr_ident);
            if (status != PEP_STATUS_OK)
                return status;
                                
            // Make new key the default    
            curr_ident->fpr = new_fpr;
    
            // This only sets as the default, does NOT TRUST IN ANY WAY
            PEP_comm_type new_key_rating = PEP_ct_unknown;
            
            // No key is ever returned as "confirmed" from here - it's based on raw key
            status = get_key_rating(session, new_fpr, &new_key_rating);
            if (status != PEP_STATUS_OK)
                return status;

            if (new_key_rating >= PEP_ct_strong_but_unconfirmed) {
                bool is_pEp = false;
                status = is_pEp_user(session, curr_ident, &is_pEp);
                if (is_pEp)
                    curr_ident->comm_type = PEP_ct_pEp_unconfirmed;
                else    
                    curr_ident->comm_type = new_key_rating & (~PEP_ct_confirmed);
            }    
            status = set_identity(session, curr_ident);  
            if (status != PEP_STATUS_OK)
                goto pEp_free; 
        }    
        else {
            // set new key as the default for this identity
            // N.B. If for some reason this is only a pubkey,
            // then so be it - but we need to double-check to 
            // ensure that in this case, we end up with a private one,
            // so talk to vb about this.
            // Make new key the default    
            curr_ident->fpr = new_fpr;
            status = set_own_key(session, curr_ident, new_fpr);
            
            if (status != PEP_STATUS_OK)
                return status;
                
            // key reset on old key
            status = key_reset(session, old_fpr, curr_ident);
            if (status != PEP_STATUS_OK)
                return status;            
        }
        old_fpr = NULL;
        new_fpr = NULL;    
    }

pEp_free:    
    free_stringlist(keylist);    
    free(old_fpr);
    free(new_fpr);
    return status;
}

PEP_STATUS create_standalone_key_reset_message(PEP_SESSION session,
                                               message** dst, 
                                               pEp_identity* own_identity,
                                               pEp_identity* recip,
                                               const char* old_fpr,
                                               const char* new_fpr) {
                                                   
    if (!dst || !own_identity || EMPTYSTR(own_identity->address) 
             || !recip || EMPTYSTR(recip->user_id) 
             || EMPTYSTR(recip->address))
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(old_fpr) || EMPTYSTR(new_fpr))
        return PEP_ILLEGAL_VALUE;
        
    *dst = NULL;
    
    message* reset_msg = NULL;
    
    PEP_STATUS status = _generate_keyreset_command_message(session, own_identity,
                                                           recip,
                                                           old_fpr, new_fpr, false,
                                                           &reset_msg);
                            
    if (status != PEP_STATUS_OK)
        goto pEp_free;
    
    if (!reset_msg)
        return PEP_ILLEGAL_VALUE;
                                                                         
    if (!reset_msg->attachments)
        return PEP_UNKNOWN_ERROR;
    
    message* output_msg = NULL;
    
    status = encrypt_message(session, reset_msg, NULL,
                             &output_msg, PEP_enc_PGP_MIME,
                             PEP_encrypt_flag_key_reset_only);

    if (status == PEP_STATUS_OK)
        *dst = output_msg;
        
pEp_free:
        
    free_message(reset_msg);    
    return status;
}

PEP_STATUS send_key_reset_to_recents(PEP_SESSION session,
                                     pEp_identity* from_ident,
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
        status = has_key_reset_been_sent(session, from_ident->address, user_id, old_fpr, &contacted);
        if (status != PEP_STATUS_OK)
            goto pEp_free;
    
        if (contacted)
            continue;
            
        // Make sure they've ever *contacted* this address    
        bool in_contact_w_this_address = false;
        status = has_partner_contacted_address(session, curr_id->user_id, from_ident->address,  
                                               &in_contact_w_this_address);
        
        if (!in_contact_w_this_address)
            continue;
            
        // if not, make em a message    
        reset_msg = NULL;
        
        status = create_standalone_key_reset_message(session,
                                                     &reset_msg,
                                                     from_ident,
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
        status = set_reset_contact_notified(session, from_ident->address, old_fpr, user_id);
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


static PEP_STATUS _key_reset_device_group_for_shared_key(PEP_SESSION session, 
                                                         identity_list* key_idents, 
                                                         const char* old_key) {
    assert(session);
    assert(key_idents);
    assert(old_key);
    
    if (!session || !key_idents || EMPTYSTR(old_key))
        return PEP_ILLEGAL_VALUE;
        
    messageToSend_t send_cb = session->messageToSend;
    if (!send_cb)
        return PEP_SYNC_NO_MESSAGE_SEND_CALLBACK;
        
    PEP_STATUS status = PEP_STATUS_OK;
        
    // each of these has the same key and needs a new one.
    identity_list* curr_ident;
    for (curr_ident = key_idents; curr_ident && curr_ident->ident; curr_ident = curr_ident->next) {
        if (curr_ident->ident->flags & PEP_idf_devicegroup) {
            pEp_identity* ident = curr_ident->ident;
            free(ident->fpr);
            ident->fpr = NULL;
            status = generate_keypair(session, ident);
            if (status != PEP_STATUS_OK)
                return status;
                
        }
        else {
            status = key_reset(session, old_key, curr_ident->ident); 
        }        
    }
        
    // Ok, everyone's got a new keypair. Hoorah! 
    // generate, sign, and push messages into queue
    for (curr_ident = key_idents; curr_ident && curr_ident->ident; curr_ident = curr_ident->next) {
        if (curr_ident->ident->flags & PEP_idf_devicegroup) {
            message* outmsg = NULL;
            
            // FIXME - do we have to? Maybe check IN the funct
            pEp_identity* to_me = identity_dup(curr_ident->ident);
            if (!to_me)
                return PEP_OUT_OF_MEMORY;
                
            status = _generate_keyreset_command_message(session, curr_ident->ident, to_me,
                                                        old_key, curr_ident->ident->fpr,
                                                        true, &outmsg);
            
            message* enc_msg = NULL;
            
            // encrypt this baby and get out
            // extra keys???
            status = encrypt_message(session, outmsg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
            
            if (status != PEP_STATUS_OK) {
                goto pEp_free;
            }
            
            // insert into queue
            status = send_cb(enc_msg);

            if (status != PEP_STATUS_OK) {
                free(enc_msg);
                goto pEp_free;            
            }                         
            // Does there need to be some kind of signal here for sync?                                               
        }    
    }
    
    // Ok, we've signed everything we need to with the old key,
    // Revoke that baby.
    status = revoke_key(session, old_key, NULL);

    if (!status)
        goto pEp_free;
        
    for (curr_ident = key_idents; curr_ident && curr_ident->ident; curr_ident = curr_ident->next) {
        if (curr_ident->ident->flags & PEP_idf_devicegroup) {
            pEp_identity* ident = curr_ident->ident;
            
            // N.B. This sort of sucks because we overwrite this every time.
            // But this case is infrequent and we don't rely on the binding.
            if (status == PEP_STATUS_OK) 
                status = set_revoked(session, old_key, curr_ident->ident->fpr, time(NULL));            

            if (!status)
                goto pEp_free;
                
            pEp_identity* tmp_ident = identity_dup(ident);
            if (!tmp_ident) {
                status = PEP_OUT_OF_MEMORY;
                goto pEp_free;
            }    
            free(tmp_ident->fpr);    
            
            // for all active communication partners:
            //      active_send revocation            
            tmp_ident->fpr = strdup(old_key); // freed in free_identity
            if (status == PEP_STATUS_OK)
                status = send_key_reset_to_recents(session, tmp_ident, old_key, ident->fpr);        
            free_identity(tmp_ident);
        }    
    }    
pEp_free:
    return status;
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

                        bool is_grouped = false;
                        if (!deviceGrouped(session, &is_grouped)) {
                            for (curr_ident = key_idents; curr_ident && curr_ident->ident; 
                                                            curr_ident = curr_ident->next) {
                                
                                pEp_identity* this_identity = curr_ident->ident;
                                // Do the full reset on this identity        
                                status = key_reset(session, fpr_copy, this_identity);
                                
                                // Ident list gets freed below, do not free here!
                            }
                        }
                        else {
                            status = _key_reset_device_group_for_shared_key(session, key_idents, fpr_copy);                        }    
                    }
                    // Ok, we've either now reset for each own identity with this key, or 
                    // we got an error and want to bail anyway.
                    goto pEp_free;
                }    
            }
            
            if (EMPTYSTR(tmp_ident->address)) {
                return PEP_UNKNOWN_ERROR; // FIXME - what case IS this?
            }
            
            // Ok, first we generate a new key.
            
            // Base case for is_own_private starts here
            // tmp ident is an actual identity now (not just a skeleton?)
            status = revoke_key(session, fpr_copy, NULL);
            
            // If we have a full identity, we have some cleanup and generation tasks here
            if (!EMPTYSTR(tmp_ident->address)) {
                // generate new key
                if (status == PEP_STATUS_OK) {
                    tmp_ident->fpr = NULL;
                    status = myself(session, tmp_ident);
                }
                if (status == PEP_STATUS_OK && tmp_ident->fpr && strcmp(fpr_copy, tmp_ident->fpr) != 0)
                    new_key = strdup(tmp_ident->fpr);
                // Error handling?    
                
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
                
                tmp_ident->fpr = fpr_copy;
                if (status == PEP_STATUS_OK)
                    status = send_key_reset_to_recents(session, tmp_ident, fpr_copy, new_key);        
                tmp_ident->fpr = NULL;    
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

/*
static stringlist_t* collect_key_material(PEP_SESSION session, stringlist_t* fprs) {
    stringlist_t* keydata = NULL;    
    stringlist_t* curr_fpr = fprs;    
    while (curr_fpr) {
        if (curr_fpr->value) {
            char* key_material = NULL;
            size_t datasize = 0;
            PEP_STATUS status = export_key(session, curr_fpr->value, &key_material, &datasize);
            if (status) {
                free_stringlist(keydata);
                return NULL;
            }
            if (datasize > 0 && key_material) {
                if (!(keydata))
                    keydata = new_stringlist(NULL);
                    
                stringlist_add(keydata, key_material);
            }
        }
        curr_fpr = curr_fpr->next;        
    }   
    return keydata; 
}

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
                status = export_key(session, curr_ident->ident->fpr, &key_material, &datasize);
                if (status) {
                    free_stringlist(keydata);
                    return status;
                }
                if (datasize > 0 && key_material)
                    stringlist_add(keydata, key_material);
                    
                key_material = NULL;
                datasize = 0;    
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

    long *major = malloc(sizeof(long));
    assert(major);
    if (!major)
        goto enomem;
    *major = KEY_RESET_MAJOR_VERSION;
    dist->choice.keyreset.choice.commands.version.major = major;

    long *minor = malloc(sizeof(long));
    assert(minor);
    if (!minor)
        goto enomem;
    *minor = KEY_RESET_MINOR_VERSION;
    dist->choice.keyreset.choice.commands.version.minor = minor;

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
