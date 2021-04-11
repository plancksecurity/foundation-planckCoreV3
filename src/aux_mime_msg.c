/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifdef ENIGMAIL_MAY_USE_THIS

#include "pEp_internal.h"
#include "message_api.h"
#include "mime.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "aux_mime_msg.h"


static PEP_STATUS update_identity_recip_list(PEP_SESSION session,
                                             identity_list* list) {

    PEP_STATUS status = PEP_STATUS_OK;

    if (!session)
        return PEP_UNKNOWN_ERROR;
    
    identity_list* id_list_ptr = NULL;
        
    for (id_list_ptr = list; id_list_ptr; id_list_ptr = id_list_ptr->next) {
        pEp_identity* curr_identity = id_list_ptr->ident;
        if (curr_identity) {
            if (!is_me(session, curr_identity)) {
                char* name_bak = curr_identity->username;
                curr_identity->username = NULL;
                status = _update_identity(session, curr_identity, true);
                if (name_bak && 
                    (EMPTYSTR(curr_identity->username) || strcmp(name_bak, curr_identity->username) != 0)) {
                    free(curr_identity->username);
                    curr_identity->username = name_bak;
                }                        
            }
            else
                status = _myself(session, curr_identity, false, false, false, true);
        if (status == PEP_ILLEGAL_VALUE || status == PEP_OUT_OF_MEMORY)
            return status;
        }
    }
    
    return PEP_STATUS_OK;                                  
}

DYNAMIC_API PEP_STATUS MIME_decrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    char** mime_plaintext,
    stringlist_t **keylist,
    PEP_rating *rating,
    PEP_decrypt_flags_t *flags,
    char** modified_src
)
{
    assert(mimetext);
    assert(mime_plaintext);
    assert(keylist);
    assert(rating);
    assert(flags);
    assert(modified_src);

    if (!(mimetext && mime_plaintext && keylist && rating && flags && modified_src))
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = PEP_STATUS_OK;
    message* tmp_msg = NULL;
    message* dec_msg = NULL;
    *mime_plaintext = NULL;

    status = mime_decode_message(mimetext, size, &tmp_msg, NULL);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    tmp_msg->dir = PEP_dir_incoming;
    // MIME decode message delivers only addresses. We need more.
    if (tmp_msg->from) {
        if (!is_me(session, tmp_msg->from))
            status = _update_identity(session, (tmp_msg->from), true);
        else
            status = _myself(session, tmp_msg->from, false, true, false, true);

        if (status == PEP_ILLEGAL_VALUE || status == PEP_OUT_OF_MEMORY || PASS_ERROR(status))
            goto pEp_error;
    }

    status = update_identity_recip_list(session, tmp_msg->to);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    status = update_identity_recip_list(session, tmp_msg->cc);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    status = update_identity_recip_list(session, tmp_msg->bcc);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    PEP_STATUS decrypt_status = decrypt_message(session,
                                                tmp_msg,
                                                &dec_msg,
                                                keylist,
                                                rating,
                                                flags);


    if (!dec_msg && (decrypt_status == PEP_UNENCRYPTED || decrypt_status == PEP_VERIFIED)) {
        dec_msg = message_dup(tmp_msg);
    }
    
    if (decrypt_status > PEP_CANNOT_DECRYPT_UNKNOWN || !dec_msg)
    {
        status = decrypt_status;
        goto pEp_error;
    }

    if (*flags & PEP_decrypt_flag_src_modified) {
        mime_encode_message(tmp_msg, false, modified_src, false);
        if (!modified_src) {
            *flags &= (~PEP_decrypt_flag_src_modified);
            decrypt_status = PEP_CANNOT_REENCRYPT; // Because we couldn't return it, I guess.
        }
    }

    // FIXME: test with att
    status = mime_encode_message(dec_msg, false, mime_plaintext, false);

    if (status == PEP_STATUS_OK)
    {
        free(tmp_msg);
        free(dec_msg);
        return decrypt_status;
    }
    
pEp_error:
    free_message(tmp_msg);
    free_message(dec_msg);

    return status;
}


DYNAMIC_API PEP_STATUS MIME_encrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    stringlist_t* extra,
    char** mime_ciphertext,
    PEP_enc_format enc_format,
    PEP_encrypt_flags_t flags
)
{
    PEP_STATUS status = PEP_STATUS_OK;
    PEP_STATUS tmp_status = PEP_STATUS_OK;
    message* tmp_msg = NULL;
    message* enc_msg = NULL;
    message* ret_msg = NULL;                             

    status = mime_decode_message(mimetext, size, &tmp_msg, NULL);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    // MIME decode message delivers only addresses. We need more.
    if (tmp_msg->from) {
        char* own_id = NULL;
        status = get_default_own_userid(session, &own_id);
        free(tmp_msg->from->user_id);
        
        if (status != PEP_STATUS_OK || !own_id) {
            tmp_msg->from->user_id = strdup(PEP_OWN_USERID);
        }
        else {
            tmp_msg->from->user_id = own_id; // ownership transfer
        }
            
        status = myself(session, tmp_msg->from);
        if (status != PEP_STATUS_OK)
            goto pEp_error;
    }
    
    // Own identities can be retrieved here where they would otherwise
    // fail because we lack all other information. This is ok and even
    // desired. FIXME: IS it?
    status = update_identity_recip_list(session, tmp_msg->to);
    if (status != PEP_STATUS_OK)
        goto pEp_error;
    
    status = update_identity_recip_list(session, tmp_msg->cc);
    if (status != PEP_STATUS_OK)
        goto pEp_error;
    
    status = update_identity_recip_list(session, tmp_msg->bcc);
    if (status != PEP_STATUS_OK)
        goto pEp_error;
    
    // This isn't incoming, though... so we need to reverse the direction
    tmp_msg->dir = PEP_dir_outgoing;
    status = encrypt_message(session,
                             tmp_msg,
                             extra,
                             &enc_msg,
                             enc_format,
                             flags);
                             
    if (status == PEP_STATUS_OK || status == PEP_UNENCRYPTED)
        ret_msg = (status == PEP_STATUS_OK ? enc_msg : tmp_msg);
    else                                
        goto pEp_error;

    if (status == PEP_STATUS_OK && !enc_msg) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_error;
    }
    
    tmp_status = mime_encode_message(ret_msg, 
                                     false, 
                                     mime_ciphertext, 
                                     false);
    
    if (tmp_status != PEP_STATUS_OK)
        status = tmp_status;

pEp_error:
    free_message(tmp_msg);
    free_message(enc_msg);

    return status;

}

DYNAMIC_API PEP_STATUS MIME_encrypt_message_for_self(
    PEP_SESSION session,
    pEp_identity* target_id,
    const char *mimetext,
    size_t size,
    stringlist_t* extra,
    char** mime_ciphertext,
    PEP_enc_format enc_format,
    PEP_encrypt_flags_t flags
)
{
    PEP_STATUS status = PEP_STATUS_OK;
    message* tmp_msg = NULL;
    message* enc_msg = NULL;

    status = mime_decode_message(mimetext, size, &tmp_msg, NULL);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    // This isn't incoming, though... so we need to reverse the direction
    tmp_msg->dir = PEP_dir_outgoing;
    status = encrypt_message_for_self(session,
                                      target_id,
                                      tmp_msg,
                                      extra,
                                      &enc_msg,
                                      enc_format,
                                      flags);
    if (status != PEP_STATUS_OK)
        goto pEp_error;
 
    if (!enc_msg) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_error;
    }

    status = mime_encode_message(enc_msg, false, mime_ciphertext, false);

pEp_error:
    free_message(tmp_msg);
    free_message(enc_msg);

    return status;
}
#else
// This is here to please ISO C - it needs a compilation unit. Value will never be used.
const int the_answer_my_friend = 42;
#endif
