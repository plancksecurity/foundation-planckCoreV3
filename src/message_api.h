#pragma once

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message.h"
#include "cryptotech.h"

#ifdef __cplusplus
extern "C" {
#endif


bool import_attached_keys(
        PEP_SESSION session, 
        const message *msg,
        identity_list **private_idents
    );
void attach_own_key(PEP_SESSION session, message *msg);
PEP_cryptotech determine_encryption_format(message *msg);

// encrypt_message() - encrypt message in memory
//
//  parameters:
//      session (in)        session handle
//      src (in)            message to encrypt
//      extra (in)          extra keys for encryption
//      dst (out)           pointer to new encrypted message or NULL on failure
//      enc_format (in)     encrypted format
//
//  return value:
//      PEP_STATUS_OK                   on success
//		PEP_KEY_NOT_FOUND	            at least one of the receipient keys
//		                                could not be found
//		PEP_KEY_HAS_AMBIG_NAME          at least one of the receipient keys has
//		                                an ambiguous name
//		PEP_GET_KEY_FAILED		        cannot retrieve key
//
//	caveat:
//	    the ownershop of src remains with the caller
//	    the ownership of dst goes to the caller

DYNAMIC_API PEP_STATUS encrypt_message(
        PEP_SESSION session,
        message *src,
        stringlist_t *extra,
        message **dst,
        PEP_enc_format enc_format
    );

// encrypt_message_for_identity() - encrypt message for one particular identity in memory
//                     (to be used, for example, to save message drafts
//                      encrypted with owner ID)
//
//  parameters:
//      session (in)        session handle
//      target_id (in)      self identity this message should be encrypted for
//      src (in)            message to encrypt
//      dst (out)           pointer to new encrypted message or NULL on failure
//      enc_format (in)     encrypted format
//
//  return value:       (FIXME: This may not be correct or complete)
//      PEP_STATUS_OK                   on success
//		PEP_KEY_NOT_FOUND	            at least one of the receipient keys
//		                                could not be found
//		PEP_KEY_HAS_AMBIG_NAME          at least one of the receipient keys has
//		                                an ambiguous name
//		PEP_GET_KEY_FAILED		        cannot retrieve key
//
//	caveat:
//	    the ownership of src remains with the caller
//      the ownership of target_id remains w/ caller            
//	    the ownership of dst goes to the caller
//      message is NOT encrypted for identities other than the target_id (and then,
//          only if the target_id refers to self!)

DYNAMIC_API PEP_STATUS encrypt_message_for_self(
        PEP_SESSION session,
        pEp_identity* target_id,
        message *src,
        message **dst,
        PEP_enc_format enc_format
    );

typedef enum _PEP_color {
    PEP_rating_undefined = 0,
    PEP_rating_cannot_decrypt,
    PEP_rating_have_no_key,
    PEP_rating_unencrypted,
    PEP_rating_unencrypted_for_some,
    PEP_rating_unreliable,
    PEP_rating_reliable,
    PEP_rating_yellow = PEP_rating_reliable,
    PEP_rating_trusted,
    PEP_rating_green = PEP_rating_trusted,
    PEP_rating_trusted_and_anonymized,
    PEP_rating_fully_anonymous,   

    PEP_rating_mistrust = -1,
    PEP_rating_red = PEP_rating_mistrust,
    PEP_rating_b0rken = -2,
    PEP_rating_under_attack = -3
} PEP_color;

typedef enum _PEP_decrypt_flags {
    PEP_decrypt_flag_own_private_key = 0x1
} PEP_decrypt_flags; 

typedef uint32_t PEP_decrypt_flags_t;

// decrypt_message() - decrypt message in memory
//
//  parameters:
//      session (in)        session handle
//      src (in)            message to decrypt
//      dst (out)           pointer to new decrypted message or NULL on failure
//      keylist (out)       stringlist with keyids
//      color (out)         color for the message
//      flags (out)         flags to signal special message features
//
//  return value:
//      error status or PEP_STATUS_OK on success
//
//	caveat:
//	    the ownership of src remains with the caller
//	    the ownership of dst goes to the caller
//	    the ownership of keylist goes to the caller
//	    if src is unencrypted this function returns PEP_UNENCRYPTED and sets
//	    dst to NULL

DYNAMIC_API PEP_STATUS decrypt_message(
        PEP_SESSION session,
        message *src,
        message **dst,
        stringlist_t **keylist,
        PEP_color *color,
        PEP_decrypt_flags_t *flags 
);

// own_message_private_key_details() - details on own key in own message
//
//  parameters:
//      session (in)        session handle
//      msg (in)            message to decrypt
//      ident (out)         identity containing uid, address and fpr of key
//
//  note:
//      In order to obtain details about key to be possibly imported
//      as a replacement of key currently used as own identity, 
//      application passes message that have been previously flagged by 
//      decrypt_message() as own message containing own key to this function
//
//  return value:
//      error status or PEP_STATUS_OK on success
//
//	caveat:
//	    the ownership of msg remains with the caller
//	    the ownership of ident goes to the caller
//	    msg MUST be encrypted so that this function can check own signature

DYNAMIC_API PEP_STATUS own_message_private_key_details(
        PEP_SESSION session,
        message *msg,
        pEp_identity **ident 
);

// outgoing_message_color() - get color for an outgoing message
//
//  parameters:
//      session (in)        session handle
//      msg (in)            message to get the color for
//      color (out)         color for the message
//
//  return value:
//      error status or PEP_STATUS_OK on success
//
//  caveat:
//      msg->from must point to a valid pEp_identity
//      msg->dir must be PEP_dir_outgoing
//      the ownership of msg remains with the caller

DYNAMIC_API PEP_STATUS outgoing_message_color(
        PEP_SESSION session,
        message *msg,
        PEP_color *color
    );


// identity_color() - get color for a single identity
//
//  parameters:
//      session (in)        session handle
//      ident (in)          identity to get the color for
//      color (out)         color for the identity
//
//  return value:
//      error status or PEP_STATUS_OK on success
//
//  caveat:
//      the ownership of ident remains with the caller

DYNAMIC_API PEP_STATUS identity_color(
        PEP_SESSION session,
        pEp_identity *ident,
        PEP_color *color
    );


// get_binary_path() - retrieve path of cryptotech binary if available
//
//  parameters:
//      tech (in)           cryptotech to get the binary for
//      path (out)          path to cryptotech binary or NULL if not available
//                          **path is owned by the library, do not change it!
DYNAMIC_API PEP_STATUS get_binary_path(PEP_cryptotech tech, const char **path);


#ifdef __cplusplus
}
#endif

