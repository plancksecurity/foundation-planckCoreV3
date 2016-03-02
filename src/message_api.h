#pragma once

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message.h"
#include "cryptotech.h"

#ifdef __cplusplus
extern "C" {
#endif


void import_attached_keys(PEP_SESSION session, const message *msg);
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

// decrypt_message() - decrypt message in memory
//
//  parameters:
//      session (in)        session handle
//      src (in)            message to decrypt
//      dst (out)           pointer to new decrypted message or NULL on failure
//      keylist (out)       stringlist with keyids
//      color (out)         color for the message
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
        PEP_color *color
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


#ifdef __cplusplus
}
#endif

