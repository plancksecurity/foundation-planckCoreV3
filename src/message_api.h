#pragma once

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif


void import_attached_keys(PEP_SESSION session, const message *msg);
void attach_own_key(PEP_SESSION session, message *msg);


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
//	    the ownership of the new message goes to the caller
//	    if src is unencrypted this function returns PEP_UNENCRYPTED and sets
//	    dst to NULL

DYNAMIC_API PEP_STATUS encrypt_message(
        PEP_SESSION session,
        message *src,
        stringlist_t *extra,
        message **dst,
        PEP_enc_format enc_format
    );


// decrypt_message() - decrypt message in memory
//
//  parameters:
//      session (in)        session handle
//      src (in)            message to decrypt
//      mime (in)           MIME encoding wanted
//      dst (out)           pointer to new decrypted message or NULL on failure
//      keylist (out)       stringlist with keyids
//
//  return value:
//      error status or PEP_STATUS_OK on success
//
//	caveat:
//	    the ownership of the new message goes to the caller

DYNAMIC_API PEP_STATUS decrypt_message(
        PEP_SESSION session,
        message *src,
        PEP_MIME_format mime,
        message **dst,
        stringlist_t **keylist
    );


typedef enum _PEP_color {
    PEP_rating_undefined = 0,
    PEP_rating_unencrypted,
    PEP_rating_cannot_decrypt,
    PEP_rating_unreliable,
    PEP_rating_reliable,
    PEP_rating_yellow = PEP_rating_reliable,
    PEP_rating_trusted,
    PEP_rating_green = PEP_rating_trusted,
    PEP_rating_trusted_and_anonymized,
    PEP_rating_fully_anonymous,   

    PEP_rating_under_attack = -1,
    PEP_rating_red = PEP_rating_under_attack,
    PEP_rating_b0rken = -2
} PEP_color;

// message_color() - get color for a message
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

DYNAMIC_API PEP_STATUS message_color(
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

DYNAMIC_API PEP_STATUS identity_color(
        PEP_SESSION session,
        pEp_identity *ident,
        PEP_color *color
    );


#ifdef __cplusplus
}
#endif

