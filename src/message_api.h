#pragma once

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message.h"
#include "mime.h"

#ifdef __cplusplus
extern "C" {
#endif


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
        message **dst
    );


typedef enum _pEp_color {
    pEp_undefined = 0,
    pEp_unencrypted,
    pEp_unreliable,
    pEp_reliable,
    pEp_yellow = pEp_reliable,
    pEp_trusted,
    pEp_green = pEp_trusted,
    pEp_trusted_and_anonymized,
    pEp_fully_anonymous,   

    pEp_under_attack = -1,
    pEp_red = pEp_under_attack,
    pEp_b0rken = -2
} pEp_color;

// get_color() - get color for a message
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

DYNAMIC_API PEP_STATUS get_color(
        PEP_SESSION session,
        message *msg,
        pEp_color *color
    );

#ifdef __cplusplus
}
#endif

