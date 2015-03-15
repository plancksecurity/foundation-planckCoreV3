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

#ifdef __cplusplus
}
#endif

