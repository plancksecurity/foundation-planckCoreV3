#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "transport.h"


// encrypt_message() - encrypt message in memory
//
//  parameters:
//      session (in)        session handle
//      src (in)            message to encrypt
//      extra (in)          extra keys for encryption
//      dst (out)           pointer to encrypted message or NULL on failure
//      format (in)         unencrypted format
//
//  return value:
//      PEP_STATUS_OK                   on success
//		PEP_KEY_NOT_FOUND	            at least one of the receipient keys
//		                                could not be found
//		PEP_KEY_HAS_AMBIG_NAME          at least one of the receipient keys has
//		                                an ambiguous name
//		PEP_GET_KEY_FAILED		        cannot retrieve key

DYNAMIC_API PEP_STATUS encrypt_message(
        PEP_SESSION session,
        const message *src,
        stringlist_t *extra,
        message **dst,
        PEP_enc_format enc_format
    );


// decrypt_message() - decrypt message in memory
//
//  parameters:
//      session (in)        session handle
//      src (in)            message to decrypt
//      dst (out)           pointer to decrypted message or NULL on failure
//
//  return value:
//      error status or PEP_STATUS_OK on success

DYNAMIC_API PEP_STATUS decrypt_message(
        PEP_SESSION session,
        const message *src,
        message **dst,
        PEP_enc_format enc_format
    );

#ifdef __cplusplus
}
#endif

