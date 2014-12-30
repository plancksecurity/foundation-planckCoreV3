#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "transport.h"


// encrypt_message() - encrypt message in memory
//
//  parameters:
//      session             session handle
//      src                 message to encrypt
//      extra               extra keys for encryption
//      dst                 pointer to encrypted message or NULL on failure
//      format              encryption format
//
//  return value:
//      error status or PEP_STATUS_OK on success; PEP_KEY_NOT_FOUND if one
//      or more keys couldn't be found, but the message could be encrypted
//      with other keys

PEP_STATUS encrypt_message(
        PEP_SESSION session,
        const message *src,
        stringlist_t *extra,
        message **dst,
        PEP_enc_format format
    );


// decrypt_message() - decrypt message in memory
//
//  parameters:
//      session             session handle
//      src                 message to decrypt
//      dst                 pointer to decrypted message or NULL on failure
//
//  return value:
//      error status or PEP_STATUS_OK on success

PEP_STATUS decrypt_message(
        PEP_SESSION session,
        const message *src,
        message **dst
    );

#ifdef __cplusplus
}
#endif

