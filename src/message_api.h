#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "transport.h"


// mime_encode_parts() - encode message with MIME
//  parameters:
//      src                 message to encode
//      dst                 encoded message or NULL on error
//
//  return value:
//      error status or PEP_STATUS_OK on success
//
//  caveat:
//      message must be unencrypted

DYNAMIC_API PEP_STATUS mime_encode_parts(const message *src, message **dst);


// mime_decode_parts() - decode MIME message
//  parameters:
//      src                 message to decode
//      dst                 decoded message or NULL on error
//
//  return value:
//      error status or PEP_STATUS_OK on success
//
//  caveat:
//      message must be unencrypted

DYNAMIC_API PEP_STATUS mime_decode_parts(const message *src, message **dst);


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

DYNAMIC_API PEP_STATUS encrypt_message(
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

DYNAMIC_API PEP_STATUS decrypt_message(
        PEP_SESSION session,
        const message *src,
        message **dst
    );

#ifdef __cplusplus
}
#endif

