// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef enum _base_protocol_type {
    BASE_SIGN = 0,

    BASE_SYNC = 1,
    BASE_KEYRESET = 2
} base_protocol_type;


// base_decorate_message() - decorate a message with payload
//
//  parameters:
//      session (in)    session handle
//      msg (inout)     message to decorate
//      type (in)       base protocol type
//      payload (in)    payload to send
//      size (in)       size of payload
//      fpr (in)        optional key to sign or NULL
//
//  returns:
//      PEP_STATUS_OK and result on success or an error on failure
//
//  caveat:
//      on success (and only then) payload goes to the ownership of the msg
//      the ownership of the msg remains with the caller

PEP_STATUS base_decorate_message(
        PEP_SESSION session,
        message *msg,
        base_protocol_type type,
        char *payload,
        size_t size,
        const char *fpr
    );


// base_prepare_message() - prepare a sync message with payload
//
//  parameters:
//      session (in)    session handle
//      me (in)         identity to use for the sender
//      partner (in)    identity to use for the receiver
//      type (in)       base protocol type
//      payload (in)    payload to send
//      size (in)       size of payload
//      fpr (in)        optional key to sign or NULL
//      result (out)    message with payload
//
//  returns:
//      PEP_STATUS_OK and result on success or an error on failure
//
//  caveat:
//      on success (and only then) payload goes to the ownership of the result
//      the ownership of the result goes to the caller

PEP_STATUS base_prepare_message(
        PEP_SESSION session,
        const pEp_identity *me,
        const pEp_identity *partner,
        base_protocol_type type,
        char *payload,
        size_t size,
        const char *fpr,
        message **result
    );


// base_extract_message() - extract a sync message from a pEp message
//
//  parameters:
//      session (in)    session handle
//      msg (in)        message to analyze
//      type (in)       base protocol type to extract
//      size (out)      size of extracted payload or 0 if not found
//      payload (out)   extraced payload
//      fpr (out)       if message was correctly signed then fpr of signature's
//                      key, otherwise NULL
//
//  returns:
//      PEP_STATUS_OK and payload == NULL if no sync message
//      PEP_STATUS_OK and payload, size if sync message found
//      any other value on error
//
//  caveat:
//      payload may point to msg attachment, the ownership does not change
//      the ownership of fpr goes to the caller

PEP_STATUS base_extract_message(
        PEP_SESSION session,
        message *msg,
        base_protocol_type type,
        size_t *size,
        const char **payload,
        char **fpr
    );


// this is the internal function to be used by asynchronous network protocol
// implementations
//
// this function is calling messageToSend(NULL) in case there is a missing or wrong passphrase

PEP_STATUS try_base_prepare_message(
        PEP_SESSION session,
        const pEp_identity *me,
        const pEp_identity *partner,
        base_protocol_type type,
        char *payload,
        size_t size,
        const char *fpr,
        message **result
    );

#ifdef __cplusplus
}
#endif

