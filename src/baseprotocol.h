// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef BASEPROTOCOL_H
#define BASEPROTOCOL_H

#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _BASE_PROTO_MIME_TYPE_SIGN "application/pEp.sign"
#define _BASE_PROTO_MIME_TYPE_SYNC "application/pEp.sync"
#define _BASE_PROTO_MIME_TYPE_DIST "application/pEp.distribution"

typedef enum _base_protocol_type {
    BASE_SIGN = 0,
    BASE_SYNC = 1,
    BASE_DISTRIBUTION = 2
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


// base_prepare_message() - prepare an administrative message with payload
//
//  parameters:
//      session (in)    session handle
//      me (in)         identity to use for the sender
//      partner (in)    identity to use for the receiver
//      type (in)       base protocol type
//      payload (in)    payload to send
//      size (in)       size of payload
//      fpr (in)        optional key to sign or NULL;
//                      the message will not be signed if NULL
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


/**
 * @internal
 *  <!--       base_extract_message()       -->
 *
 *  @brief      Extract protocol data from a pEp administrative message
 *
 *  @param[in]   session    session handle
 *  @param[in]   msg        message to analyze
 *  @param[in]   type       base protocol type to extract
 *  @param[out]  size       size of extracted payload, or 0 if not found
 *  @param[out]  payload    extracted payload, if sync message is found.
 *                          otherwise, NULL
 *  @param[out]  fpr        if message was correctly signed then fpr of signature's
 *                          key, otherwise NULL
 *
 *  @retval PEP_STATUS_OK       if no error occurred, whether or not pEp message was found
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval error_status        any other value on error
 *
 *  @ownership
 *  - Payload may point to msg attachment, but the ownership does not change
 *  - If fpr != NULL the ownership goes to the caller
 *
 *  @todo Volker, expand this definition from sync message. What do we call these? Administrative messages? - K
 *
 */
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

#endif
