/**
 * @internal
 * @file     baseprotocol.h
 * @brief    Basic functions for administrative pEp messages (preparation,
 *           decoration, payload, extraction, etc.). 
 *
 * These are used for
 *           protocol messages in, for example, key sync and key reset.
 *           The payloads of these messages are, in general, not human-readable.
 * @license  GNU General Public License 3.0 - see LICENSE.txt
 */
/*
Changelog:

* 2023-07 is_distribution_message() new function to check if a message is a distribution protocol message.
*/

#ifndef BASEPROTOCOL_H
#define BASEPROTOCOL_H

#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _BASE_PROTO_MIME_TYPE_SIGN "application/pEp.sign"
#define _BASE_PROTO_MIME_TYPE_SYNC "application/pEp.sync"
#define _BASE_PROTO_MIME_TYPE_DIST "application/pEp.distribution"

/**
 * @internal
 *  @enum    base_protocol_type
 *  
 *  @brief    TODO
 *  
 */
typedef enum _base_protocol_type {
    BASE_SIGN = 0,
    BASE_SYNC = 1,
    BASE_DISTRIBUTION = 2
} base_protocol_type;


/**
 * @internal
 *  <!--       base_decorate_message()       -->
 *  
 *  @brief      Given the data payload for an administrative message, add the appropriate
 *              information for the payload based on type and insert the payload into the
 *              message
 *  
 *  @param[in]     session    session handle
 *  @param[in,out] msg        message to decorate
 *  @param[in]     type       base protocol type
 *  @param[in]     payload    payload to send
 *  @param[in]     size       size of payload
 *  @param[in]     fpr        optional key to sign or NULL
 *  
 *  @retval PEP_STATUS_OK     on success 
 *  @retval error_status      on failure
 *  
 *  @ownership 
 *  - On success (and only then), ownership of the payload is assigned to the msg structure
 *  - Ownership of the msg remains with the caller
 *  
 */

PEP_STATUS base_decorate_message(
        PEP_SESSION session,
        message *msg,
        base_protocol_type type,
        char *payload,
        size_t size,
        const char *fpr
    );


/**
 * @internal
 *  <!--       base_prepare_message()       -->
 *  
 *  @brief      Given a protocol data payload and a message type, prepare an administrative
 *              protocol message for encryption and/or delivery
 *  
 *  @param[in]   session    session handle
 *  @param[in]   me         identity to use for the sender
 *  @param[in]   partner    identity to use for the receiver
 *  @param[in]   type       base protocol type
 *  @param[in]   payload    payload to send
 *  @param[in]   size       size of payload
 *  @param[in]   fpr        optional key to sign or NULL;
 *                          the message will not be signed if NULL
 *  @param[out]  result     returned message with payload on success
 *  
 *  @retval PEP_STATUS_OK       on success
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval any other value     on failure
 *  
 *  @ownership 
 *  - On (and only on) success, ownership of payload is assigned to the result structure
 *  - Ownership of the result goes to the caller
 *  
 */

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
 *  <!--       is_distribution_message()       -->
 *
 *  @brief      Check if a message is or not a distribution message.
 *
 *  @param[in]   session    session handle
 *  @param[in]   msg        message to analyze
 *
 *  @retval true       if no error occurred
 *  @retval false   illegal parameter values
 *
 */

bool is_distribution_message(
        PEP_SESSION session,
        message *msg
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
 *  @retval PEP_STATUS_OK       if no error occurred, whether or not sync message was found
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


/**
 * @internal
 *  <!--       try_base_prepare_message()       -->
 *  
 *  @brief      Prepare an administrative message with payload. 
 *
 *  This is the internal function to be used by
 *              asynchronous network protocol implementations. This function differs from
 *              base_prepare_message in that it calls messageToSend(NULL) in case there is a missing
 *              or wrong passphrase, but more explanation is required here.
 *  
 *  @param[in]   session    session handle
 *  @param[in]   me         identity to use for the sender
 *  @param[in]   partner    identity to use for the receiver
 *  @param[in]   type       base protocol type
 *  @param[in]   payload    payload to send
 *  @param[in]   size       size of payload
 *  @param[in]   fpr        optional key to sign or NULL
 *  @param[out]  result     returned message with payload on success
 *  
 *  @retval PEP_STATUS_OK       if no error occurred, whether or not sync message was found
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval error_status        any other value on error
 *
 *  @ownership 
 *  - On (and only on) success, ownership of payload is assigned to the result structure
 *  - Ownership of the result goes to the caller
 * 
 *  @todo Volker, I need a better explanation of the use case here to document correctly - K
 * 
 *  @see base_prepare_message()
 */

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
