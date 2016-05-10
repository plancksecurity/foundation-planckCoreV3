#pragma once

#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif

// prepare_message() - prepare a sync message with payload
//
//  parameters:
//      me (in)         identity to use for the sender
//      partner (in)    identity to use for the receiver
//      payload (in)    payload to send
//      size (in)       size of payload
//      result (out)    message with payload
//
//  returns:
//      PEP_STATUS_OK on success or PEP_OUT_OF_MEMORY
//
//  caveat:
//      on success (and only then) payload goes to the ownership of the message
//      created

PEP_STATUS prepare_message(
        const pEp_identity *me,
        const pEp_identity *partner,
        char *payload,
        size_t size,
        message **result
    );

#ifdef __cplusplus
}
#endif

