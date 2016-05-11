#pragma once

#include "message.h"


// this module is for being used WITHOUT the Transport API in transport.h
// DO NOT USE IT WHEN USING Transport API!


#ifdef __cplusplus
extern "C" {
#endif

// messageToSend() - send a beacon message
//
//  parameters:
//      obj (in)        object handle (implementation defined)
//      msg (in)        message struct with message to send
//
//  return value:
//      PEP_STATUS_OK or any other value on error

typedef PEP_STATUS (*messageToSend_t)(void *obj, const message *msg);


typedef enum _sync_handshake_result {
    SYNC_HANDSHAKE_CANCEL = -1,
    SYNC_HANDSHAKE_ACCEPTED = 0,
    SYNC_HANDSHAKE_REJECTED = 1
} sync_handshake_result;

// showHandshake() - do a handshake and deliver the result
//
//  parameters:
//      obj (in)        object handle (implementation defined)
//      self (in)       own identity
//      partner (in)    identity of partner
//      result (out)    result of handshake
//
//  return value:
//      PEP_STATUS_OK or any other value on error

typedef PEP_STATUS (*showHandshake_t)(
        void *obj,
        const pEp_identity *self,
        const pEp_identity *partner,
        sync_handshake_result *result
    );


// register_sync_callbacks() - register adapter's callbacks
//
//  parameters:
//      session (in)                session where to store obj handle
//      obj (in)                    object handle (implementation defined)
//      messageToSend (in)          callback for sending message
//      showHandshake (in)          callback for doing the handshake
//
//  return value:
//      PEP_STATUS_OK or any other value on errror
//
//  caveat:
//      call that BEFORE you're using any other part of the engine

DYNAMIC_API PEP_STATUS register_sync_callbacks(
        PEP_SESSION session,
        void *obj,
        messageToSend_t messageToSend,
        showHandshake_t showHandshake
    );


// unregister_sync_callbacks() - unregister adapter's callbacks
//
//  parameters:
//      session (in)                session where to store obj handle

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session);


#ifdef __cplusplus
}
#endif

