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
//      msg (in)        message struct with message to send
//
//  return value:
//      must return PEP_STATUS_OK or any other value on error

typedef PEP_STATUS (*messageToSend_t)(const message *msg);


typedef enum _sync_handshake_result {
    SYNC_HANDSHAKE_CANCEL = -1,
    SYNC_HANDSHAKE_ACCEPTED = 0,
    SYNC_HANDSHAKE_REJECTED = 1
} sync_handshake_result;

// showHandshake() - do a handshake and deliver the result
//
//  parameters:
//      self (in)       own identity
//      partner (in)    identity of partner
//
//  return value:
//      result of handshake

typedef sync_handshake_result (*showHandshake_t)(
        const pEp_identity *self,
        const pEp_identity *partner
    );


// register_sync_callbacks() - register adapter's callbacks
//
//  parameters:
//      messageToSend (in)             callback for sending beacon
//      showHandshake (in)          callback for doing the handshake
//
//  return value:
//      PEP_STATUS_OK or any other value on errror
//
//  caveat:
//      call that BEFORE you're using any other part of the engine

DYNAMIC_API PEP_STATUS register_sync_callbacks(
        messageToSend_t messageToSend,
        showHandshake_t showHandshake
    );


// unregister_sync_callbacks() - unregister adapter's callbacks

DYNAMIC_API void unregister_sync_callbacks();


#ifdef __cplusplus
}
#endif

