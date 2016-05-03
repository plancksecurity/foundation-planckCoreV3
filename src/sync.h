#pragma once

#include "message.h"


// this module is for being used WITHOUT the Transport API in transport.h
// DO NOT USE IT WHEN USING Transport API!


#ifdef __cplusplus
extern "C" {
#endif

// sendBeacon() - send a beacon message
//
//  parameters:
//      beacon (in)     message struct with beacon message to send
//
//  return value:
//      must return PEP_STATUS_OK or any other value on error

typedef PEP_STATUS (*sendBeacon_t)(message beacon);


// sendHandshakeRequest() - send a handshake request message
//
//  parameters:
//      request (in)    message struct with beacon message to send
//
//  return value:
//      must return PEP_STATUS_OK or any other value on error

typedef PEP_STATUS (*sendHandshakeRequest_t)(message request);


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
        pEp_identity self,
        pEp_identity partner
    );


// register_sync_callbacks() - register adapter's callbacks
//
//  parameters:
//      session (in)                session handle
//      sendBeacon (in)             callback for sending beacon
//      sendHandshakeRequest (in)   callback for sending handshake request
//      showHandshake (in)          callback for doing the handshake
//
//  return value:
//      PEP_STATUS_OK or any other value on errror

DYNAMIC_API PEP_STATUS register_sync_callbacks(
        PEP_SESSION session,
        sendBeacon_t sendBeacon,
        sendHandshakeRequest_t sendHandshakeRequest,
        showHandshake_t showHandshake
    );


// unregister_sync_callbacks() - unregister adapter's callbacks
//
//  parameters:
//      session (in)                session handle

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session);


#ifdef __cplusplus
}
#endif

