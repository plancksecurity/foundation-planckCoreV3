#pragma once

#include "message.h"
#include "sync_fsm.h"


// this module is for being used WITHOUT the Transport API in transport.h
// DO NOT USE IT WHEN USING Transport API!


#ifdef __cplusplus
extern "C" {
#endif

// messageToSend() - send a message
//
//  parameters:
//      obj (in)        object handle (implementation defined)
//      msg (in)        message struct with message to send
//
//  return value:
//      PEP_STATUS_OK or any other value on error
//
//  caveat:
//      the ownership of msg goes to the callee

typedef PEP_STATUS (*messageToSend_t)(void *obj, message *msg);


typedef enum _sync_handshake_result {
    SYNC_HANDSHAKE_CANCEL = -1,
    SYNC_HANDSHAKE_ACCEPTED = 0,
    SYNC_HANDSHAKE_REJECTED = 1
} sync_handshake_result;

// showHandshake() - do a handshake by showing the handshake dialog
//
//  parameters:
//      obj (in)        object handle (implementation defined)
//      me (in)         own identity
//      partner (in)    identity of partner
//
//  return value:
//      PEP_STATUS_OK or any other value on error
//
//  caveat:
//      ownership of self and partner go to the callee

typedef PEP_STATUS (*showHandshake_t)(
        void *obj,
        pEp_identity *me,
        pEp_identity *partner
    );


// deliverHandshakeResult() - give the result of the handshake dialog
//
//  parameters:
//      session (in)        session handle
//      result (in)         handshake result

DYNAMIC_API PEP_STATUS deliverHandshakeResult(
        PEP_SESSION session,
        Identity partner,
        sync_handshake_result result
    );


// inject_sync_msg - inject sync protocol message
//
//  parameters:
//      msg (in)            message to inject
//      management (in)     application defined
//
//  return value:
//      0 if msg could be stored successfully or nonzero otherwise

typedef int (*inject_sync_msg_t)(void *msg, void *management);


// retrieve_next_sync_msg - receive next sync message
//
//  parameters:
//      management (in)     application defined
//
//  return value:
//      next message or NULL for termination

typedef void *(*retrieve_next_sync_msg_t)(void *management);


// register_sync_callbacks() - register adapter's callbacks
//
//  parameters:
//      session (in)                session where to store obj handle
//      obj (in)                    object handle (implementation defined)
//      messageToSend (in)          callback for sending message
//      showHandshake (in)          callback for doing the handshake
//      retrieve_next_sync_msg (in) callback for receiving sync messages
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
        showHandshake_t showHandshake,
        inject_sync_msg_t inject_sync_msg,
        retrieve_next_sync_msg_t retrieve_next_sync_msg
    );


// unregister_sync_callbacks() - unregister adapter's callbacks
//
//  parameters:
//      session (in)                session where to store obj handle

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session);


// do_sync_protocol() - function to be run on an extra thread
//
//  parameters:
//      session                 pEp session to use
//      retrieve_next_sync_msg  pointer to retrieve_next_identity() callback
//                              which returns at least a valid address field in
//                              the identity struct
//      management              management data to give to keymanagement
//                              (implementation defined)
//
//  return value:
//      PEP_STATUS_OK if thread has to terminate successfully or any other
//      value on failure
//
//  caveat:
//      to ensure proper working of this library, a thread has to be started
//      with this function immediately after initialization
//      do_keymanagement() calls retrieve_next_identity(management)

DYNAMIC_API PEP_STATUS do_sync_protocol(
        PEP_SESSION session,
        void *management
    );


// decode_sync_msg() - decode sync message from PER into XER
//
//  parameters:
//      data (in)               PER encoded data
//      size (in)               size of PER encoded data
//      text (out)              XER text of the same sync message

DYNAMIC_API PEP_STATUS decode_sync_msg(
        const char *data,
        size_t size,
        char **text
    );


// encode_sync_msg() - encode sync message from XER into PER
//
//  parameters:
//      text (in)               string with XER text of the sync message
//      data (out)              PER encoded data
//      size (out)              size of PER encoded data

DYNAMIC_API PEP_STATUS encode_sync_msg(
        const char *text,
        char **data,
        size_t *size
    );


#ifdef __cplusplus
}
#endif

