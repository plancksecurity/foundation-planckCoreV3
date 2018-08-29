// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once


#include "message.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef enum _sync_handshake_signal {
    SYNC_NOTIFY_UNDEFINED = 0,

    // request show handshake dialog
    SYNC_NOTIFY_INIT_ADD_OUR_DEVICE,
    SYNC_NOTIFY_INIT_ADD_OTHER_DEVICE,
    SYNC_NOTIFY_INIT_FORM_GROUP,
    SYNC_NOTIFY_INIT_MOVE_OUR_DEVICE,

    // handshake process timed out
    SYNC_NOTIFY_TIMEOUT,

    // handshake accepted by user
    SYNC_NOTIFY_ACCEPTED_DEVICE_ADDED,
    SYNC_NOTIFY_ACCEPTED_GROUP_CREATED,
    SYNC_NOTIFY_ACCEPTED_DEVICE_MOVED,

    // handshake dialog must be closed
    SYNC_NOTIFY_OVERTAKEN
} sync_handshake_signal;


// notifyHandshake() - notify UI about sync handshaking process
//
//  parameters:
//      obj (in)        object handle (implementation defined)
//      me (in)         own identity
//      partner (in)    identity of partner
//      signal (in)     reason of the notification
//
//  return value:
//      PEP_STATUS_OK or any other value on error
//
//  caveat:
//      ownership of self and partner go to the callee

typedef PEP_STATUS (*notifyHandshake_t)(
        void *obj,
        pEp_identity *me,
        pEp_identity *partner,
        sync_handshake_signal signal
    );

typedef enum _sync_handshake_result {
    SYNC_HANDSHAKE_CANCEL = -1,
    SYNC_HANDSHAKE_ACCEPTED = 0,
    SYNC_HANDSHAKE_REJECTED = 1
} sync_handshake_result;

// deliverHandshakeResult() - give the result of the handshake dialog
//
//  parameters:
//      session (in)        session handle
//      result (in)         handshake result

DYNAMIC_API PEP_STATUS deliverHandshakeResult(
        PEP_SESSION session,
        pEp_identity *partner,
        sync_handshake_result result
    );


// retrieve_next_sync_event - receive next sync event
//
//  parameters:
//      management (in)     application defined; usually a locked queue
//      threshold (in)      threshold in seconds for timeout
//
//  return value:
//      next event

typedef SYNC_EVENT (*retrieve_next_sync_event_t)(void *management,
        time_t threshold);


// register_sync_callbacks() - register adapter's callbacks
//
//  parameters:
//      session (in)                    session where to store obj handle
//      management (in)                 application defined; usually a locked queue
//      notifyHandshake (in)            callback for doing the handshake
//      retrieve_next_sync_event (in)   callback for receiving sync event
//
//  return value:
//      PEP_STATUS_OK or any other value on errror
//
//  caveat:
//      call that BEFORE you're using any other part of the engine

DYNAMIC_API PEP_STATUS register_sync_callbacks(
        PEP_SESSION session,
        void *management,
        notifyHandshake_t notifyHandshake,
        retrieve_next_sync_event_t retrieve_next_sync_event
    );

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session);


// do_sync_protocol() - function to be run on an extra thread
//
//  parameters:
//      session                 pEp session to use
//      retrieve_next_sync_msg  pointer to retrieve_next_identity() callback
//                              which returns at least a valid address field in
//                              the identity struct
//      obj                     application defined sync object
//
//  return value:
//      PEP_STATUS_OK if thread has to terminate successfully or any other
//      value on failure

DYNAMIC_API PEP_STATUS do_sync_protocol(
        PEP_SESSION session,
        void *obj
    );


// do_sync_protocol_step() - function for single threaded implementations
//
//  parameters:
//      session                 pEp session to use
//      retrieve_next_sync_msg  pointer to retrieve_next_identity() callback
//                              which returns at least a valid address field in
//                              the identity struct
//      obj                     application defined sync object
//      event                   Sync event to process

DYNAMIC_API PEP_STATUS do_sync_protocol_step(
        PEP_SESSION session,
        void *obj,
        SYNC_EVENT event
    );


// is_sync_thread() - determine if this is sync thread's session
//
//  paramters:
//      session                 pEp session to test
//
//  return value:
//      true if this is sync thread's session, false otherwise

DYNAMIC_API bool is_sync_thread(PEP_SESSION session);


#ifdef __cplusplus
}
#endif

