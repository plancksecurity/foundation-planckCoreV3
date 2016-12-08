/*
====================================
Engine/adapter/app KeySync interface 
====================================

In the engine, KeySync is implemented through a state machine [1]. KeySync
state machine is driven [2] by events, triggering actions [3] and transitions
to new states. Events happens on decryption of email messages, on key
generation, on user interaction through the app and in case of timeout when
staying too long in some particular states.

To use KeySync, the adapter has to create a session dedicated to handle the
protocol, register some callbacks [4] to the engine, and then call protocol's
event consumer loop [5] in a dedicated thread. KeySync actions are executed
as callback invoked from that loop : send pEp messages through app's transport
and display KeySync status and handshake to the user.

When a session is attached [6] to a KeySync session, decryption of pEp (email)
messages in that session may trigger operations in attached KeySync session. In
case of an adapter capable to serve multiple apps, each app is associated to a
different KeySync session, and sessions created for use in that app are
attached to that session.

KeySync messages [7], not to be confused with pEp (email) messages, are either
directly events to be processed by the state machine or KeySync payloads
collected from decrypted messages. They are jobs to be processed by the state
machine.

KeySync messages can be emitted by multiple session, and could naturally come
from different threads. They must be serialized in a locked queue. Attached
sessions inject [8] KeySync messages in the queue. Protocol loop retrieves [9]
them from the queue. KeySync message is received [10] by the state machine,
where event eventually deduced from payload.

A state timeout event is a particular case. It doesn't traverse the queue, and
isn't emitted by a session. It is triggered by a timeout on the retrieve
operation. Value of the timeout is determined when entering a new state, and is
passed as a parameter of the call to the blocking queue retrieve operation on 
next protocol loop iteraton.

[1] sync/device_group.fsm , src/sync_fsm.c (generated)
[2] src/sync_driver.c (generated)
[3] src/sync_actions.c , src/sync_send_actions.c (generated)
[4] register_sync_callbacks()
[5] do_sync_protocol()
[6] attach_sync_session()
[7] type sync_msg_t
[8] callback inject_sync_msg
[9] callback retrieve_next_sync_msg
[10] receive_sync_msg() (src/sync_impl.c)

*/

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

typedef enum _sync_handshake_signal {
    SYNC_NOTIFY_UNDEFINED = 0,

    // request show handshake dialog
    SYNC_NOTIFY_INIT_ADD_OUR_DEVICE,
    SYNC_NOTIFY_INIT_ADD_OTHER_DEVICE,
    SYNC_NOTIFY_INIT_FORM_GROUP,

    // handshake process was cancelled
    SYNC_NOTIFY_CANCELED,

    // handshake accepted by user
    SYNC_NOTIFY_ACCEPTED_DEVICE_ADDED,
    SYNC_NOTIFY_ACCEPTED_GROUP_CREATED,

    // handshake was rejected by user
    SYNC_NOTIFY_REJECTED
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
        Identity partner,
        sync_handshake_result result
    );

// sync_msg_t - items queued for serialized handling by protocol engine
typedef struct _sync_msg_t sync_msg_t;

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
//      timeout (in,out)    do not wait longer than timeout for message
//
//  return value:
//      next message or :
//      NULL and timeout == 0 for termination
//      NULL and timeout != 0 for timeout occurence

typedef void *(*retrieve_next_sync_msg_t)(void *management, time_t *timeout);


// register_sync_callbacks() - register adapter's callbacks
//
//  parameters:
//      session (in)                session where to store obj handle
//      management (in)             application defined
//      messageToSend (in)          callback for sending message
//      notifyHandshake (in)        callback for doing the handshake
//      retrieve_next_sync_msg (in) callback for receiving sync messages
//
//  return value:
//      PEP_STATUS_OK or any other value on errror
//
//  caveat:
//      call that BEFORE you're using any other part of the engine

DYNAMIC_API PEP_STATUS register_sync_callbacks(
        PEP_SESSION session,
        void *management,
        messageToSend_t messageToSend,
        notifyHandshake_t notifyHandshake,
        inject_sync_msg_t inject_sync_msg,
        retrieve_next_sync_msg_t retrieve_next_sync_msg
    );

// attach_sync_session() - attach session to a session running keysync state machine 
//
//  parameters:
//      session (in)                session to attach
//      sync_session (in)           session running keysync
//
//  return value:
//      PEP_STATUS_OK or any other value on errror
//
//  caveat:
//      register_sync_callbacks must have been called on sync_session
//      call that BEFORE you're using that session in any other part of the engine

DYNAMIC_API PEP_STATUS attach_sync_session(
        PEP_SESSION session,
        PEP_SESSION sync_session
    );

// detach_sync_session() - detach previously attached sync session
//
//  parameters:
//      session (in)                session to detach 

DYNAMIC_API PEP_STATUS detach_sync_session(PEP_SESSION session);

// unregister_sync_callbacks() - unregister adapter's callbacks
//
//  parameters:
//      session (in)                session to unregister

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
//
//  caveat:
//      to ensure proper working of this library, a thread has to be started
//      with this function immediately after initialization

DYNAMIC_API PEP_STATUS do_sync_protocol(
        PEP_SESSION session,
        void *obj
    );

// free_sync_msg() - free sync_msg_t struct when not passed to do_sync_protocol  
//
//  parameters:
//      sync_msg (in)            pointer to sync_msg_t struct to free

DYNAMIC_API void free_sync_msg(sync_msg_t *sync_msg);

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

