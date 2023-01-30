// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef SYNC_API_H
#define SYNC_API_H


#include "message.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef enum _sync_handshake_signal {
    SYNC_NOTIFY_UNDEFINED = 0,

    // request show handshake dialog
    SYNC_NOTIFY_INIT_ADD_OUR_DEVICE = 1,
    SYNC_NOTIFY_INIT_ADD_OTHER_DEVICE = 2,
    SYNC_NOTIFY_INIT_FORM_GROUP = 3,
    // SYNC_NOTIFY_INIT_MOVE_OUR_DEVICE = 4,

    // handshake process timed out
    SYNC_NOTIFY_TIMEOUT = 5,

    // handshake accepted by user
    SYNC_NOTIFY_ACCEPTED_DEVICE_ADDED = 6,
    SYNC_NOTIFY_ACCEPTED_GROUP_CREATED = 7,
    SYNC_NOTIFY_ACCEPTED_DEVICE_ACCEPTED = 8,

    // handshake dialog must be closed
    // SYNC_NOTIFY_OVERTAKEN = 9,

    // forming group
    // SYNC_NOTIFY_FORMING_GROUP = 10,

    // The rating of an outgoing message being composed may have changed because
    // of a received Distribugion.Echo message: an application in which a
    // message is being compose should recompute its rating and display a new
    // colour.
    SYNC_NOTIFY_OUTGOING_RATING_CHANGE = 64,
    
    // these two notifications must be evaluated by applications, which are
    // using a Desktop Adapter
    SYNC_NOTIFY_START = 126,
    SYNC_NOTIFY_STOP = 127,

    // message cannot be sent, need passphrase
    SYNC_PASSPHRASE_REQUIRED = 128,

    // notification of actual group status
    SYNC_NOTIFY_SOLE = 254,
    SYNC_NOTIFY_IN_GROUP = 255
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
//      ownership of me and partner go to the callee

typedef PEP_STATUS (*notifyHandshake_t)(
        pEp_identity *me,
        pEp_identity *partner,
        sync_handshake_signal signal
    );

typedef enum _sync_handshake_result {
    SYNC_HANDSHAKE_CANCEL = -1,
    SYNC_HANDSHAKE_ACCEPTED = 0,
    SYNC_HANDSHAKE_REJECTED = 1
} sync_handshake_result;

// deliverHandshakeResult() - provide the result of the handshake dialog
//
//  parameters:
//      session (in)            session handle
//      result (in)             handshake result
//      identities_sharing (in) own_identities sharing data in this group
//
//  caveat:
//      identities_sharing may be NULL; in this case all identities are sharing
//      data in the group
//      identities_sharing may only contain own identities

DYNAMIC_API PEP_STATUS deliverHandshakeResult(
        PEP_SESSION session,
        sync_handshake_result result,
        const identity_list *identities_sharing
    );


// retrieve_next_sync_event - receive next sync event
//
//  parameters:
//      management (in)     application defined; usually a locked queue
//      threshold (in)      threshold in seconds for timeout
//
//  return value:
//      next event
//
//  caveat:
//      an implementation of retrieve_next_sync_event must return
//      new_sync_timeout_event() in case of timeout

typedef SYNC_EVENT (*retrieve_next_sync_event_t)(void *management,
        unsigned threshold);


// register_sync_callbacks() - register adapter's callbacks
//
//  parameters:
//      session (in)                    session where to register callbacks
//      management (in)                 application defined; usually a locked queue
//      notifyHandshake (in)            callback for doing the handshake
//      retrieve_next_sync_event (in)   callback for receiving sync event
//
//  return value:
//      PEP_STATUS_OK or any other value on errror
//
//  caveat:
//      use this function in an adapter where you're processing the sync
//      state machine
//
//      implement start_sync() in this adapter and provide it to the
//      application, so it can trigger startup
//
//      in case of parallelization start_sync() and register_sync_callbacks()
//      will run in parallel
//
//      do not return from start_sync() before register_sync_callbacks() was
//      executed
//
//      when execution of the sync state machine ends a call to
//      unregister_sync_callbacks() is recommended

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

/**
 *  <!--       do_sync_protocol_init()       -->
 *  
 *  @brief Function for manual implementations
 *  
 *  
 */

DYNAMIC_API PEP_STATUS do_sync_protocol_init(PEP_SESSION session);

// do_sync_protocol_step() - function for manual implementations
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
//      session (in)            pEp session to test
//
//  return value:
//      true if this is sync thread's session, false otherwise

DYNAMIC_API bool is_sync_thread(PEP_SESSION session);


// new_sync_timeout_event() - create a Sync timeout event
//
//  return value:
//      returns a new Sync timeout event, or NULL on failure

DYNAMIC_API SYNC_EVENT new_sync_timeout_event();


// enter_device_group() - enter a device group
//
//  parameters:
//      session (in)            pEp session
//      identities_sharing (in) own_identities sharing data in this group
//
//  caveat:
//      identities_sharing may be NULL; in this case all identities are sharing
//      data in the group
//      identities_sharing may only contain own identities
//
//      this call can be repeated if sharing information changes

DYNAMIC_API PEP_STATUS enter_device_group(
        PEP_SESSION session,
        const identity_list *identities_sharing
    );


// disable_sync() - leave a device group and shutdown sync
//
//  parameters:
//      session                 pEp session

PEP_STATUS disable_sync(PEP_SESSION session);


// leave_device_group() - Issue a group key reset request and 
// leave the device group, shutting down sync 
//
//  parameters:
//      session                 pEp session

DYNAMIC_API PEP_STATUS leave_device_group(PEP_SESSION session);


// enable_identity_for_sync() - enable sync for this identity
//  parameters:
//      session                 pEp session
//      ident                   own identity to enable

DYNAMIC_API PEP_STATUS enable_identity_for_sync(PEP_SESSION session,
        pEp_identity *ident);


// disable_identity_for_sync() - disable sync for this identity
//  parameters:
//      session                 pEp session
//      ident                   own identity to disable

DYNAMIC_API PEP_STATUS disable_identity_for_sync(PEP_SESSION session,
        pEp_identity *ident);


/**
 *  <!--       disable_all_sync_channels()       -->
 *
 *  @brief Disable sync for all identities; use this function to reset
 *         the state which identities will be synced and which not
 *         This function is intended to be used at app init
 *
 *
 */

DYNAMIC_API PEP_STATUS disable_all_sync_channels(PEP_SESSION session);

/**
 *  <!--       enter_device_group()       -->
 *  
 *  @brief Explicitly reinitialize Sync.  This is meant to be explicitly called
 *         from the application upon user request (of course through the
 *         adaptor).
 *  
 *  @param[in]   session               pEp session
 *  
 */
DYNAMIC_API PEP_STATUS sync_reinit(PEP_SESSION session);

#ifdef __cplusplus
}
#endif

#endif
