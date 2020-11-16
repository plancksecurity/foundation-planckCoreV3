/**
 * @file    sync_api.h
 * @brief   sync API
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once


#include "message.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 *  @enum    sync_handshake_signal
 *  
 *  @brief    TODO
 *  
 */
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


/**
 *  <!--       notifyHandshake()       -->
 *  
 *  @brief Notify UI about sync handshaking process
 *  
 *  @param[in]   obj        object handle (implementation defined)
 *  @param[in]   me         own identity
 *  @param[in]   partner    identity of partner
 *  @param[in]   signal     reason of the notification
 *  
 *  @retval PEP_STATUS_OK or any other value on error
 *  
 *  @warning ownership of me and partner go to the callee
 *  
 */

typedef PEP_STATUS (*notifyHandshake_t)(
        pEp_identity *me,
        pEp_identity *partner,
        sync_handshake_signal signal
    );

/**
 *  @enum    sync_handshake_result
 *  
 *  @brief    TODO
 *  
 */
typedef enum _sync_handshake_result {
    SYNC_HANDSHAKE_CANCEL = -1,
    SYNC_HANDSHAKE_ACCEPTED = 0,
    SYNC_HANDSHAKE_REJECTED = 1
} sync_handshake_result;

/**
 *  <!--       deliverHandshakeResult()       -->
 *  
 *  @brief Provide the result of the handshake dialog
 *  
 *  @param[in]   session               session handle
 *  @param[in]   result                handshake result
 *  @param[in]   identities_sharing    own_identities sharing data in this group
 *  
 *  @warning identities_sharing may be NULL; in this case all identities are sharing
 *           data in the group
 *           identities_sharing may only contain own identities
 *  
 */

DYNAMIC_API PEP_STATUS deliverHandshakeResult(
        PEP_SESSION session,
        sync_handshake_result result,
        const identity_list *identities_sharing
    );


/**
 *  <!--       retrieve_next_sync_event()       -->
 *  
 *  @brief Receive next sync event
 *  
 *  @param[in]   management    application defined; usually a locked queue
 *  @param[in]   threshold     threshold in seconds for timeout
 *  
 *  @retval next event
 *  
 *  @warning an implementation of retrieve_next_sync_event must return
 *           new_sync_timeout_event() in case of timeout
 *  
 */

typedef SYNC_EVENT (*retrieve_next_sync_event_t)(void *management,
        unsigned threshold);


/**
 *  <!--       register_sync_callbacks()       -->
 *  
 *  @brief Register adapter's callbacks
 *  
 *  @param[in]   session                     session where to register callbacks
 *  @param[in]   management                  application defined; usually a locked queue
 *  @param[in]   notifyHandshake             callback for doing the handshake
 *  @param[in]   retrieve_next_sync_event    callback for receiving sync event
 *  
 *  @retval PEP_STATUS_OK or any other value on errror
 *  
 *  @warning use this function in an adapter where you're processing the sync
 *           state machine
 *           implement start_sync() in this adapter and provide it to the
 *           application, so it can trigger startup
 *           in case of parallelization start_sync() and register_sync_callbacks()
 *           will run in parallel
 *           do not return from start_sync() before register_sync_callbacks() was
 *           executed
 *           when execution of the sync state machine ends a call to
 *           unregister_sync_callbacks() is recommended
 *  
 */

DYNAMIC_API PEP_STATUS register_sync_callbacks(
        PEP_SESSION session,
        void *management,
        notifyHandshake_t notifyHandshake,
        retrieve_next_sync_event_t retrieve_next_sync_event
    );

/**
 *  <!--       unregister_sync_callbacks()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        PEP_SESSION
 *  
 */
DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session);


/**
 *  <!--       do_sync_protocol()       -->
 *  
 *  @brief Function to be run on an extra thread
 *  
 *  @retval PEP_STATUS_OK if thread has to terminate successfully or any other
 *  @retval value on failure
 *  
 *  
 */

DYNAMIC_API PEP_STATUS do_sync_protocol(
        PEP_SESSION session,
        void *obj
    );


/**
 *  <!--       do_sync_protocol_step()       -->
 *  
 *  @brief Function for single threaded implementations
 *  
 *  
 */

DYNAMIC_API PEP_STATUS do_sync_protocol_step(
        PEP_SESSION session,
        void *obj,
        SYNC_EVENT event
    );


/**
 *  <!--       is_sync_thread()       -->
 *  
 *  @brief Determine if this is sync thread's session
 *  
 *  paramters:
 *  session (in)            pEp session to test
 *  
 *  @retval true if this is sync thread's session, false otherwise
 *  
 *  
 */

DYNAMIC_API bool is_sync_thread(PEP_SESSION session);


/**
 *  <!--       new_sync_timeout_event()       -->
 *  
 *  @brief Create a Sync timeout event
 *  
 *  @retval returns a new Sync timeout event, or NULL on failure
 *  
 *  
 */

DYNAMIC_API SYNC_EVENT new_sync_timeout_event();


/**
 *  <!--       enter_device_group()       -->
 *  
 *  @brief Enter a device group
 *  
 *  @param[in]   session               pEp session
 *  @param[in]   identities_sharing    own_identities sharing data in this group
 *  
 *  @warning identities_sharing may be NULL; in this case all identities are sharing
 *           data in the group
 *           identities_sharing may only contain own identities
 *           this call can be repeated if sharing information changes
 *  
 */

DYNAMIC_API PEP_STATUS enter_device_group(
        PEP_SESSION session,
        const identity_list *identities_sharing
    );


/**
 *  <!--       disable_sync()       -->
 *  
 *  @brief Leave a device group and shutdown sync
 *  
 *  
 */

PEP_STATUS disable_sync(PEP_SESSION session);


/**
 *  <!--       leave_device_group()       -->
 *  
 *  @brief Issue a group key reset request and 
 *         leave the device group, shutting down sync 
 *  
 *  
 */

DYNAMIC_API PEP_STATUS leave_device_group(PEP_SESSION session);


/**
 *  <!--       enable_identity_for_sync()       -->
 *  
 *  @brief Enable sync for this identity
 *  
 *  
 */

DYNAMIC_API PEP_STATUS enable_identity_for_sync(PEP_SESSION session,
        pEp_identity *ident);


/**
 *  <!--       disable_identity_for_sync()       -->
 *  
 *  @brief Disable sync for this identity
 *  
 *  
 */

DYNAMIC_API PEP_STATUS disable_identity_for_sync(PEP_SESSION session,
        pEp_identity *ident);


#ifdef __cplusplus
}
#endif
