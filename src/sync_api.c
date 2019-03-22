// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"

#include <memory.h>
#include <assert.h>

#include "KeySync_fsm.h"

DYNAMIC_API PEP_STATUS register_sync_callbacks(
        PEP_SESSION session,
        void *management,
        notifyHandshake_t notifyHandshake,
        retrieve_next_sync_event_t retrieve_next_sync_event
    )
{
    assert(session && notifyHandshake && retrieve_next_sync_event);
    if (!(session && notifyHandshake && retrieve_next_sync_event))
        return PEP_ILLEGAL_VALUE;

    session->sync_management = management;
    session->notifyHandshake = notifyHandshake;
    session->retrieve_next_sync_event = retrieve_next_sync_event;

    // start state machine
    return Sync_driver(session, Sync_PR_keysync, Init);
}

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session) {
    // stop state machine
    free_Sync_state(session);

    // unregister
    session->sync_management = NULL;
    session->notifyHandshake = NULL;
    session->retrieve_next_sync_event = NULL;
}

DYNAMIC_API PEP_STATUS deliverHandshakeResult(
        PEP_SESSION session,
        sync_handshake_result result
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    int event;

    switch (result) {
        case SYNC_HANDSHAKE_CANCEL:
            event = Cancel;
            break;
        case SYNC_HANDSHAKE_ACCEPTED:
        {
            event = Accept;
            break;
        }
        case SYNC_HANDSHAKE_REJECTED:
        {
            event = Reject;
            break;
        }
        default:
            return PEP_ILLEGAL_VALUE;
    }

    status = send_Sync_message(session, Sync_PR_keysync, event);

    return status;
}

DYNAMIC_API PEP_STATUS do_sync_protocol(
        PEP_SESSION session,
        void *obj
    )
{
    Sync_event_t *event= NULL;

    assert(session && session->retrieve_next_sync_event);
    if (!(session && session->retrieve_next_sync_event))
        return PEP_ILLEGAL_VALUE;

    log_event(session, "sync_protocol thread started", "pEp sync protocol",
            NULL, NULL);

    while (true) 
    {
        event = session->retrieve_next_sync_event(session->sync_management,
                SYNC_THRESHOLD);
        if (!event)
            break;

        do_sync_protocol_step(session, obj, event);
    }
    session->sync_obj = NULL;

    log_event(session, "sync_protocol thread shutdown", "pEp sync protocol",
            NULL, NULL);

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS do_sync_protocol_step(
        PEP_SESSION session,
        void *obj,
        SYNC_EVENT event
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    if (!event)
        return PEP_STATUS_OK;

    session->sync_obj = obj;

    PEP_STATUS status = recv_Sync_event(session, event);
    return status == PEP_MESSAGE_IGNORE ? PEP_STATUS_OK : status;
}

DYNAMIC_API bool is_sync_thread(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return false;
    return session->retrieve_next_sync_event != NULL;
}

DYNAMIC_API SYNC_EVENT new_sync_timeout_event()
{
    return SYNC_TIMEOUT_EVENT;
}

