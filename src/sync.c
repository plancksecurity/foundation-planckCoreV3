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
        inject_sync_event_t inject_sync_event,
        retrieve_next_sync_event_t retrieve_next_sync_event
    )
{
    assert(session && management && notifyHandshake && inject_sync_event && retrieve_next_sync_event);
    if (!(session && management && notifyHandshake && inject_sync_event && retrieve_next_sync_event))
        return PEP_ILLEGAL_VALUE;

    session->sync_management = management;
    session->notifyHandshake = notifyHandshake;
    session->inject_sync_event = inject_sync_event;
    session->retrieve_next_sync_event = retrieve_next_sync_event;

    return PEP_STATUS_OK;
}

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session) {
    // stop state machine
    free_Sync_state(session);

    // unregister
    session->sync_management = NULL;
    session->notifyHandshake = NULL;
    session->inject_sync_event = NULL;
    session->retrieve_next_sync_event = NULL;
}

DYNAMIC_API PEP_STATUS deliverHandshakeResult(
        PEP_SESSION session,
        pEp_identity *partner,
        sync_handshake_result result
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    int event;
    bool need_partner = false;

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

    pEp_identity *_partner = NULL;
    if(need_partner){
        _partner = identity_dup(partner);
        if (_partner == NULL)
            return PEP_OUT_OF_MEMORY;
    }
    status = send_Sync_message(session, Sync_PR_keysync, event);

    return status;
}

DYNAMIC_API PEP_STATUS do_sync_protocol(
        PEP_SESSION session,
        void *obj
    )
{
    Sync_t *msg = NULL;
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session && session->retrieve_next_sync_event);
    if (!(session && session->retrieve_next_sync_event))
        return PEP_ILLEGAL_VALUE;

    log_event(session, "sync_protocol thread started", "pEp sync protocol", NULL, NULL);

    session->sync_obj = obj;
    while (true) 
    {
        event = session->retrieve_next_sync_event(session->sync_management);
        if (msg == NULL)
            break;

        status = recv_Sync_event(session, msg);
        if (status != PEP_STATUS_OK && status != PEP_MESSAGE_IGNORE) {
            char buffer[MAX_LINELENGTH];
            memset(buffer, 0, MAX_LINELENGTH);
            snprintf(buffer, MAX_LINELENGTH, "problem with msg received: %d\n", (int) status);
            log_event(session, buffer, "pEp sync protocol", NULL, NULL);
        }
    }
    session->sync_obj = NULL;

    log_event(session, "sync_protocol thread shutdown", "pEp sync protocol", NULL, NULL);

    return PEP_STATUS_OK;
}

