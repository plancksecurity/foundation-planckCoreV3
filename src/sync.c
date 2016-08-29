#include "pEp_internal.h"

#include <memory.h>
#include <assert.h>

#include "../asn.1/DeviceGroup-Protocol.h"

// receive_sync_msg is defined in the sync_actions

PEP_STATUS receive_sync_msg(
        PEP_SESSION session,
        DeviceGroup_Protocol_t *msg
    );

DYNAMIC_API PEP_STATUS register_sync_callbacks(
        PEP_SESSION session,
        void *obj,
        messageToSend_t messageToSend,
        showHandshake_t showHandshake,
        inject_sync_msg_t inject_sync_msg,
        retrieve_next_sync_msg_t retrieve_next_sync_msg
    )
{
    unsigned char uuid[16];
    uuid_generate_random(uuid);
    uuid_unparse_upper(uuid, sync_uuid);

    session->sync_obj = obj;
    session->messageToSend = messageToSend;
    session->showHandshake = showHandshake;
    session->inject_sync_msg = inject_sync_msg;
    session->retrieve_next_sync_msg = retrieve_next_sync_msg;

    // start state machine
    session->sync_state = InitState;
    PEP_STATUS status = fsm_DeviceState_inject(session, Init, NULL, NULL);
    if (status != PEP_STATUS_OK)
        unregister_sync_callbacks(session);

    return status;
}

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session) {
    // stop state machine
    session->sync_state = DeviceState_state_NONE;

    // unregister
    session->sync_obj = NULL;
    session->messageToSend = NULL;
    session->showHandshake = NULL;
    session->retrieve_next_sync_msg = NULL;
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

    switch (result) {
        case SYNC_HANDSHAKE_CANCEL:
            status = fsm_DeviceState_inject(session, Cancel, NULL, 0);
            break;
        case SYNC_HANDSHAKE_ACCEPTED:
            status = fsm_DeviceState_inject(session, HandshakeAccepted, NULL, 0);
            break;
        case SYNC_HANDSHAKE_REJECTED:
            status = fsm_DeviceState_inject(session, HandshakeRejected, NULL, 0);
            break;
        default:
            return PEP_ILLEGAL_VALUE;
    }

    return status;
}

DYNAMIC_API PEP_STATUS do_sync_protocol(
        PEP_SESSION session,
        void *management
    )
{
    DeviceGroup_Protocol_t *msg = NULL;
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session && session->retrieve_next_sync_msg);
    assert(management);

    if (!(session && session->retrieve_next_sync_msg) || !management)
        return PEP_ILLEGAL_VALUE;

    log_event(session, "sync_protocol thread started", "pEp sync protocol", NULL, NULL);

    while ((msg = (DeviceGroup_Protocol_t *) session->retrieve_next_sync_msg(management))) 
    {
        if ((status = receive_sync_msg(session, msg) != PEP_STATUS_OK)) {
            char buffer[MAX_LINELENGTH];
            memset(buffer, 0, MAX_LINELENGTH);
            snprintf(buffer, MAX_LINELENGTH, "problem with msg received: %d\n", (int) status);
            log_event(session, buffer, "pEp sync protocol", NULL, NULL);
        }
    }

    log_event(session, "sync_protocol thread shutdown", "pEp sync protocol", NULL, NULL);

    return PEP_STATUS_OK;
}

