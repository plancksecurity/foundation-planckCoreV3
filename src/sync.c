#include "pEp_internal.h"

#include <memory.h>
#include <assert.h>

#include "../asn.1/DeviceGroup-Protocol.h"


DYNAMIC_API PEP_STATUS register_sync_callbacks(
        PEP_SESSION session,
        void *obj,
        messageToSend_t messageToSend,
        showHandshake_t showHandshake
    )
{
    session->sync_obj = obj;
    session->messageToSend = messageToSend;
    session->showHandshake = showHandshake;

    return PEP_STATUS_OK;
}

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session) {
    session->sync_obj = NULL;
    session->messageToSend = NULL;
    session->showHandshake = NULL;
}

DYNAMIC_API PEP_STATUS deliverHandshakeResult(
        PEP_SESSION session,
        sync_handshake_result result
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    switch (result) {
        case SYNC_HANDSHAKE_CANCEL:
            fsm_DeviceState_inject(session, Cancel, NULL, 0);
            break;
        case SYNC_HANDSHAKE_ACCEPTED:
            fsm_DeviceState_inject(session, HandshakeAccepted, NULL, 0);
            break;
        case SYNC_HANDSHAKE_REJECTED:
            fsm_DeviceState_inject(session, HandshakeRejected, NULL, 0);
            break;
        default:
            return PEP_ILLEGAL_VALUE;
    }

    return PEP_STATUS_OK;
}

