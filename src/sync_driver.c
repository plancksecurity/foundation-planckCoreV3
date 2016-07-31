// Driver for DeviceState state machine

#include <assert.h>
#include "pEp_internal.h"


DYNAMIC_API PEP_STATUS fsm_DeviceState_inject(
        PEP_SESSION session,
        DeviceState_event event,
        Identity partner,
        void *extra
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    session->sync_state = fsm_DeviceState(session, session->sync_state,
            event, partner, extra);

    return PEP_STATUS_OK;
}

