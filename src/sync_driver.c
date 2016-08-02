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

    DeviceState_state state = fsm_DeviceState(session,
            session->sync_state, event, partner, extra);
    if (state == invalid_out_of_memory)
        return PEP_OUT_OF_MEMORY;
    if (state < 0)
        return PEP_SYNC_STATEMACHINE_ERROR - state;

    session->sync_state = state;
    return PEP_STATUS_OK;
}

