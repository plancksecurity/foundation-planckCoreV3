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

    while(true)
    {
        DeviceState_state new_state = fsm_DeviceState(session,
            session->sync_state, event, partner, extra);

        if (new_state == DeviceState_state_invalid_out_of_memory)
            return PEP_OUT_OF_MEMORY;

        if (new_state < 0)
            return PEP_SYNC_STATEMACHINE_ERROR - new_state;
        
        if (new_state == session->sync_state)
            break;

        event = Init;
        extra = NULL;
        session->sync_state = new_state;
    } 

    return PEP_STATUS_OK;
}

