// Driver for DeviceState state machine

#include <assert.h>
#include "sync_fsm.h"


PEP_STATUS fsm_DeviceState_inject(PEP_SESSION session, DeviceState_event event)
{
    PEP_STATUS status = PEP_STATUS_OK;

    static DeviceState_state state = InitState;
    static Identity partner = NULL;

    state = fsm_DeviceState(state, event, partner);
    return status;
}

