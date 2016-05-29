// Driver for DeviceState state machine

#include <assert.h>
#include "pEp_internal.h"


PEP_STATUS fsm_DeviceState_inject(
        PEP_SESSION session,
        DeviceState_event event,
        Identity partner,
        DeviceState_state state_partner
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    session->sync_state = InitState;
    session->sync_state = fsm_DeviceState(session, session->sync_state,
            event, partner, state_partner);

    return status;
}

