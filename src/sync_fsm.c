#include "sync_fsm.h"

// state machine for DeviceState

DeviceState_state fsm_DeviceState(
        PEP_SESSION session,
        DeviceState_state state,
        DeviceState_event event,
        Identity partner,
        void *extra
    )
{
    int cond_result;
    PEP_STATUS status = PEP_STATUS_OK;

    switch (state) {
        case InitState:
            switch (event) {
                case Init:
                    cond_result = storedGroupKeys(session);
                    if (cond_result < 0)
                        return cond_result;
                    if (cond_result) {
                        return Grouped;
                    }
                    return Sole;
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        
        case Sole:
            switch (event) {
                case Init: break;
                case KeyGen:
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case CannotDecrypt:
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case Beacon:
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case HandshakeRequest:
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    return HandshakingSole;
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        
        case HandshakingSole:
            switch (event) {
                case Init:
                    status = showHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case HandshakeRejected:
                    status = rejectHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    return Sole;
                case HandshakeAccepted:
                    status = acceptHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    cond_result = keyElectionWon(session, partner);
                    if (cond_result < 0)
                        return cond_result;
                    if (cond_result) {
                        status = sendGroupKeys(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        return Grouped;
                    }
                    return WaitForGroupKeys;
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        
        case WaitForGroupKeys:
            switch (event) {
                case Init: break;
                case GroupKeys:
                    status = storeGroupKeys(session, state, partner, extra /*keys*/);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    return Grouped;
                case Cancel:
                    return Sole;
                case Reject:
                    status = rejectHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    return Sole;
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        
        case Grouped:
            switch (event) {
                case Init: break;
                case KeyGen:
                    status = sendGroupKeys(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case Beacon:
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case HandshakeRequest:
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    status = showHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case HandshakeRejected:
                    status = rejectHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case HandshakeAccepted:
                    status = acceptHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    status = sendGroupKeys(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case Reject:
                    status = rejectHandshake(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        
        default:
            return (DeviceState_state) invalid_state;
    }

    return state;
}

