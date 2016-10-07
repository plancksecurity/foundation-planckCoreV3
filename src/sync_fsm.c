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
            printf("State : InitState\n");
            switch (event) {
                case Init:
                printf("Event : Init\n");
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
            printf("State : Sole\n");
            switch (event) {
                case Init: printf("Event : Init\n"); break;
                case KeyGen:
                printf("Event : KeyGen\n");
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case CannotDecrypt:
                printf("Event : CannotDecrypt\n");
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case Beacon:
                printf("Event : Beacon\n");
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case HandshakeRequest:
                printf("Event : HandshakeRequest\n");
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
            printf("State : HandshakingSole\n");
            switch (event) {
                case Init:
                printf("Event : Init\n");
                    status = showHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case HandshakeRejected:
                printf("Event : HandshakeRejected\n");
                    status = rejectHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    return Sole;
                case HandshakeAccepted:
                printf("Event : HandshakeAccepted\n");
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
                    return WaitForGroupKeysSole;
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        
        case WaitForGroupKeysSole:
            printf("State : WaitForGroupKeysSole\n");
            switch (event) {
                case Init: printf("Event : Init\n"); break;
                case GroupKeys:
                printf("Event : GroupKeys\n");
                    status = storeGroupKeys(session, state, partner, extra /*keys*/);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    return Grouped;
                case Cancel:
                printf("Event : Cancel\n");
                    return Sole;
                case Reject:
                printf("Event : Reject\n");
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
            printf("State : Grouped\n");
            switch (event) {
                case Init: printf("Event : Init\n"); break;
                case KeyGen:
                printf("Event : KeyGen\n");
                    status = sendGroupKeys(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case Beacon:
                printf("Event : Beacon\n");
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case HandshakeRequest:
                printf("Event : HandshakeRequest\n");
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    return HandshakingGrouped;
                case GroupKeys:
                printf("Event : GroupKeys\n");
                    status = storeGroupKeys(session, state, partner, extra /*keys*/);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    return Grouped;
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        
        case HandshakingGrouped:
            printf("State : HandshakingGrouped\n");
            switch (event) {
                case Init:
                printf("Event : Init\n");
                    status = showHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                case HandshakeRejected:
                printf("Event : HandshakeRejected\n");
                    status = rejectHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    return Grouped;
                case HandshakeAccepted:
                printf("Event : HandshakeAccepted\n");
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
                    return Grouped;
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        
        default:
            return (DeviceState_state) invalid_state;
    }

    return state;
}

