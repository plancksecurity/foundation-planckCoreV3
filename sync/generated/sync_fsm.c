#include "pEp_internal.h"
#include "sync_fsm.h"

// state machine for DeviceState

DeviceState_state fsm_DeviceState(
        PEP_SESSION session,
        DeviceState_state state,
        DeviceState_event event,
        Identity partner,
        void *extra,
        time_t *timeout
    )
{
    int cond_result;
    PEP_STATUS status = PEP_STATUS_OK;

    switch (state) {
        case InitState:
        {
            *timeout = 0;
            switch (event) {
                case Init:
                {
                    cond_result = storedGroupKeys(session);
                    if (cond_result < 0)
                        return cond_result;
                    if (cond_result) {
                        return Grouped;
                    }
                    return Sole;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case Sole:
        {
            *timeout = 0;
            switch (event) {
                case Init: break;
                case KeyGen:
                {
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case CannotDecrypt:
                {
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case Beacon:
                {
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case HandshakeRequest:
                {
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    session->sync_state_payload = identity_dup(partner);
                    return HandshakingSole;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case HandshakingSole:
        {
            Identity expected = (Identity)session->sync_state_payload;
            *timeout = 600;
            switch (event) {
                case Init:
                {
                    status = showHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case HandshakeRejected:
                {
                    status = rejectHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    return Sole;
                }
                case HandshakeAccepted:
                {
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
                        status = handshakeGroupCreated(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        if(session->sync_state_payload){
                            free_identity((Identity)session->sync_state_payload);
                            session->sync_state_payload = NULL;
                        }
                        return Grouped;
                    }
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    session->sync_state_payload = identity_dup(partner);
                    return WaitForGroupKeysSole;
                }
                case Cancel:
                {
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    return Sole;
                }
                case Timeout:
                {
                    status = dismissHandshake(session, state, expected, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    return Sole;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case WaitForGroupKeysSole:
        {
            Identity expected = (Identity)session->sync_state_payload;
            *timeout = 600;
            switch (event) {
                case Init: break;
                case GroupKeys:
                {
                    status = storeGroupKeys(session, state, partner, extra /*keys*/);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    status = handshakeSuccess(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    return Grouped;
                }
                case Timeout:
                {
                    status = handshakeFailure(session, state, expected, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    return Sole;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case Grouped:
        {
            *timeout = 0;
            switch (event) {
                case Init:
                {
                    status = enterGroup(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case KeyGen:
                {
                    status = sendGroupUpdate(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case CannotDecrypt:
                {
                    status = sendUpdateRequest(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case UpdateRequest:
                {
                    status = sendGroupUpdate(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case Beacon:
                {
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case HandshakeRequest:
                {
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    session->sync_state_payload = identity_dup(partner);
                    return HandshakingGrouped;
                }
                case GroupUpdate:
                {
                    status = storeGroupKeys(session, state, partner, extra /*keys*/);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case HandshakingGrouped:
        {
            Identity expected = (Identity)session->sync_state_payload;
            *timeout = 600;
            switch (event) {
                case Init:
                {
                    status = showHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case HandshakeRejected:
                {
                    status = rejectHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    return Grouped;
                }
                case HandshakeAccepted:
                {
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
                    status = handshakeDeviceAdded(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    return Grouped;
                }
                case Timeout:
                {
                    status = handshakeFailure(session, state, expected, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    return Grouped;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        default:
            return (DeviceState_state) invalid_state;
    }

    return state;
}

