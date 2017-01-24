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
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=InitState")
            switch (event) {
                case Init:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=InitState", "event=Init")
                    cond_result = storedGroupKeys(session);
                    #ifndef NDEBUG
                    char resstr[11] = {0,};
                    snprintf(resstr,10,"result=%d",cond_result);
                    #endif
                    DEBUG_LOG("FSM condition", "sync_fsm.c, state=InitState, event=Init, condition=storedGroupKeys", resstr)
                    if (cond_result < 0)
                        return cond_result;
                    if (cond_result) {
                        DEBUG_LOG("FSM transition", "sync_fsm.c, state=InitState, event=Init", "target=Grouped")
                        return Grouped;
                    }
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=InitState, event=Init", "target=Sole")
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
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=Sole")
            switch (event) {
                case Init: DEBUG_LOG("FSM event", "sync_fsm.c, state=Sole", "event=Init") break;
                case KeyGen:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Sole", "event=KeyGen")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Sole, event=KeyGen", "action=sendBeacon")
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case CannotDecrypt:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Sole", "event=CannotDecrypt")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Sole, event=CannotDecrypt", "action=sendBeacon")
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case Beacon:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Sole", "event=Beacon")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Sole, event=Beacon", "action=sendHandshakeRequest")
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    session->sync_state_payload = identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=Sole, event=Beacon", "target=SoleBeaconed")
                    return SoleBeaconed;
                }
                case HandshakeRequest:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Sole", "event=HandshakeRequest")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Sole, event=HandshakeRequest", "action=sendHandshakeRequest")
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    session->sync_state_payload = identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=Sole, event=HandshakeRequest", "target=HandshakingSole")
                    return HandshakingSole;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case SoleBeaconed:
        {
            Identity expected = (Identity)session->sync_state_payload;
            *timeout = 600;
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=SoleBeaconed")
            switch (event) {
                case Init: DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleBeaconed", "event=Init") break;
                case KeyGen:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleBeaconed", "event=KeyGen")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=SoleBeaconed, event=KeyGen", "action=sendBeacon")
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=SoleBeaconed, event=KeyGen", "target=Sole")
                    return Sole;
                }
                case CannotDecrypt:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleBeaconed", "event=CannotDecrypt")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=SoleBeaconed, event=CannotDecrypt", "action=sendBeacon")
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=SoleBeaconed, event=CannotDecrypt", "target=Sole")
                    return Sole;
                }
                case Beacon:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleBeaconed", "event=Beacon")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=SoleBeaconed, event=Beacon", "action=sendHandshakeRequest")
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    session->sync_state_payload = identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=SoleBeaconed, event=Beacon", "target=SoleBeaconed")
                    return SoleBeaconed;
                }
                case HandshakeRequest:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleBeaconed", "event=HandshakeRequest")
                    cond_result = sameIdentities(session, partner, expected);
                    #ifndef NDEBUG
                    char resstr[11] = {0,};
                    snprintf(resstr,10,"result=%d",cond_result);
                    #endif
                    DEBUG_LOG("FSM condition", "sync_fsm.c, state=SoleBeaconed, event=HandshakeRequest, condition=sameIdentities", resstr)
                    if (cond_result < 0)
                        return cond_result;
                    if (cond_result) {
                    }
                    else {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=SoleBeaconed, event=HandshakeRequest", "action=sendHandshakeRequest")
                        status = sendHandshakeRequest(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                    }
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    session->sync_state_payload = identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=SoleBeaconed, event=HandshakeRequest", "target=HandshakingSole")
                    return HandshakingSole;
                }
                case Timeout:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleBeaconed", "event=Timeout")
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=SoleBeaconed, event=Timeout", "target=Sole")
                    return Sole;
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
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=HandshakingSole")
            switch (event) {
                case Init:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingSole", "event=Init")
                    cond_result = keyElectionWon(session, partner);
                    #ifndef NDEBUG
                    char resstr[11] = {0,};
                    snprintf(resstr,10,"result=%d",cond_result);
                    #endif
                    DEBUG_LOG("FSM condition", "sync_fsm.c, state=HandshakingSole, event=Init, condition=keyElectionWon", resstr)
                    if (cond_result < 0)
                        return cond_result;
                    if (cond_result) {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=Init", "action=notifyInitFormGroup")
                        status = notifyInitFormGroup(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                    }
                    else {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=Init", "action=notifyInitAddOurDevice")
                        status = notifyInitAddOurDevice(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                    }
                    break;
                }
                case HandshakeRejected:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingSole", "event=HandshakeRejected")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=HandshakeRejected", "action=rejectHandshake")
                    status = rejectHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingSole, event=HandshakeRejected", "target=Sole")
                    return Sole;
                }
                case HandshakeAccepted:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingSole", "event=HandshakeAccepted")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted", "action=acceptHandshake")
                    status = acceptHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    cond_result = keyElectionWon(session, partner);
                    #ifndef NDEBUG
                    char resstr[11] = {0,};
                    snprintf(resstr,10,"result=%d",cond_result);
                    #endif
                    DEBUG_LOG("FSM condition", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted, condition=keyElectionWon", resstr)
                    if (cond_result < 0)
                        return cond_result;
                    if (cond_result) {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted", "action=sendGroupKeys")
                        status = sendGroupKeys(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted", "action=notifyAcceptedGroupCreated")
                        status = notifyAcceptedGroupCreated(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        if(session->sync_state_payload){
                            free_identity((Identity)session->sync_state_payload);
                            session->sync_state_payload = NULL;
                        }
                        DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted", "target=Grouped")
                        return Grouped;
                    }
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    session->sync_state_payload = identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted", "target=WaitForGroupKeysSole")
                    return WaitForGroupKeysSole;
                }
                case Cancel:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingSole", "event=Cancel")
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingSole, event=Cancel", "target=Sole")
                    return Sole;
                }
                case Timeout:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingSole", "event=Timeout")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=Timeout", "action=notifyTimeout")
                    status = notifyTimeout(session, state, expected, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=Timeout", "action=sendBeacon")
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingSole, event=Timeout", "target=Sole")
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
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=WaitForGroupKeysSole")
            switch (event) {
                case Init: DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForGroupKeysSole", "event=Init") break;
                case GroupKeys:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForGroupKeysSole", "event=GroupKeys")
                    cond_result = sameIdentities(session, partner, expected);
                    #ifndef NDEBUG
                    char resstr[11] = {0,};
                    snprintf(resstr,10,"result=%d",cond_result);
                    #endif
                    DEBUG_LOG("FSM condition", "sync_fsm.c, state=WaitForGroupKeysSole, event=GroupKeys, condition=sameIdentities", resstr)
                    if (cond_result < 0)
                        return cond_result;
                    if (cond_result) {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysSole, event=GroupKeys", "action=storeGroupKeys")
                        status = storeGroupKeys(session, state, partner, extra /*keys*/);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysSole, event=GroupKeys", "action=notifyAcceptedDeviceAdded")
                        status = notifyAcceptedDeviceAdded(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        if(session->sync_state_payload){
                            free_identity((Identity)session->sync_state_payload);
                            session->sync_state_payload = NULL;
                        }
                        DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForGroupKeysSole, event=GroupKeys", "target=Grouped")
                        return Grouped;
                    }
                    break;
                }
                case Timeout:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForGroupKeysSole", "event=Timeout")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysSole, event=Timeout", "action=notifyTimeout")
                    status = notifyTimeout(session, state, expected, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForGroupKeysSole, event=Timeout", "target=Sole")
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
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=Grouped")
            switch (event) {
                case Init:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Grouped", "event=Init")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Grouped, event=Init", "action=enterGroup")
                    status = enterGroup(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case KeyGen:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Grouped", "event=KeyGen")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Grouped, event=KeyGen", "action=sendGroupUpdate")
                    status = sendGroupUpdate(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case CannotDecrypt:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Grouped", "event=CannotDecrypt")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Grouped, event=CannotDecrypt", "action=sendUpdateRequest")
                    status = sendUpdateRequest(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case UpdateRequest:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Grouped", "event=UpdateRequest")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Grouped, event=UpdateRequest", "action=sendGroupUpdate")
                    status = sendGroupUpdate(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case Beacon:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Grouped", "event=Beacon")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Grouped, event=Beacon", "action=sendHandshakeRequest")
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    session->sync_state_payload = identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=Grouped, event=Beacon", "target=GroupedBeaconed")
                    return GroupedBeaconed;
                }
                case HandshakeRequest:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Grouped", "event=HandshakeRequest")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Grouped, event=HandshakeRequest", "action=sendHandshakeRequest")
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    session->sync_state_payload = identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=Grouped, event=HandshakeRequest", "target=HandshakingGrouped")
                    return HandshakingGrouped;
                }
                case GroupUpdate:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Grouped", "event=GroupUpdate")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Grouped, event=GroupUpdate", "action=storeGroupKeys")
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
        case GroupedBeaconed:
        {
            Identity expected = (Identity)session->sync_state_payload;
            *timeout = 600;
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=GroupedBeaconed")
            switch (event) {
                case Init: DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupedBeaconed", "event=Init") break;
                case KeyGen:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupedBeaconed", "event=KeyGen")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupedBeaconed, event=KeyGen", "action=sendGroupUpdate")
                    status = sendGroupUpdate(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case CannotDecrypt:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupedBeaconed", "event=CannotDecrypt")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupedBeaconed, event=CannotDecrypt", "action=sendUpdateRequest")
                    status = sendUpdateRequest(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case UpdateRequest:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupedBeaconed", "event=UpdateRequest")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupedBeaconed, event=UpdateRequest", "action=sendGroupUpdate")
                    status = sendGroupUpdate(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case Beacon:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupedBeaconed", "event=Beacon")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupedBeaconed, event=Beacon", "action=sendHandshakeRequest")
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    session->sync_state_payload = identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=GroupedBeaconed, event=Beacon", "target=GroupedBeaconed")
                    return GroupedBeaconed;
                }
                case HandshakeRequest:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupedBeaconed", "event=HandshakeRequest")
                    cond_result = sameIdentities(session, partner, expected);
                    #ifndef NDEBUG
                    char resstr[11] = {0,};
                    snprintf(resstr,10,"result=%d",cond_result);
                    #endif
                    DEBUG_LOG("FSM condition", "sync_fsm.c, state=GroupedBeaconed, event=HandshakeRequest, condition=sameIdentities", resstr)
                    if (cond_result < 0)
                        return cond_result;
                    if (cond_result) {
                    }
                    else {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupedBeaconed, event=HandshakeRequest", "action=sendHandshakeRequest")
                        status = sendHandshakeRequest(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                    }
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    session->sync_state_payload = identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=GroupedBeaconed, event=HandshakeRequest", "target=HandshakingGrouped")
                    return HandshakingGrouped;
                }
                case GroupUpdate:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupedBeaconed", "event=GroupUpdate")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupedBeaconed, event=GroupUpdate", "action=storeGroupKeys")
                    status = storeGroupKeys(session, state, partner, extra /*keys*/);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case Timeout:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupedBeaconed", "event=Timeout")
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=GroupedBeaconed, event=Timeout", "target=Grouped")
                    return Grouped;
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
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=HandshakingGrouped")
            switch (event) {
                case Init:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingGrouped", "event=Init")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=Init", "action=notifyInitAddOurDevice")
                    status = notifyInitAddOurDevice(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case HandshakeRejected:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingGrouped", "event=HandshakeRejected")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=HandshakeRejected", "action=rejectHandshake")
                    status = rejectHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingGrouped, event=HandshakeRejected", "target=Grouped")
                    return Grouped;
                }
                case HandshakeAccepted:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingGrouped", "event=HandshakeAccepted")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=HandshakeAccepted", "action=acceptHandshake")
                    status = acceptHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=HandshakeAccepted", "action=sendGroupKeys")
                    status = sendGroupKeys(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingGrouped, event=HandshakeAccepted", "target=Grouped")
                    return Grouped;
                }
                case Timeout:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingGrouped", "event=Timeout")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=Timeout", "action=notifyTimeout")
                    status = notifyTimeout(session, state, expected, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    if(session->sync_state_payload){
                        free_identity((Identity)session->sync_state_payload);
                        session->sync_state_payload = NULL;
                    }
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingGrouped, event=Timeout", "target=Grouped")
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

