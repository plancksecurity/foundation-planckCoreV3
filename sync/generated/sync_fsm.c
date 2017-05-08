#include "pEp_internal.h"
#include "sync_fsm.h"
#include "sync_impl.h"

// local definitions for DeviceState's state machine 

typedef struct _SoleBeaconed_state_payload {
    Identity expected;
} SoleBeaconed_state_payload_t;

typedef struct _HandshakingSole_state_payload {
    Identity expected;
} HandshakingSole_state_payload_t;

typedef struct _WaitForGroupKeysSole_state_payload {
    Identity expected;
} WaitForGroupKeysSole_state_payload_t;

typedef struct _WaitForAcceptSole_state_payload {
    Identity expected;
    group_keys_extra_t* groupkeys;
} WaitForAcceptSole_state_payload_t;

typedef struct _GroupedBeaconed_state_payload {
    Identity expected;
} GroupedBeaconed_state_payload_t;

typedef struct _HandshakingGrouped_state_payload {
    Identity expected;
} HandshakingGrouped_state_payload_t;

typedef struct _WaitForGroupKeysGrouped_state_payload {
    Identity expected;
} WaitForGroupKeysGrouped_state_payload_t;

typedef struct _WaitForAcceptGrouped_state_payload {
    Identity expected;
    group_keys_extra_t* groupkeys;
} WaitForAcceptGrouped_state_payload_t;


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
    PEP_STATUS status = PEP_STATUS_OK;

    switch (state) {
        case InitState:
        {
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=InitState")
            switch (event) {
                case Init:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=InitState", "event=Init")
                    *timeout = 0;
                    {
                        int cond_result = deviceGrouped(session);
                        #ifndef NDEBUG
                        char resstr[11] = {0,};
                        snprintf(resstr,10,"result=%d",cond_result);
                        #endif
                        DEBUG_LOG("FSM condition", "sync_fsm.c, state=InitState, event=Init, condition=deviceGrouped", resstr)
                        if (cond_result < 0)
                            return cond_result;
                        if (cond_result) {
                        DEBUG_LOG("FSM transition", "sync_fsm.c, state=InitState, event=Init", "target=Grouped")
                        return Grouped;
                        }
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
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=Sole")
            switch (event) {
                case Init: 
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Sole", "event=Init") 
                    *timeout = 0;
                    break;
                case KeyGen:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Sole", "event=KeyGen")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Sole, event=KeyGen", "action=sendBeacon")
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=Sole, event=KeyGen", "target=SoleWaiting")
                    return SoleWaiting;
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
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=Sole, event=CannotDecrypt", "target=SoleWaiting")
                    return SoleWaiting;
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
                    session->sync_state_payload = malloc(sizeof(SoleBeaconed_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((SoleBeaconed_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
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
                    session->sync_state_payload = malloc(sizeof(HandshakingSole_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((HandshakingSole_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=Sole, event=HandshakeRequest", "target=HandshakingSole")
                    return HandshakingSole;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case SoleWaiting:
        {
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=SoleWaiting")
            switch (event) {
                case Init: 
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleWaiting", "event=Init") 
                    *timeout = 60;
                    break;
                case KeyGen:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleWaiting", "event=KeyGen")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=SoleWaiting, event=KeyGen", "action=sendBeacon")
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case CannotDecrypt:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleWaiting", "event=CannotDecrypt")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=SoleWaiting, event=CannotDecrypt", "action=sendBeacon")
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case Beacon:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleWaiting", "event=Beacon")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=SoleWaiting, event=Beacon", "action=sendHandshakeRequest")
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    session->sync_state_payload = malloc(sizeof(SoleBeaconed_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((SoleBeaconed_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=SoleWaiting, event=Beacon", "target=SoleBeaconed")
                    return SoleBeaconed;
                }
                case HandshakeRequest:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleWaiting", "event=HandshakeRequest")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=SoleWaiting, event=HandshakeRequest", "action=sendHandshakeRequest")
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    session->sync_state_payload = malloc(sizeof(HandshakingSole_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((HandshakingSole_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=SoleWaiting, event=HandshakeRequest", "target=HandshakingSole")
                    return HandshakingSole;
                }
                case Timeout:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleWaiting", "event=Timeout")
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=SoleWaiting, event=Timeout", "target=Sole")
                    return Sole;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case SoleBeaconed:
        {
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=SoleBeaconed")
            assert(session->sync_state_payload);
            if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
            Identity expected = ((SoleBeaconed_state_payload_t*)session->sync_state_payload)->expected;
            switch (event) {
                case Init: 
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleBeaconed", "event=Init") 
                    *timeout = 600;
                    break;
                case KeyGen:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleBeaconed", "event=KeyGen")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=SoleBeaconed, event=KeyGen", "action=sendBeacon")
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((SoleBeaconed_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
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
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((SoleBeaconed_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
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
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((SoleBeaconed_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    session->sync_state_payload = malloc(sizeof(SoleBeaconed_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((SoleBeaconed_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=SoleBeaconed, event=Beacon", "target=SoleBeaconed")
                    return SoleBeaconed;
                }
                case HandshakeRequest:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleBeaconed", "event=HandshakeRequest")
                    {
                        int cond_result = sameIdentities(session, partner, expected);
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
                    }
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((SoleBeaconed_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    session->sync_state_payload = malloc(sizeof(HandshakingSole_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((HandshakingSole_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=SoleBeaconed, event=HandshakeRequest", "target=HandshakingSole")
                    return HandshakingSole;
                }
                case Timeout:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=SoleBeaconed", "event=Timeout")
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((SoleBeaconed_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
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
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=HandshakingSole")
            assert(session->sync_state_payload);
            if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
            Identity expected = ((HandshakingSole_state_payload_t*)session->sync_state_payload)->expected;
            switch (event) {
                case Init:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingSole", "event=Init")
                    *timeout = 600;
                    {
                        int cond_result = keyElectionWon(session, expected);
                        #ifndef NDEBUG
                        char resstr[11] = {0,};
                        snprintf(resstr,10,"result=%d",cond_result);
                        #endif
                        DEBUG_LOG("FSM condition", "sync_fsm.c, state=HandshakingSole, event=Init, condition=keyElectionWon", resstr)
                        if (cond_result < 0)
                            return cond_result;
                        if (cond_result) {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=Init", "action=notifyInitFormGroup")
                        status = notifyInitFormGroup(session, state, expected, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        }
                        else {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=Init", "action=notifyInitAddOurDevice")
                        status = notifyInitAddOurDevice(session, state, expected, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        }
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
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((HandshakingSole_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingSole, event=HandshakeRejected", "target=Sole")
                    return Sole;
                }
                case HandshakeAccepted:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingSole", "event=HandshakeAccepted")
                    {
                        int cond_result = sameIdentities(session, partner, expected);
                        #ifndef NDEBUG
                        char resstr[11] = {0,};
                        snprintf(resstr,10,"result=%d",cond_result);
                        #endif
                        DEBUG_LOG("FSM condition", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted, condition=sameIdentities", resstr)
                        if (cond_result < 0)
                            return cond_result;
                        if (cond_result) {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted", "action=acceptHandshake")
                        status = acceptHandshake(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        {
                            int cond_result = keyElectionWon(session, partner);
                            #ifndef NDEBUG
                            char resstr[11] = {0,};
                            snprintf(resstr,10,"result=%d",cond_result);
                            #endif
                            DEBUG_LOG("FSM condition", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted, condition=keyElectionWon", resstr)
                            if (cond_result < 0)
                                return cond_result;
                            if (cond_result) {
                            DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted", "action=makeGroup")
                            status = makeGroup(session, state, NULL, NULL);
                            if (status == PEP_OUT_OF_MEMORY)
                                return (int) invalid_out_of_memory;
                            if (status != PEP_STATUS_OK)
                                return (int) invalid_action;
                            DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted", "action=sendGroupKeys")
                            status = sendGroupKeys(session, state, partner, NULL);
                            if (status == PEP_OUT_OF_MEMORY)
                                return (int) invalid_out_of_memory;
                            if (status != PEP_STATUS_OK)
                                return (int) invalid_action;
                            DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted", "action=renewUUID")
                            status = renewUUID(session, state, NULL, NULL);
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
                            assert(session->sync_state_payload);
                            if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                            free_identity(((HandshakingSole_state_payload_t*)session->sync_state_payload)->expected);
                            free(session->sync_state_payload);
                            session->sync_state_payload = NULL;
                            DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted", "target=Grouped")
                            return Grouped;
                            }
                        }
                        assert(session->sync_state_payload);
                        if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                        free_identity(((HandshakingSole_state_payload_t*)session->sync_state_payload)->expected);
                        free(session->sync_state_payload);
                        session->sync_state_payload = NULL;
                        session->sync_state_payload = malloc(sizeof(WaitForGroupKeysSole_state_payload_t));
                        assert(session->sync_state_payload);
                        if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                        ((WaitForGroupKeysSole_state_payload_t*)session->sync_state_payload)->expected =
                            identity_dup(partner);
                        DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted", "target=WaitForGroupKeysSole")
                        return WaitForGroupKeysSole;
                        }
                    }
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((HandshakingSole_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingSole, event=HandshakeAccepted", "target=Sole")
                    return Sole;
                }
                case Cancel:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingSole", "event=Cancel")
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((HandshakingSole_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingSole, event=Cancel", "target=Sole")
                    return Sole;
                }
                case GroupKeys:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingSole", "event=GroupKeys")
                    group_keys_extra_t* groupkeys = (group_keys_extra_t*)extra;
                    {
                        int cond_result = keyElectionWon(session, expected);
                        #ifndef NDEBUG
                        char resstr[11] = {0,};
                        snprintf(resstr,10,"result=%d",cond_result);
                        #endif
                        DEBUG_LOG("FSM condition", "sync_fsm.c, state=HandshakingSole, event=GroupKeys, condition=keyElectionWon", resstr)
                        if (cond_result < 0)
                            return cond_result;
                        if (cond_result) {
                        }
                        else {
                        {
                            int cond_result = sameKeyAndAddress(session, partner, expected);
                            #ifndef NDEBUG
                            char resstr[11] = {0,};
                            snprintf(resstr,10,"result=%d",cond_result);
                            #endif
                            DEBUG_LOG("FSM condition", "sync_fsm.c, state=HandshakingSole, event=GroupKeys, condition=sameKeyAndAddress", resstr)
                            if (cond_result < 0)
                                return cond_result;
                            if (cond_result) {
                            assert(session->sync_state_payload);
                            if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                            free_identity(((HandshakingSole_state_payload_t*)session->sync_state_payload)->expected);
                            free(session->sync_state_payload);
                            session->sync_state_payload = NULL;
                            session->sync_state_payload = malloc(sizeof(WaitForAcceptSole_state_payload_t));
                            assert(session->sync_state_payload);
                            if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                            ((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->expected =
                                identity_dup(partner);
                            ((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->groupkeys =
                                group_keys_extra_dup(groupkeys);
                            DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingSole, event=GroupKeys", "target=WaitForAcceptSole")
                            return WaitForAcceptSole;
                            }
                        }
                        }
                    }
                    break;
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
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((HandshakingSole_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
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
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=WaitForGroupKeysSole")
            assert(session->sync_state_payload);
            if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
            Identity expected = ((WaitForGroupKeysSole_state_payload_t*)session->sync_state_payload)->expected;
            switch (event) {
                case Init: 
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForGroupKeysSole", "event=Init") 
                    *timeout = 600;
                    break;
                case GroupKeys:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForGroupKeysSole", "event=GroupKeys")
                    group_keys_extra_t* groupkeys = (group_keys_extra_t*)extra;
                    {
                        int cond_result = sameKeyAndAddress(session, partner, expected);
                        #ifndef NDEBUG
                        char resstr[11] = {0,};
                        snprintf(resstr,10,"result=%d",cond_result);
                        #endif
                        DEBUG_LOG("FSM condition", "sync_fsm.c, state=WaitForGroupKeysSole, event=GroupKeys, condition=sameKeyAndAddress", resstr)
                        if (cond_result < 0)
                            return cond_result;
                        if (cond_result) {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysSole, event=GroupKeys", "action=storeGroupKeys")
                        status = storeGroupKeys(session, state, partner, groupkeys);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysSole, event=GroupKeys", "action=sendGroupUpdate")
                        status = sendGroupUpdate(session, state, NULL, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysSole, event=GroupKeys", "action=renewUUID")
                        status = renewUUID(session, state, NULL, NULL);
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
                        assert(session->sync_state_payload);
                        if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                        free_identity(((WaitForGroupKeysSole_state_payload_t*)session->sync_state_payload)->expected);
                        free(session->sync_state_payload);
                        session->sync_state_payload = NULL;
                        DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForGroupKeysSole, event=GroupKeys", "target=Grouped")
                        return Grouped;
                        }
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
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((WaitForGroupKeysSole_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForGroupKeysSole, event=Timeout", "target=Sole")
                    return Sole;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case WaitForAcceptSole:
        {
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=WaitForAcceptSole")
            assert(session->sync_state_payload);
            if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
            Identity expected = ((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->expected;
            group_keys_extra_t* groupkeys = ((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->groupkeys;
            switch (event) {
                case Init: 
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForAcceptSole", "event=Init") 
                    *timeout = 600;
                    break;
                case HandshakeRejected:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForAcceptSole", "event=HandshakeRejected")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptSole, event=HandshakeRejected", "action=rejectHandshake")
                    status = rejectHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->expected);
                    free_group_keys_extra(((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->groupkeys);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForAcceptSole, event=HandshakeRejected", "target=Sole")
                    return Sole;
                }
                case HandshakeAccepted:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForAcceptSole", "event=HandshakeAccepted")
                    {
                        int cond_result = sameKeyAndAddress(session, partner, expected);
                        #ifndef NDEBUG
                        char resstr[11] = {0,};
                        snprintf(resstr,10,"result=%d",cond_result);
                        #endif
                        DEBUG_LOG("FSM condition", "sync_fsm.c, state=WaitForAcceptSole, event=HandshakeAccepted, condition=sameKeyAndAddress", resstr)
                        if (cond_result < 0)
                            return cond_result;
                        if (cond_result) {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptSole, event=HandshakeAccepted", "action=acceptHandshake")
                        status = acceptHandshake(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptSole, event=HandshakeAccepted", "action=storeGroupKeys")
                        status = storeGroupKeys(session, state, partner, groupkeys);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptSole, event=HandshakeAccepted", "action=sendGroupUpdate")
                        status = sendGroupUpdate(session, state, NULL, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptSole, event=HandshakeAccepted", "action=renewUUID")
                        status = renewUUID(session, state, NULL, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptSole, event=HandshakeAccepted", "action=notifyAcceptedDeviceAdded")
                        status = notifyAcceptedDeviceAdded(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        assert(session->sync_state_payload);
                        if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                        free_identity(((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->expected);
                        free_group_keys_extra(((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->groupkeys);
                        free(session->sync_state_payload);
                        session->sync_state_payload = NULL;
                        DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForAcceptSole, event=HandshakeAccepted", "target=Grouped")
                        return Grouped;
                        }
                    }
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->expected);
                    free_group_keys_extra(((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->groupkeys);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForAcceptSole, event=HandshakeAccepted", "target=Sole")
                    return Sole;
                }
                case Cancel:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForAcceptSole", "event=Cancel")
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->expected);
                    free_group_keys_extra(((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->groupkeys);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForAcceptSole, event=Cancel", "target=Sole")
                    return Sole;
                }
                case Timeout:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForAcceptSole", "event=Timeout")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptSole, event=Timeout", "action=notifyTimeout")
                    status = notifyTimeout(session, state, expected, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->expected);
                    free_group_keys_extra(((WaitForAcceptSole_state_payload_t*)session->sync_state_payload)->groupkeys);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForAcceptSole, event=Timeout", "target=Sole")
                    return Sole;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case Grouped:
        {
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=Grouped")
            switch (event) {
                case Init: 
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Grouped", "event=Init") 
                    *timeout = 0;
                    break;
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
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Grouped, event=CannotDecrypt", "action=sendBeacon")
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=Grouped, event=CannotDecrypt", "target=GroupWaiting")
                    return GroupWaiting;
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
                    session->sync_state_payload = malloc(sizeof(GroupedBeaconed_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((GroupedBeaconed_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
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
                    session->sync_state_payload = malloc(sizeof(HandshakingGrouped_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((HandshakingGrouped_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=Grouped, event=HandshakeRequest", "target=HandshakingGrouped")
                    return HandshakingGrouped;
                }
                case GroupUpdate:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=Grouped", "event=GroupUpdate")
                    identity_list* keys = (identity_list*)extra;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=Grouped, event=GroupUpdate", "action=storeGroupUpdate")
                    status = storeGroupUpdate(session, state, partner, keys);
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
        case GroupWaiting:
        {
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=GroupWaiting")
            switch (event) {
                case Init: 
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupWaiting", "event=Init") 
                    *timeout = 60;
                    break;
                case KeyGen:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupWaiting", "event=KeyGen")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupWaiting, event=KeyGen", "action=sendGroupUpdate")
                    status = sendGroupUpdate(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case CannotDecrypt:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupWaiting", "event=CannotDecrypt")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupWaiting, event=CannotDecrypt", "action=sendUpdateRequest")
                    status = sendUpdateRequest(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupWaiting, event=CannotDecrypt", "action=sendBeacon")
                    status = sendBeacon(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case UpdateRequest:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupWaiting", "event=UpdateRequest")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupWaiting, event=UpdateRequest", "action=sendGroupUpdate")
                    status = sendGroupUpdate(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case Beacon:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupWaiting", "event=Beacon")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupWaiting, event=Beacon", "action=sendHandshakeRequest")
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    session->sync_state_payload = malloc(sizeof(GroupedBeaconed_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((GroupedBeaconed_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=GroupWaiting, event=Beacon", "target=GroupedBeaconed")
                    return GroupedBeaconed;
                }
                case HandshakeRequest:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupWaiting", "event=HandshakeRequest")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupWaiting, event=HandshakeRequest", "action=sendHandshakeRequest")
                    status = sendHandshakeRequest(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    session->sync_state_payload = malloc(sizeof(HandshakingGrouped_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((HandshakingGrouped_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=GroupWaiting, event=HandshakeRequest", "target=HandshakingGrouped")
                    return HandshakingGrouped;
                }
                case GroupUpdate:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupWaiting", "event=GroupUpdate")
                    identity_list* keys = (identity_list*)extra;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupWaiting, event=GroupUpdate", "action=storeGroupUpdate")
                    status = storeGroupUpdate(session, state, partner, keys);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case Timeout:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupWaiting", "event=Timeout")
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=GroupWaiting, event=Timeout", "target=Grouped")
                    return Grouped;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case GroupedBeaconed:
        {
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=GroupedBeaconed")
            assert(session->sync_state_payload);
            if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
            Identity expected = ((GroupedBeaconed_state_payload_t*)session->sync_state_payload)->expected;
            switch (event) {
                case Init: 
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupedBeaconed", "event=Init") 
                    *timeout = 600;
                    break;
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
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupedBeaconed, event=CannotDecrypt", "action=sendBeacon")
                    status = sendBeacon(session, state, NULL, NULL);
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
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((GroupedBeaconed_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    session->sync_state_payload = malloc(sizeof(GroupedBeaconed_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((GroupedBeaconed_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=GroupedBeaconed, event=Beacon", "target=GroupedBeaconed")
                    return GroupedBeaconed;
                }
                case HandshakeRequest:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupedBeaconed", "event=HandshakeRequest")
                    {
                        int cond_result = sameIdentities(session, partner, expected);
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
                    }
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((GroupedBeaconed_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    session->sync_state_payload = malloc(sizeof(HandshakingGrouped_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((HandshakingGrouped_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=GroupedBeaconed, event=HandshakeRequest", "target=HandshakingGrouped")
                    return HandshakingGrouped;
                }
                case GroupUpdate:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupedBeaconed", "event=GroupUpdate")
                    identity_list* keys = (identity_list*)extra;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=GroupedBeaconed, event=GroupUpdate", "action=storeGroupUpdate")
                    status = storeGroupUpdate(session, state, partner, keys);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    break;
                }
                case Timeout:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=GroupedBeaconed", "event=Timeout")
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((GroupedBeaconed_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
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
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=HandshakingGrouped")
            assert(session->sync_state_payload);
            if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
            Identity expected = ((HandshakingGrouped_state_payload_t*)session->sync_state_payload)->expected;
            switch (event) {
                case Init:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingGrouped", "event=Init")
                    *timeout = 600;
                    {
                        int cond_result = keyElectionWon(session, expected);
                        #ifndef NDEBUG
                        char resstr[11] = {0,};
                        snprintf(resstr,10,"result=%d",cond_result);
                        #endif
                        DEBUG_LOG("FSM condition", "sync_fsm.c, state=HandshakingGrouped, event=Init, condition=keyElectionWon", resstr)
                        if (cond_result < 0)
                            return cond_result;
                        if (cond_result) {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=Init", "action=notifyInitAddOtherDevice")
                        status = notifyInitAddOtherDevice(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        }
                        else {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=Init", "action=notifyInitMoveOurDevice")
                        status = notifyInitMoveOurDevice(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        }
                    }
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
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=HandshakeRejected", "action=sendGroupUpdate")
                    status = sendGroupUpdate(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((HandshakingGrouped_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
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
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=HandshakeAccepted", "action=sendGroupUpdate")
                    status = sendGroupUpdate(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    {
                        int cond_result = keyElectionWon(session, partner);
                        #ifndef NDEBUG
                        char resstr[11] = {0,};
                        snprintf(resstr,10,"result=%d",cond_result);
                        #endif
                        DEBUG_LOG("FSM condition", "sync_fsm.c, state=HandshakingGrouped, event=HandshakeAccepted, condition=keyElectionWon", resstr)
                        if (cond_result < 0)
                            return cond_result;
                        if (cond_result) {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=HandshakeAccepted", "action=sendGroupKeys")
                        status = sendGroupKeys(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=HandshakeAccepted", "action=notifyAcceptedDeviceAdded")
                        status = notifyAcceptedDeviceAdded(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        assert(session->sync_state_payload);
                        if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                        free_identity(((HandshakingGrouped_state_payload_t*)session->sync_state_payload)->expected);
                        free(session->sync_state_payload);
                        session->sync_state_payload = NULL;
                        DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingGrouped, event=HandshakeAccepted", "target=Grouped")
                        return Grouped;
                        }
                    }
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((HandshakingGrouped_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    session->sync_state_payload = malloc(sizeof(WaitForGroupKeysGrouped_state_payload_t));
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                    ((WaitForGroupKeysGrouped_state_payload_t*)session->sync_state_payload)->expected =
                        identity_dup(partner);
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingGrouped, event=HandshakeAccepted", "target=WaitForGroupKeysGrouped")
                    return WaitForGroupKeysGrouped;
                }
                case Cancel:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingGrouped", "event=Cancel")
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((HandshakingGrouped_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingGrouped, event=Cancel", "target=Grouped")
                    return Grouped;
                }
                case GroupKeys:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingGrouped", "event=GroupKeys")
                    group_keys_extra_t* groupkeys = (group_keys_extra_t*)extra;
                    {
                        int cond_result = keyElectionWon(session, expected);
                        #ifndef NDEBUG
                        char resstr[11] = {0,};
                        snprintf(resstr,10,"result=%d",cond_result);
                        #endif
                        DEBUG_LOG("FSM condition", "sync_fsm.c, state=HandshakingGrouped, event=GroupKeys, condition=keyElectionWon", resstr)
                        if (cond_result < 0)
                            return cond_result;
                        if (cond_result) {
                        }
                        else {
                        {
                            int cond_result = sameKeyAndAddress(session, partner, expected);
                            #ifndef NDEBUG
                            char resstr[11] = {0,};
                            snprintf(resstr,10,"result=%d",cond_result);
                            #endif
                            DEBUG_LOG("FSM condition", "sync_fsm.c, state=HandshakingGrouped, event=GroupKeys, condition=sameKeyAndAddress", resstr)
                            if (cond_result < 0)
                                return cond_result;
                            if (cond_result) {
                            assert(session->sync_state_payload);
                            if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                            free_identity(((HandshakingGrouped_state_payload_t*)session->sync_state_payload)->expected);
                            free(session->sync_state_payload);
                            session->sync_state_payload = NULL;
                            session->sync_state_payload = malloc(sizeof(WaitForAcceptGrouped_state_payload_t));
                            assert(session->sync_state_payload);
                            if(!session->sync_state_payload) return (DeviceState_state) invalid_out_of_memory;
                            ((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->expected =
                                identity_dup(partner);
                            ((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->groupkeys =
                                group_keys_extra_dup(groupkeys);
                            DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingGrouped, event=GroupKeys", "target=WaitForAcceptGrouped")
                            return WaitForAcceptGrouped;
                            }
                        }
                        }
                    }
                    break;
                }
                case GroupUpdate:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=HandshakingGrouped", "event=GroupUpdate")
                    identity_list* keys = (identity_list*)extra;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=GroupUpdate", "action=notifyOvertaken")
                    status = notifyOvertaken(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=HandshakingGrouped, event=GroupUpdate", "action=storeGroupUpdate")
                    status = storeGroupUpdate(session, state, partner, keys);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((HandshakingGrouped_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingGrouped, event=GroupUpdate", "target=Grouped")
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
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((HandshakingGrouped_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=HandshakingGrouped, event=Timeout", "target=Grouped")
                    return Grouped;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case WaitForGroupKeysGrouped:
        {
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=WaitForGroupKeysGrouped")
            assert(session->sync_state_payload);
            if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
            Identity expected = ((WaitForGroupKeysGrouped_state_payload_t*)session->sync_state_payload)->expected;
            switch (event) {
                case Init: 
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForGroupKeysGrouped", "event=Init") 
                    *timeout = 600;
                    break;
                case GroupKeys:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForGroupKeysGrouped", "event=GroupKeys")
                    group_keys_extra_t* groupkeys = (group_keys_extra_t*)extra;
                    {
                        int cond_result = sameIdentities(session, partner, expected);
                        #ifndef NDEBUG
                        char resstr[11] = {0,};
                        snprintf(resstr,10,"result=%d",cond_result);
                        #endif
                        DEBUG_LOG("FSM condition", "sync_fsm.c, state=WaitForGroupKeysGrouped, event=GroupKeys, condition=sameIdentities", resstr)
                        if (cond_result < 0)
                            return cond_result;
                        if (cond_result) {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysGrouped, event=GroupKeys", "action=storeGroupKeys")
                        status = storeGroupKeys(session, state, partner, groupkeys);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysGrouped, event=GroupKeys", "action=sendGroupUpdate")
                        status = sendGroupUpdate(session, state, NULL, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysGrouped, event=GroupKeys", "action=renewUUID")
                        status = renewUUID(session, state, NULL, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysGrouped, event=GroupKeys", "action=notifyAcceptedDeviceMoved")
                        status = notifyAcceptedDeviceMoved(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        assert(session->sync_state_payload);
                        if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                        free_identity(((WaitForGroupKeysGrouped_state_payload_t*)session->sync_state_payload)->expected);
                        free(session->sync_state_payload);
                        session->sync_state_payload = NULL;
                        DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForGroupKeysGrouped, event=GroupKeys", "target=Grouped")
                        return Grouped;
                        }
                    }
                    break;
                }
                case GroupUpdate:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForGroupKeysGrouped", "event=GroupUpdate")
                    identity_list* keys = (identity_list*)extra;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysGrouped, event=GroupUpdate", "action=notifyOvertaken")
                    status = notifyOvertaken(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysGrouped, event=GroupUpdate", "action=storeGroupUpdate")
                    status = storeGroupUpdate(session, state, partner, keys);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((WaitForGroupKeysGrouped_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForGroupKeysGrouped, event=GroupUpdate", "target=Grouped")
                    return Grouped;
                }
                case Timeout:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForGroupKeysGrouped", "event=Timeout")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForGroupKeysGrouped, event=Timeout", "action=notifyTimeout")
                    status = notifyTimeout(session, state, expected, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((WaitForGroupKeysGrouped_state_payload_t*)session->sync_state_payload)->expected);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForGroupKeysGrouped, event=Timeout", "target=Grouped")
                    return Grouped;
                }
                default:
                    return (DeviceState_state) invalid_event;
            }
            break;
        }
        case WaitForAcceptGrouped:
        {
            DEBUG_LOG("Entering FSM state", "sync_fsm.c", "state=WaitForAcceptGrouped")
            assert(session->sync_state_payload);
            if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
            Identity expected = ((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->expected;
            group_keys_extra_t* groupkeys = ((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->groupkeys;
            switch (event) {
                case Init: 
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForAcceptGrouped", "event=Init") 
                    *timeout = 600;
                    break;
                case HandshakeRejected:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForAcceptGrouped", "event=HandshakeRejected")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptGrouped, event=HandshakeRejected", "action=rejectHandshake")
                    status = rejectHandshake(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptGrouped, event=HandshakeRejected", "action=sendGroupUpdate")
                    status = sendGroupUpdate(session, state, NULL, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->expected);
                    free_group_keys_extra(((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->groupkeys);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForAcceptGrouped, event=HandshakeRejected", "target=Grouped")
                    return Grouped;
                }
                case HandshakeAccepted:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForAcceptGrouped", "event=HandshakeAccepted")
                    {
                        int cond_result = sameIdentities(session, partner, expected);
                        #ifndef NDEBUG
                        char resstr[11] = {0,};
                        snprintf(resstr,10,"result=%d",cond_result);
                        #endif
                        DEBUG_LOG("FSM condition", "sync_fsm.c, state=WaitForAcceptGrouped, event=HandshakeAccepted, condition=sameIdentities", resstr)
                        if (cond_result < 0)
                            return cond_result;
                        if (cond_result) {
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptGrouped, event=HandshakeAccepted", "action=acceptHandshake")
                        status = acceptHandshake(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptGrouped, event=HandshakeAccepted", "action=storeGroupKeys")
                        status = storeGroupKeys(session, state, partner, groupkeys);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptGrouped, event=HandshakeAccepted", "action=sendGroupUpdate")
                        status = sendGroupUpdate(session, state, NULL, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptGrouped, event=HandshakeAccepted", "action=renewUUID")
                        status = renewUUID(session, state, NULL, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptGrouped, event=HandshakeAccepted", "action=notifyAcceptedDeviceMoved")
                        status = notifyAcceptedDeviceMoved(session, state, partner, NULL);
                        if (status == PEP_OUT_OF_MEMORY)
                            return (int) invalid_out_of_memory;
                        if (status != PEP_STATUS_OK)
                            return (int) invalid_action;
                        }
                    }
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->expected);
                    free_group_keys_extra(((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->groupkeys);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForAcceptGrouped, event=HandshakeAccepted", "target=Grouped")
                    return Grouped;
                }
                case Cancel:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForAcceptGrouped", "event=Cancel")
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->expected);
                    free_group_keys_extra(((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->groupkeys);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForAcceptGrouped, event=Cancel", "target=Grouped")
                    return Grouped;
                }
                case GroupUpdate:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForAcceptGrouped", "event=GroupUpdate")
                    identity_list* keys = (identity_list*)extra;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptGrouped, event=GroupUpdate", "action=notifyOvertaken")
                    status = notifyOvertaken(session, state, partner, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptGrouped, event=GroupUpdate", "action=storeGroupUpdate")
                    status = storeGroupUpdate(session, state, partner, keys);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->expected);
                    free_group_keys_extra(((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->groupkeys);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForAcceptGrouped, event=GroupUpdate", "target=Grouped")
                    return Grouped;
                }
                case Timeout:
                {
                    DEBUG_LOG("FSM event", "sync_fsm.c, state=WaitForAcceptGrouped", "event=Timeout")
                    DEBUG_LOG("FSM action", "sync_fsm.c, state=WaitForAcceptGrouped, event=Timeout", "action=notifyTimeout")
                    status = notifyTimeout(session, state, expected, NULL);
                    if (status == PEP_OUT_OF_MEMORY)
                        return (int) invalid_out_of_memory;
                    if (status != PEP_STATUS_OK)
                        return (int) invalid_action;
                    assert(session->sync_state_payload);
                    if(!session->sync_state_payload) return (DeviceState_state) invalid_state;
                    free_identity(((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->expected);
                    free_group_keys_extra(((WaitForAcceptGrouped_state_payload_t*)session->sync_state_payload)->groupkeys);
                    free(session->sync_state_payload);
                    session->sync_state_payload = NULL;
                    DEBUG_LOG("FSM transition", "sync_fsm.c, state=WaitForAcceptGrouped, event=Timeout", "target=Grouped")
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

