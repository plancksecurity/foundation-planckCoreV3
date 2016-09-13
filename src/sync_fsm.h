#pragma once

// state machine for DeviceState

#include "message_api.h"

#ifdef __cplusplus
extern "C" {
#endif

// types

typedef pEp_identity * Identity;
typedef stringlist_t * Stringlist;
typedef union _param { Identity partner; stringlist_t *keylist; } param_t;

// error values

typedef enum _fsm_error {
    // these error values are corresponding to
    // PEP_SYNC_STATEMACHINE_ERROR - value
    invalid_state = -2,
    invalid_event = -3,
    invalid_condition = -4,
    invalid_action = -5,

    // out of memory condition
    invalid_out_of_memory = -128
} fsm_error;

// conditions

int storedGroupKeys(PEP_SESSION session);
int keyElectionWon(PEP_SESSION session, Identity partner);

// states

typedef enum _DeviceState_state {
    // error values also in this namespace
    DeviceState_state_invalid_state = (int) invalid_state,
    DeviceState_state_invalid_event = (int) invalid_event,
    DeviceState_state_invalid_condition = (int) invalid_condition,
    DeviceState_state_invalid_action = (int) invalid_action,
    DeviceState_state_invalid_out_of_memory = (int) invalid_out_of_memory,

    DeviceState_state_NONE = 0,
    InitState, 
    Sole, 
    HandshakingSole, 
    WaitForGroupKeys, 
    Grouped
} DeviceState_state;

// events

typedef enum _DeviceState_event {
    DeviceState_event_NONE = 0,
    Init = 1,
    Beacon = 2,
    HandshakeRequest = 3,
    GroupKeys = 4,
    KeyGen, 
    CannotDecrypt, 
    HandshakeRejected, 
    HandshakeAccepted, 
    Cancel, 
    Reject
} DeviceState_event;

// actions

PEP_STATUS sendBeacon(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS sendHandshakeRequest(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS showHandshake(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS rejectHandshake(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS acceptHandshake(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS sendGroupKeys(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS storeGroupKeys(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);

// message receiver

PEP_STATUS receive_DeviceState_msg(PEP_SESSION session, message *msg, PEP_rating rating);

// state machine

DeviceState_state fsm_DeviceState(
        PEP_SESSION session,
        DeviceState_state state,
        DeviceState_event event,
        Identity partner,
        void *extra
    );

// driver

DYNAMIC_API PEP_STATUS fsm_DeviceState_inject(
        PEP_SESSION session,
        DeviceState_event event,
        Identity partner,
        void *extra
    );

#ifdef __cplusplus
}
#endif

