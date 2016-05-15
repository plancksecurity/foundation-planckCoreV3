#pragma once

// state machine for DeviceState

#include "pEpEngine.h"

// types

typedef pEp_identity * Identity;
typedef union _param { const Identity partner; const stringlist_t *keylist; } param_t;

// error values

typedef enum _fsm_error {
    invalid_state = -1,
    invalid_event = -2
} fsm_error;

// states

typedef enum _DeviceState_state {
    InitState, 
    Sole, 
    HandshakingSole, 
    WaitForGroupKeys, 
    Grouped
} DeviceState_state;

// events

typedef enum _DeviceState_event {
    Init, 
    KeyGen, 
    CannotDecrypt, 
    Beacon, 
    HandshakeRequest, 
    HandshakeRejected, 
    HandshakeAccepted, 
    ReceiveGroupKeys, 
    Cancel, 
    Reject
} DeviceState_event;

// actions

PEP_STATUS sendBeacon(PEP_SESSION session, const Identity partner);
PEP_STATUS sendHandshakeRequest(PEP_SESSION session, const Identity partner);
PEP_STATUS showHandshake(PEP_SESSION session, const Identity partner);
PEP_STATUS reject(PEP_SESSION session, const Identity partner);
PEP_STATUS storeGroupKeys(PEP_SESSION session, const Identity partner);
PEP_STATUS sendOwnKeys(PEP_SESSION session, const Identity partner);
PEP_STATUS transmitGroupKeys(PEP_SESSION session, const Identity partner);

// state machine

DeviceState_state fsm_DeviceState(
        PEP_SESSION session,
        DeviceState_state state,
        DeviceState_event event,
        const Identity partner
    );

// driver

PEP_STATUS fsm_DeviceState_inject(PEP_SESSION session, DeviceState_event event);

