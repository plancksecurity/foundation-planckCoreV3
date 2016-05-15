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
    Sole, 
    HandshakingSole, 
    WaitForGroupKeys, 
    Grouped
} DeviceState_state;

// events

typedef enum _DeviceState_event {
    KeyGen, 
    CannotDecrypt, 
    Beacon, 
    HandshakeRequest, 
    Init, 
    HandshakeRejected, 
    HandshakeAccepted, 
    ReceiveGroupKeys, 
    Cancel, 
    Reject
} DeviceState_event;

// actions

PEP_STATUS sendBeacon(const Identity partner);
PEP_STATUS sendHandshakeRequest(const Identity partner);
PEP_STATUS showHandshake(const Identity partner);
PEP_STATUS reject(const Identity partner);
PEP_STATUS storeGroupKeys(const Identity partner);
PEP_STATUS sendOwnKeys(const Identity partner);
PEP_STATUS transmitGroupKeys(const Identity partner);

// driver

PEP_STATUS fsm_DeviceState_inject(PEP_SESSION session, DeviceState_event event);

