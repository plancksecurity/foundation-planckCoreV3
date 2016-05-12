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

void sendBeacon(const Identity partner);
void sendHandshakeRequest(const Identity partner);
void showHandshake(const Identity partner);
void reject(const Identity partner);
void storeGroupKeys(const Identity partner);
void sendOwnKeys(const Identity partner);
void transmitGroupKeys(const Identity partner);

// driver

void fsm_DeviceState_inject(PEP_SESSION session, DeviceState_event event);

