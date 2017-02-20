#pragma once

// state machine for DeviceState

#include "message_api.h"

#ifdef __cplusplus
extern "C" {
#endif

// types

typedef pEp_identity * Identity;
typedef stringlist_t * Stringlist;

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

int deviceGrouped(PEP_SESSION session);
int keyElectionWon(PEP_SESSION session, Identity partner);
int sameIdentities(PEP_SESSION session, Identity a, Identity b);

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
    SoleBeaconed, 
    HandshakingSole, 
    WaitForGroupKeysSole, 
    WaitForAcceptSole, 
    Grouped, 
    GroupedBeaconed, 
    HandshakingGrouped, 
    WaitForGroupKeysGrouped, 
    WaitForAcceptGrouped
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
    Timeout, 
    HandshakeRejected, 
    HandshakeAccepted, 
    Cancel, 
    UpdateRequest, 
    GroupUpdate
} DeviceState_event;

// actions

PEP_STATUS sendBeacon(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS sendHandshakeRequest(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS notifyInitFormGroup(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS notifyInitAddOurDevice(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS rejectHandshake(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS acceptHandshake(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS makeGroup(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS sendGroupKeys(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS notifyAcceptedGroupCreated(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS notifyTimeout(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS storeGroupKeys(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS sendGroupUpdate(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS notifyAcceptedDeviceAdded(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS sendUpdateRequest(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS storeGroupUpdate(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS notifyInitAddOtherDevice(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS notifyInitMoveOurDevice(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS notifyAcceptedDeviceMoved(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);

// event injector

PEP_STATUS inject_DeviceState_event(
    PEP_SESSION session, 
    DeviceState_event event,
    Identity partner,
    void *extra);

// message receiver

PEP_STATUS receive_DeviceState_msg(
        PEP_SESSION session, 
        message *src, 
        PEP_rating rating, 
        stringlist_t *keylist
    );

// state machine

DeviceState_state fsm_DeviceState(
        PEP_SESSION session,
        DeviceState_state state,
        DeviceState_event event,
        Identity partner,
        void *extra,
        time_t *timeout
    );

// driver

DYNAMIC_API PEP_STATUS fsm_DeviceState_inject(
        PEP_SESSION session,
        DeviceState_event event,
        Identity partner,
        void *extra,
        time_t *timeout
    );

#ifdef __cplusplus
}
#endif

