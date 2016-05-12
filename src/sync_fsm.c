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

// decoders

void decodeBeacon(void);
void decodeHandshakeRequest(Identity partner);
void decodeOwnKeys(void);

// encoders 

void encodeBeacon(void);
void encodeHandshakeRequest(Identity partner);
void encodeOwnKeys(void);

// state machine

DeviceState_state fsm_DeviceState(
        DeviceState_state state,
        DeviceState_event event,
        const Identity partner
    )
{
    switch (state) {
    case Sole:
        switch (event) {
            case KeyGen:
                sendBeacon(NULL);
                break;
            case CannotDecrypt:
                sendBeacon(NULL);
                break;
            case Beacon:
                sendHandshakeRequest(partner);
                break;
            case HandshakeRequest:
                sendHandshakeRequest(partner);
                return HandshakingSole;
        default:
            return invalid_event;
        }
        break;
    
    case HandshakingSole:
        switch (event) {
            case Init:
                showHandshake(partner);
                break;
            case HandshakeRejected:
                reject(partner);
                return Sole;
            case HandshakeAccepted:
                return WaitForGroupKeys;
        default:
            return invalid_event;
        }
        break;
    
    case WaitForGroupKeys:
        switch (event) {
            case ReceiveGroupKeys:
                storeGroupKeys(partner);
                return Grouped;
            case Cancel:
                return Sole;
            case Reject:
                reject(partner);
                return Sole;
        default:
            return invalid_event;
        }
        break;
    
    case Grouped:
        switch (event) {
            case KeyGen:
                sendOwnKeys(NULL);
                break;
            case HandshakeRequest:
                sendHandshakeRequest(partner);
                showHandshake(partner);
                break;
            case HandshakeRejected:
                reject(partner);
                break;
            case HandshakeAccepted:
                transmitGroupKeys(partner);
                break;
            case Reject:
                reject(NULL);
                break;
        default:
            return invalid_event;
        }
        break;
    
        default:
            return invalid_state;
    }

    return state;
}
