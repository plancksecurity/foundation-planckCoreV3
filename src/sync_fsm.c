// state machine for DeviceState

#include "pEpEngine.h"

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

void sendBeacon(const pEp_identity *partner);
void sendHandshakeRequest(const pEp_identity *partner);
void showHandshake(const pEp_identity *partner);
void reject(const pEp_identity *partner);
void sendOwnKeys(const pEp_identity *partner);
void transmitGroupKeys(const pEp_identity *partner);

// state machine

DeviceState_state fsm_DeviceState(
        DeviceState_state state,
        DeviceState_event event,
        const pEp_identity *partner
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
