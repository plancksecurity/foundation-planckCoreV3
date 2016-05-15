#include "sync_fsm.h"

// state machine for DeviceState

DeviceState_state fsm_DeviceState(
        DeviceState_state state,
        DeviceState_event event,
        const Identity partner
    )
{
    switch (state) {
    case InitState:
        switch (event) {
            case Init:
                return Sole;
        default:
            return invalid_event;
        }
        break;
    
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
