#include "sync_fsm.h"

// state machine for DeviceState

DeviceState_state fsm_DeviceState(
        PEP_SESSION session,
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
                sendBeacon(session, NULL);
                break;
            case CannotDecrypt:
                sendBeacon(session, NULL);
                break;
            case Beacon:
                sendHandshakeRequest(session, partner);
                break;
            case HandshakeRequest:
                sendHandshakeRequest(session, partner);
                return HandshakingSole;
        default:
            return invalid_event;
        }
        break;
    
    case HandshakingSole:
        switch (event) {
            case Init:
                showHandshake(session, partner);
                break;
            case HandshakeRejected:
                reject(session, partner);
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
                storeGroupKeys(session, partner);
                return Grouped;
            case Cancel:
                return Sole;
            case Reject:
                reject(session, partner);
                return Sole;
        default:
            return invalid_event;
        }
        break;
    
    case Grouped:
        switch (event) {
            case KeyGen:
                sendOwnKeys(session, NULL);
                break;
            case HandshakeRequest:
                sendHandshakeRequest(session, partner);
                showHandshake(session, partner);
                break;
            case HandshakeRejected:
                reject(session, partner);
                break;
            case HandshakeAccepted:
                transmitGroupKeys(session, partner);
                break;
            case Reject:
                reject(session, NULL);
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
