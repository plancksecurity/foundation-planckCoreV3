#include "sync_fsm.h"

// state machine for DeviceState

DeviceState_state fsm_DeviceState(
        PEP_SESSION session,
        DeviceState_state state,
        DeviceState_event event,
        Identity partner,
        DeviceState_state state_partner
    )
{
    switch (state) {
    case InitState:
        switch (event) {
            case Init:
                return Sole;
        default:
            return (DeviceState_state) invalid_event;
        }
        break;
    
    case Sole:
        switch (event) {
            case KeyGen:
                sendBeacon(session, state, NULL, NULL);
                break;
            case CannotDecrypt:
                sendBeacon(session, state, NULL, NULL);
                break;
            case Beacon:
                sendHandshakeRequest(session, state, partner, NULL);
                break;
            case HandshakeRequest:
                sendHandshakeRequest(session, state, partner, NULL);
                return HandshakingSole;
        default:
            return (DeviceState_state) invalid_event;
        }
        break;
    
    case HandshakingSole:
        switch (event) {
            case Init:
                showHandshake(session, state, partner, NULL);
                break;
            case HandshakeRejected:
                reject(session, state, partner, NULL);
                return Sole;
            case HandshakeAccepted:
                return WaitForGroupKeys;
        default:
            return (DeviceState_state) invalid_event;
        }
        break;
    
    case WaitForGroupKeys:
        switch (event) {
            case GroupKeys:
                storeGroupKeys(session, state, partner, NULL);
                return Grouped;
            case Cancel:
                return Sole;
            case Reject:
                reject(session, state, partner, NULL);
                return Sole;
        default:
            return (DeviceState_state) invalid_event;
        }
        break;
    
    case Grouped:
        switch (event) {
            case KeyGen:
                sendGroupKeys(session, state, NULL, NULL);
                break;
            case HandshakeRequest:
                sendHandshakeRequest(session, state, partner, NULL);
                showHandshake(session, state, partner, NULL);
                break;
            case HandshakeRejected:
                reject(session, state, partner, NULL);
                break;
            case Hand:
                break;
            case Reject:
                reject(session, state, NULL, NULL);
                break;
        default:
            return (DeviceState_state) invalid_event;
        }
        break;
    
        default:
            return (DeviceState_state) invalid_state;
    }

    return state;
}

