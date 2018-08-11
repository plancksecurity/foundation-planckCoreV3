// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "fsm_common.h"
#include "message_api.h"
#include "Sync_event.h"

#ifdef __cplusplus
extern "C" {
#endif

// conditions

PEP_STATUS deviceGrouped(PEP_SESSION session, bool *result);
PEP_STATUS challengeAccepted(PEP_SESSION session, bool *result);
PEP_STATUS partnerIsGrouped(PEP_SESSION session, bool *result);
PEP_STATUS keyElectionWon(PEP_SESSION session, bool *result);

// actions

PEP_STATUS closeHandshakeDialog(PEP_SESSION session);
PEP_STATUS openChallenge(PEP_SESSION session);
PEP_STATUS storeChallenge(PEP_SESSION session);
PEP_STATUS openTransaction(PEP_SESSION session);
PEP_STATUS storeTransaction(PEP_SESSION session);
PEP_STATUS showSoleHandshake(PEP_SESSION session);
PEP_STATUS disable(PEP_SESSION session);
PEP_STATUS saveGroupKeys(PEP_SESSION session);
PEP_STATUS ownKeysAreGroupKeys(PEP_SESSION session);
PEP_STATUS showJoinGroupHandshake(PEP_SESSION session);
PEP_STATUS showGroupedHandshake(PEP_SESSION session);

// notify state machine from event
// use state to generate Sync message if necessary

PEP_STATUS Sync_notify(
        PEP_SESSION session, 
        Sync_PR fsm,
        int message_type
    );

// send message about an event to communication partners using state

PEP_STATUS send_Sync_message(
        PEP_SESSION session, 
        Sync_PR fsm,
        int event
    );

// receive message and store it in state

PEP_STATUS recv_Sync_event(
        PEP_SESSION session,
        Sync_event_t *ev
    );

// state machine driver
// if fsm or event set to 0 use fields in src if present

PEP_STATUS Sync_driver(
        PEP_SESSION session,
        Sync_PR fsm,
        int event
    );

PEP_STATUS inject_Sync_event(
        PEP_SESSION session, 
        Sync_PR fsm,
        int event
    );


#ifdef __cplusplus
}
#endif

