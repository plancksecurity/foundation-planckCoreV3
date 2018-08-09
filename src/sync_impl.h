// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "fsm_common.h"
#include "message_api.h"
#include "../asn.1/Sync.h"

#ifdef __cplusplus
extern "C" {
#endif

// event struct

typedef struct _Sync_event {
    Sync_PR fsm;
    int event;
    Sync_t *msg;
} Sync_event_t;

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

// send event to own state machine, use state to generate
// Sync message if necessary

PEP_STATUS Sync_send(
        PEP_SESSION session, 
        Sync_PR fsm,
        int message_type
    );

// send message to partners

PEP_STATUS send_Sync_message(
        PEP_SESSION session, 
        Sync_PR fsm,
        int event
    );

// receive event, free Sync_event_t structure if call does not fail
// with PEP_ILLEGAL_VALUE

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

