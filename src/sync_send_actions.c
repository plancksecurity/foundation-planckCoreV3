// Send Actions for DeviceState state machine

#include <assert.h>
#include "pEp_internal.h"
#include "keymanagement.h"
#include "message.h"
#include "sync_fsm.h"
#include "baseprotocol.h"
#include "map_asn1.h"
#include "../asn.1/DeviceGroup-Protocol.h"
#include "sync_impl.h"
#include "../asn.1/Beacon.h"
#include "../asn.1/HandshakeRequest.h"
#include "../asn.1/GroupKeys.h"


// sendBeacon() - send Beacon message
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        (must be NULL)
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendBeacon(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    assert(session && state);
    if (!(session && state))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    DeviceGroup_Protocol_t *msg = new_DeviceGroup_Protocol_msg(DeviceGroup_Protocol__payload_PR_beacon);
    if (!msg)
        goto enomem;

    bool encrypted = false;
    status = multicast_self_msg(session, state, msg, encrypted);
    if (status != PEP_STATUS_OK)
        goto error;

    free_DeviceGroup_Protocol_msg(msg);
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    free_DeviceGroup_Protocol_msg(msg);
    return status;
}


// sendHandshakeRequest() - send HandshakeRequest message
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendHandshakeRequest(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    assert(session && state);
    if (!(session && state))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    DeviceGroup_Protocol_t *msg = new_DeviceGroup_Protocol_msg(DeviceGroup_Protocol__payload_PR_handshakeRequest);
    if (!msg)
        goto enomem;

    if (Identity_from_Struct(partner,
                             &msg->payload.choice.handshakeRequest.partner) == NULL)
        goto enomem;

    bool encrypted = true;
    status = unicast_msg(session, partner, state, msg, encrypted);
    if (status != PEP_STATUS_OK)
        goto error;

    free_DeviceGroup_Protocol_msg(msg);
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    free_DeviceGroup_Protocol_msg(msg);
    return status;
}


// sendGroupKeys() - send GroupKeys message
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendGroupKeys(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    assert(session && state);
    if (!(session && state))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    identity_list *kl = new_identity_list(NULL);

    DeviceGroup_Protocol_t *msg = new_DeviceGroup_Protocol_msg(DeviceGroup_Protocol__payload_PR_groupKeys);
    if (!msg)
        goto enomem;

    status = own_identities_retrieve(session, &kl);
    if (status != PEP_STATUS_OK)
        goto error;
    if (Identity_from_Struct(partner,
                             &msg->payload.choice.groupKeys.partner) == NULL)
        goto enomem;

    if (IdentityList_from_identity_list(kl, &msg->payload.choice.groupKeys.ownIdentities) == NULL)
        goto enomem;

    bool encrypted = true;
    status = unicast_msg(session, partner, state, msg, encrypted);
    if (status != PEP_STATUS_OK)
        goto error;

    free_identity_list(kl);
    free_DeviceGroup_Protocol_msg(msg);
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    free_DeviceGroup_Protocol_msg(msg);
    free_identity_list(kl);
    return status;
}

