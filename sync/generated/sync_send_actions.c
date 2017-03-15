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
#include "../asn.1/GroupUpdate.h"
#include "../asn.1/UpdateRequest.h"


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

    msg->payload.choice.handshakeRequest.partner_id = 
        OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String,
                                 partner->user_id, -1);
    if (partner->user_id && !msg->payload.choice.handshakeRequest.partner_id)
       goto enomem;

    char *devgrp = NULL;
    status = get_device_group(session, &devgrp);
    if (status == PEP_STATUS_OK && devgrp && devgrp[0])
    msg->payload.choice.handshakeRequest.group_id = 
        OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String,
                                 devgrp, -1);
    free(devgrp);
    if (devgrp && !msg->payload.choice.handshakeRequest.partner_id)
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

    status = _own_identities_retrieve(session, &kl, PEP_idf_not_for_sync);
    if (status != PEP_STATUS_OK)
        goto error;
    if (IdentityList_from_identity_list(kl, &msg->payload.choice.groupKeys.ownIdentities) == NULL)
        goto enomem;

    msg->payload.choice.groupKeys.partner_id = 
        OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String,
                                 partner->user_id, -1);
    if (partner->user_id && !msg->payload.choice.groupKeys.partner_id)
       goto enomem;

    char *devgrp = NULL;
    status = get_device_group(session, &devgrp);
    if (status == PEP_STATUS_OK && devgrp && devgrp[0])
    msg->payload.choice.groupKeys.group_id = 
        OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String,
                                 devgrp, -1);
    free(devgrp);
    if (devgrp && !msg->payload.choice.groupKeys.partner_id)
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


// sendGroupUpdate() - send GroupUpdate message
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        (must be NULL)
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendGroupUpdate(
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

    DeviceGroup_Protocol_t *msg = new_DeviceGroup_Protocol_msg(DeviceGroup_Protocol__payload_PR_groupUpdate);
    if (!msg)
        goto enomem;

    status = _own_identities_retrieve(session, &kl, PEP_idf_not_for_sync);
    if (status != PEP_STATUS_OK)
        goto error;
    if (IdentityList_from_identity_list(kl, &msg->payload.choice.groupUpdate.ownIdentities) == NULL)
        goto enomem;

    bool encrypted = true;
    status = multicast_self_msg(session, state, msg, encrypted);
    if (status != PEP_STATUS_OK)
        goto error;

    free_identity_list(kl);
    free_DeviceGroup_Protocol_msg(msg);
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    free_DeviceGroup_Protocol_msg(msg);
    return status;
}


// sendUpdateRequest() - send UpdateRequest message
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        (must be NULL)
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendUpdateRequest(
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

    DeviceGroup_Protocol_t *msg = new_DeviceGroup_Protocol_msg(DeviceGroup_Protocol__payload_PR_updateRequest);
    if (!msg)
        goto enomem;

    bool encrypted = true;
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


PEP_STATUS _notifyHandshake(
        PEP_SESSION session,
        Identity partner,
        sync_handshake_signal signal
    );

// notifyInitFormGroup() - notify InitFormGroup to app
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS notifyInitFormGroup(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    assert(session && state);
    assert(extra == NULL);
    if (!(session && state && extra == NULL))
        return PEP_ILLEGAL_VALUE;

    return _notifyHandshake(session, partner, SYNC_NOTIFY_INIT_FORM_GROUP);
}


// notifyInitAddOurDevice() - notify InitAddOurDevice to app
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS notifyInitAddOurDevice(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    assert(session && state);
    assert(extra == NULL);
    if (!(session && state && extra == NULL))
        return PEP_ILLEGAL_VALUE;

    return _notifyHandshake(session, partner, SYNC_NOTIFY_INIT_ADD_OUR_DEVICE);
}


// notifyAcceptedGroupCreated() - notify AcceptedGroupCreated to app
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS notifyAcceptedGroupCreated(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    assert(session && state);
    assert(extra == NULL);
    if (!(session && state && extra == NULL))
        return PEP_ILLEGAL_VALUE;

    return _notifyHandshake(session, partner, SYNC_NOTIFY_ACCEPTED_GROUP_CREATED);
}


// notifyTimeout() - notify Timeout to app
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS notifyTimeout(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    assert(session && state);
    assert(extra == NULL);
    if (!(session && state && extra == NULL))
        return PEP_ILLEGAL_VALUE;

    return _notifyHandshake(session, partner, SYNC_NOTIFY_TIMEOUT);
}


// notifyAcceptedDeviceAdded() - notify AcceptedDeviceAdded to app
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS notifyAcceptedDeviceAdded(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    assert(session && state);
    assert(extra == NULL);
    if (!(session && state && extra == NULL))
        return PEP_ILLEGAL_VALUE;

    return _notifyHandshake(session, partner, SYNC_NOTIFY_ACCEPTED_DEVICE_ADDED);
}

