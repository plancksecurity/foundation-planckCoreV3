// Send Actions for DeviceState state machine

#include <assert.h>
#include "pEp_internal.h"
#include "keymanagement.h"
#include "message.h"
#include "sync_fsm.h"
#include "baseprotocol.h"
#include "map_asn1.h"
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
    PEP_STATUS status = PEP_STATUS_OK;
    Beacon_t *msg = NULL;
    char *payload = NULL;
    message *_message = NULL;
    pEp_identity *me = NULL;

    assert(session);
    assert(!partner);
    if (!(session && !partner))
        return PEP_ILLEGAL_VALUE;

    assert(session->messageToSend);
    if (!session->messageToSend)
        return PEP_SEND_FUNCTION_NOT_REGISTERED;

    msg = (Beacon_t *) calloc(1, sizeof(Beacon_t));
    assert(msg);
    if (!msg)
        goto enomem;

    int32_t seq;
    status = sequence_value(session, "DeviceGroup", &seq);
    if (status != PEP_STATUS_OK)
        goto error;
    msg->header.sequence = (long) seq;

    msg->state = (long) state;

    me = new_identity(NULL, NULL, NULL, NULL);
    if (!me)
        goto enomem;
    status = myself(session, me);
    if (status != PEP_STATUS_OK)
        goto error;
    if (Identity_from_Struct(me, &msg->me) == NULL)
        goto enomem;

    if (asn_check_constraints(&asn_DEF_Beacon, msg, NULL, NULL)) {
        status = PEP_CONTRAINTS_VIOLATED;
        goto error;
    }

    ssize_t size = uper_encode_to_new_buffer(&asn_DEF_Beacon,
            NULL, msg, (void **) &payload);
    if (size == -1) {
        status = PEP_CANNOT_ENCODE;
        goto error;
    }

    status = prepare_message(me, partner, payload, size, &_message);
    if (status != PEP_STATUS_OK)
        goto error;
    payload = NULL;

    free_identity(me);
    me = NULL;

    status = session->messageToSend(session->sync_obj, _message);

    free_message(_message);
    ASN_STRUCT_FREE(asn_DEF_Beacon, msg);

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    ASN_STRUCT_FREE(asn_DEF_Beacon, msg);
    free(payload);
    free_message(_message);
    free_identity(me);
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
    PEP_STATUS status = PEP_STATUS_OK;
    HandshakeRequest_t *msg = NULL;
    char *payload = NULL;
    message *_message = NULL;
    pEp_identity *me = NULL;

    assert(session);
    assert(partner);
    if (!(session && partner))
        return PEP_ILLEGAL_VALUE;

    assert(session->messageToSend);
    if (!session->messageToSend)
        return PEP_SEND_FUNCTION_NOT_REGISTERED;

    msg = (HandshakeRequest_t *) calloc(1, sizeof(HandshakeRequest_t));
    assert(msg);
    if (!msg)
        goto enomem;

    int32_t seq;
    status = sequence_value(session, "DeviceGroup", &seq);
    if (status != PEP_STATUS_OK)
        goto error;
    msg->header.sequence = (long) seq;

    msg->state = (long) state;

    me = new_identity(NULL, NULL, NULL, NULL);
    if (!me)
        goto enomem;
    status = myself(session, me);
    if (status != PEP_STATUS_OK)
        goto error;
    if (Identity_from_Struct(me, &msg->me) == NULL)
        goto enomem;

    if (Identity_from_Struct(partner, &msg->partner) == NULL)
        goto enomem;

    if (asn_check_constraints(&asn_DEF_HandshakeRequest, msg, NULL, NULL)) {
        status = PEP_CONTRAINTS_VIOLATED;
        goto error;
    }

    ssize_t size = uper_encode_to_new_buffer(&asn_DEF_HandshakeRequest,
            NULL, msg, (void **) &payload);
    if (size == -1) {
        status = PEP_CANNOT_ENCODE;
        goto error;
    }

    status = prepare_message(me, partner, payload, size, &_message);
    if (status != PEP_STATUS_OK)
        goto error;
    payload = NULL;

    free_identity(me);
    me = NULL;

    status = session->messageToSend(session->sync_obj, _message);

    free_message(_message);
    ASN_STRUCT_FREE(asn_DEF_HandshakeRequest, msg);

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    ASN_STRUCT_FREE(asn_DEF_HandshakeRequest, msg);
    free(payload);
    free_message(_message);
    free_identity(me);
    return status;
}


// sendGroupKeys() - send GroupKeys message
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        (must be NULL)
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
    PEP_STATUS status = PEP_STATUS_OK;
    GroupKeys_t *msg = NULL;
    char *payload = NULL;
    message *_message = NULL;
    pEp_identity *me = NULL;

    assert(session);
    assert(!partner);
    if (!(session && !partner))
        return PEP_ILLEGAL_VALUE;

    assert(session->messageToSend);
    if (!session->messageToSend)
        return PEP_SEND_FUNCTION_NOT_REGISTERED;

    msg = (GroupKeys_t *) calloc(1, sizeof(GroupKeys_t));
    assert(msg);
    if (!msg)
        goto enomem;

    int32_t seq;
    status = sequence_value(session, "DeviceGroup", &seq);
    if (status != PEP_STATUS_OK)
        goto error;
    msg->header.sequence = (long) seq;

    msg->state = (long) state;

    me = new_identity(NULL, NULL, NULL, NULL);
    if (!me)
        goto enomem;
    status = myself(session, me);
    if (status != PEP_STATUS_OK)
        goto error;
    if (Identity_from_Struct(me, &msg->me) == NULL)
        goto enomem;

    if (asn_check_constraints(&asn_DEF_GroupKeys, msg, NULL, NULL)) {
        status = PEP_CONTRAINTS_VIOLATED;
        goto error;
    }

    ssize_t size = uper_encode_to_new_buffer(&asn_DEF_GroupKeys,
            NULL, msg, (void **) &payload);
    if (size == -1) {
        status = PEP_CANNOT_ENCODE;
        goto error;
    }

    status = prepare_message(me, partner, payload, size, &_message);
    if (status != PEP_STATUS_OK)
        goto error;
    payload = NULL;

    free_identity(me);
    me = NULL;

    status = session->messageToSend(session->sync_obj, _message);

    free_message(_message);
    ASN_STRUCT_FREE(asn_DEF_GroupKeys, msg);

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    ASN_STRUCT_FREE(asn_DEF_GroupKeys, msg);
    free(payload);
    free_message(_message);
    free_identity(me);
    return status;
}

