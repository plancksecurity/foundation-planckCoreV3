// Actions for DeviceState state machine

#include <assert.h>
#include "pEp_internal.h"
#include "keymanagement.h"
#include "message.h"
#include "sync_fsm.h"
#include "baseprotocol.h"
#include "map_asn1.h"
#include "../asn.1/Beacon.h"
#include "../asn.1/HandshakeRequest.h"
#include "../asn.1/OwnKeys.h"


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
        const Identity partner
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    Beacon_t *msg = NULL;
    char *payload = NULL;
    message *_message = NULL;

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

    pEp_identity *me = new_identity(NULL, NULL, NULL, NULL);
    if (!me)
        goto enomem;
    status = myself(session, me);
    if (status != PEP_STATUS_OK)
        goto error;
    if (Identity_from_Struct(me, &msg->me) == NULL)
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
    return status;
}


// sendHandshakeRequest() - send HandshakeRequest message
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendHandshakeRequest(
        PEP_SESSION session,
        DeviceState_state state,
        const Identity partner
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    HandshakeRequest_t *msg = NULL;
    char *payload = NULL;
    message *_message = NULL;

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

    pEp_identity *me = new_identity(NULL, NULL, NULL, NULL);
    if (!me)
        goto enomem;
    status = myself(session, me);
    if (status != PEP_STATUS_OK)
        goto error;
    if (Identity_from_Struct(me, &msg->me) == NULL)
        goto enomem;

    if (Identity_from_Struct(partner, &msg->partner) == NULL)
        goto enomem;

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
    return status;
}


// showHandshake() - 
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS showHandshake(
        PEP_SESSION session,
        DeviceState_state state,
        const Identity partner
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    if (!(session && partner))
        return PEP_ILLEGAL_VALUE;

    // working code


    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    // free...
    return status;
}


// reject() - 
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS reject(
        PEP_SESSION session,
        DeviceState_state state,
        const Identity partner
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    if (!(session && partner))
        return PEP_ILLEGAL_VALUE;

    // working code


    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    // free...
    return status;
}


// storeGroupKeys() - 
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS storeGroupKeys(
        PEP_SESSION session,
        DeviceState_state state,
        const Identity partner
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    if (!(session && partner))
        return PEP_ILLEGAL_VALUE;

    // working code


    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    // free...
    return status;
}


// sendOwnKeys() - send OwnKeys message
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        (must be NULL)
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendOwnKeys(
        PEP_SESSION session,
        DeviceState_state state,
        const Identity partner
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    OwnKeys_t *msg = NULL;
    char *payload = NULL;
    message *_message = NULL;

    assert(session);
    assert(!partner);
    if (!(session && !partner))
        return PEP_ILLEGAL_VALUE;

    assert(session->messageToSend);
    if (!session->messageToSend)
        return PEP_SEND_FUNCTION_NOT_REGISTERED;

    msg = (OwnKeys_t *) calloc(1, sizeof(OwnKeys_t));
    assert(msg);
    if (!msg)
        goto enomem;

    int32_t seq;
    status = sequence_value(session, "DeviceGroup", &seq);
    if (status != PEP_STATUS_OK)
        goto error;
    msg->header.sequence = (long) seq;

    msg->state = (long) state;

    pEp_identity *me = new_identity(NULL, NULL, NULL, NULL);
    if (!me)
        goto enomem;
    status = myself(session, me);
    if (status != PEP_STATUS_OK)
        goto error;
    if (Identity_from_Struct(me, &msg->me) == NULL)
        goto enomem;

    stringlist_t *sl;
    status = own_key_retrieve(session, &sl);
    if (status != PEP_STATUS_OK)
        goto error;
    if (KeyList_from_stringlist(sl, &msg->keylist) == NULL)
        goto enomem;

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

    status = session->messageToSend(session->sync_obj, _message);

    free_message(_message);
    ASN_STRUCT_FREE(asn_DEF_OwnKeys, msg);

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    ASN_STRUCT_FREE(asn_DEF_OwnKeys, msg);
    free(payload);
    free_message(_message);
    return status;
}


// transmitGroupKeys() - 
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS transmitGroupKeys(
        PEP_SESSION session,
        DeviceState_state state,
        const Identity partner
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    if (!(session && partner))
        return PEP_ILLEGAL_VALUE;

    // working code


    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    // free...
    return status;
}

