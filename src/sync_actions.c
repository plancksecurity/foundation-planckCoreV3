// Actions for DeviceState state machine

#include <assert.h>
#include "keymanagement.h"
#include "sync_fsm.h"
#include "map_asn1.h"
#include "../asn.1/Beacon.h"
#include "../asn.1/HandshakeRequest.h"
#include "../asn.1/OwnKeys.h"


// sendBeacon() - send Beacon message
//
//  params:
//      session (in)        session handle
//      partner (in)        (must be NULL)
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendBeacon(PEP_SESSION session, const Identity partner)
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(!partner);
    if (!(session && !partner))
        return PEP_ILLEGAL_VALUE;

    Beacon_t *msg = (Beacon_t *) calloc(1, sizeof(Beacon_t));
    assert(msg);
    if (!msg)
        goto enomem;

    int32_t seq;
    status = sequence_value(session, "DeviceGroup", &seq);
    if (status != PEP_STATUS_OK)
        goto error;
    msg->header.sequence = (long) seq;

    pEp_identity *me = new_identity(NULL, NULL, NULL, NULL);
    if (!me)
        goto enomem;
    status = myself(session, me);
    if (status != PEP_STATUS_OK)
        goto error;
    if (Identity_from_Struct(me, &msg->me) == NULL)
        goto enomem;

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    ASN_STRUCT_FREE(asn_DEF_Beacon, msg);
    return status;
}


// sendHandshakeRequest() - send HandshakeRequest message
//
//  params:
//      session (in)        session handle
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendHandshakeRequest(PEP_SESSION session, const Identity partner)
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    if (!(session && partner))
        return PEP_ILLEGAL_VALUE;

    HandshakeRequest_t *msg = (HandshakeRequest_t *) calloc(1, sizeof(HandshakeRequest_t));
    assert(msg);
    if (!msg)
        goto enomem;

    int32_t seq;
    status = sequence_value(session, "DeviceGroup", &seq);
    if (status != PEP_STATUS_OK)
        goto error;
    msg->header.sequence = (long) seq;

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

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    ASN_STRUCT_FREE(asn_DEF_HandshakeRequest, msg);
    return status;
}


// showHandshake() - 
//
//  params:
//      session (in)        session handle
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS showHandshake(PEP_SESSION session, const Identity partner)
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
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS reject(PEP_SESSION session, const Identity partner)
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
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS storeGroupKeys(PEP_SESSION session, const Identity partner)
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
//      partner (in)        (must be NULL)
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendOwnKeys(PEP_SESSION session, const Identity partner)
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(!partner);
    if (!(session && !partner))
        return PEP_ILLEGAL_VALUE;

    OwnKeys_t *msg = (OwnKeys_t *) calloc(1, sizeof(OwnKeys_t));
    assert(msg);
    if (!msg)
        goto enomem;

    int32_t seq;
    status = sequence_value(session, "DeviceGroup", &seq);
    if (status != PEP_STATUS_OK)
        goto error;
    msg->header.sequence = (long) seq;

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

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    ASN_STRUCT_FREE(asn_DEF_OwnKeys, msg);
    return status;
}


// transmitGroupKeys() - 
//
//  params:
//      session (in)        session handle
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS transmitGroupKeys(PEP_SESSION session, const Identity partner)
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

