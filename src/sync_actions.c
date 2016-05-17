// Actions for DeviceState state machine

#include <assert.h>
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

    
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    ASN_STRUCT_FREE(asn_DEF_HandshakeRequest, msg);
    return status;
}


// showHandshake() - send
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


// reject() - send
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


// storeGroupKeys() - send
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

    
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    ASN_STRUCT_FREE(asn_DEF_OwnKeys, msg);
    return status;
}


// transmitGroupKeys() - send
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

