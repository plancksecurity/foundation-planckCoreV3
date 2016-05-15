// Actions for DeviceState state machine

#include <assert.h>
#include "sync_fsm.h"


// sendBeacon() - 
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

    assert(partner == NULL);
    if (partner)
        return PEP_ILLEGAL_VALUE;

    // working code


    return status;
}

// sendHandshakeRequest() - 
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

    assert(partner);
    if (!partner)
        return PEP_ILLEGAL_VALUE;

    // working code


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

    assert(partner);
    if (!partner)
        return PEP_ILLEGAL_VALUE;

    // working code


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

    assert(partner);
    if (!partner)
        return PEP_ILLEGAL_VALUE;

    // working code


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

    assert(partner);
    if (!partner)
        return PEP_ILLEGAL_VALUE;

    // working code


    return status;
}

// sendOwnKeys() - 
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

    assert(partner == NULL);
    if (partner)
        return PEP_ILLEGAL_VALUE;

    // working code


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

    assert(partner);
    if (!partner)
        return PEP_ILLEGAL_VALUE;

    // working code


    return status;
}

