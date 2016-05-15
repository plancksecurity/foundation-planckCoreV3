// Actions for DeviceState state machine

#include <assert.h>
#include "sync_fsm.h"


// sendBeacon() - 
//
//  params:
//      partner (in)        (must be NULL)
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendBeacon(const Identity partner)
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
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendHandshakeRequest(const Identity partner)
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
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS showHandshake(const Identity partner)
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
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS reject(const Identity partner)
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
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS storeGroupKeys(const Identity partner)
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
//      partner (in)        (must be NULL)
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS sendOwnKeys(const Identity partner)
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
//      partner (in)        partner in sync
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS transmitGroupKeys(const Identity partner)
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(partner);
    if (!partner)
        return PEP_ILLEGAL_VALUE;

    // working code


    return status;
}

