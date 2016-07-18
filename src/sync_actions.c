// Actions for DeviceState state machine

#include <assert.h>
#include "pEp_internal.h"
#include "message.h"
#include "sync_fsm.h"


// showHandshake() - trigger the handshake dialog of the application
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
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
    assert(session->showHandshake);
    if (!session->showHandshake)
        return PEP_SYNC_NO_TRUSTWORDS_CALLBACK;

    pEp_identity *me = NULL;
    status = get_identity(session, partner->address, PEP_OWN_USERID, &me);
    if (status != PEP_STATUS_OK)
        goto error;
    
    status = session->showHandshake(session, me, partner);
    if (status != PEP_STATUS_OK)
        goto error;

    free_identity(me);
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    free_identity(me);
    return status;
}


// reject() - stores rejection of partner
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
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
//      partner (in)        partner to communicate with
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

