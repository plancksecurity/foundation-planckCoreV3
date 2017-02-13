// This file is under GNU General Public License 3.0
// see LICENSE.txt

// Actions for DeviceState state machine

#include <assert.h>
#include "pEp_internal.h"
#include "message.h"
#include "sync_fsm.h"
#include "map_asn1.h"
#include "baseprotocol.h"

// conditions

int deviceGrouped(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return invalid_condition; // error

    char *devgrp = NULL;
    int res = 0;
    PEP_STATUS status;

    status = get_device_group(session, &devgrp);

    if (status == PEP_STATUS_OK && devgrp && devgrp[0])
        res = 1;

    free(devgrp);

    return res;
}

int keyElectionWon(PEP_SESSION session, Identity partner)
{
    assert(session);
    assert(partner);
    if (!(session && partner))
        return invalid_condition; // error

    // an already existing group always wins

    if (deviceGrouped(session)) {
        assert(!(partner->flags & PEP_idf_devicegroup));
        return 1;
    }

    if (partner->flags & PEP_idf_devicegroup)
        return 0;

    Identity me = NULL;
    PEP_STATUS status = get_identity(session, partner->address, PEP_OWN_USERID,
            &me);
    if (status == PEP_OUT_OF_MEMORY)
        return invalid_out_of_memory;
    if (status != PEP_STATUS_OK)
        return invalid_condition; // error

    int result = invalid_condition; // error state has to be overwritten

    time_t own_created;
    time_t partners_created;

    status = key_created(session, me->fpr, &own_created);
    if (status != PEP_STATUS_OK)
        goto the_end;

    status = key_created(session, partner->fpr, &partners_created);
    if (status != PEP_STATUS_OK)
        goto the_end;

    if (own_created > partners_created)
        result = 0;
    else
        result = 1;

the_end:
    free_identity(me);
    return result;
}

int sameIdentities(PEP_SESSION session, Identity a, Identity b)
{
    assert(session);
    assert(a);
    assert(b);

    if (!(session && a && b))
        return invalid_condition; // error

    if (a->fpr == NULL || b->fpr == NULL ||
        (!_same_fpr(a->fpr, strlen(a->fpr), b->fpr, strlen(b->fpr))) ||
        a->address == NULL || b->address == NULL ||
        strcmp(a->address, b->address) != 0 ||
        a->user_id == NULL || b->user_id == NULL ||
        strcmp(a->user_id, b->user_id) != 0)
            return 0;
    return 1;
}

// actions

PEP_STATUS _notifyHandshake(
        PEP_SESSION session,
        Identity partner,
        sync_handshake_signal signal
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);

    if (!(session && partner))
        return PEP_ILLEGAL_VALUE;

    assert(session->notifyHandshake);
    if (!session->notifyHandshake)
        return PEP_SYNC_NO_NOTIFY_CALLBACK;

    // notifyHandshake take ownership of given identities
    pEp_identity *me = NULL;
    status = get_identity(session, partner->address, PEP_OWN_USERID, &me);
    if (status != PEP_STATUS_OK)
        goto error;
    
    pEp_identity *_partner = NULL;
    _partner = identity_dup(partner);
    if (_partner == NULL){
        status = PEP_OUT_OF_MEMORY;
        goto error;
    }

    status = session->notifyHandshake(session->sync_obj, me, _partner, signal);
    if (status != PEP_STATUS_OK)
        goto error;

    return status;

error:
    free_identity(me);
    return status;
}

// acceptHandshake() - stores acception of partner
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS acceptHandshake(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    assert(extra == NULL);
    if (!(session && partner))
        return PEP_ILLEGAL_VALUE;

    status = trust_personal_key(session, partner);

    return status;
}


// rejectHandshake() - stores rejection of partner
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS rejectHandshake(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    assert(extra == NULL);
    if (!(session && partner))
        return PEP_ILLEGAL_VALUE;

    status = set_identity_flags(session, partner,
            partner->flags | PEP_idf_not_for_sync);

    return status;
}


// storeGroupKeys() - 
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//      _group_keys (in)    group keys received from partner
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS storeGroupKeys(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *_group_keys
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    assert(_group_keys);
    if (!(session && partner && _group_keys))
        return PEP_ILLEGAL_VALUE;

    identity_list *group_keys = (identity_list *) _group_keys;

    for (identity_list *il = group_keys; il && il->ident; il = il->next) {

        // Check that identity isn't excluded from sync.
        pEp_identity *stored_identity = NULL;
        status = get_identity(session, il->ident->address, PEP_OWN_USERID,
                &stored_identity);
        if (status == PEP_STATUS_OK) {
            if(stored_identity->flags & PEP_idf_not_for_sync){
                free_identity(stored_identity);
                continue;
            }
            free_identity(stored_identity);
        }

        free(il->ident->user_id);
        il->ident->user_id = strdup(PEP_OWN_USERID);
        assert(il->ident->user_id);
        if (!il->ident->user_id)
            goto enomem;
        status = set_identity(session, il->ident);
        if (status != PEP_STATUS_OK)
            break;
    }

    free_identity_list(group_keys);
    
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
    free_identity_list(group_keys);
    return status;
}

// enterGroup() - 
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        ignored
//      extra (in)          ignored
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS enterGroup(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);

    // groups have no uuid for now
    status = set_device_group(session, "1");

    // change sync_uuid when entering group 
    // thus ignoring unprocessed handshakes
    // addressed to previous self (sole) once in.
    pEpUUID uuid;
    uuid_generate_random(uuid);
    uuid_unparse_upper(uuid, session->sync_uuid);
    
    return status;
}

// leaveGroup() - 
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        ignored
//      extra (in)          ignored
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS leaveGroup(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);

    status = set_device_group(session, NULL);
    
    return status;
}
