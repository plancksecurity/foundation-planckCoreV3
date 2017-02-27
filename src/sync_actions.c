// This file is under GNU General Public License 3.0
// see LICENSE.txt

// Actions for DeviceState state machine

#include <assert.h>
#include "pEp_internal.h"
#include "message.h"
#include "sync_fsm.h"
#include "sync_impl.h"
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

    int partner_is_group = partner->flags & PEP_idf_devicegroup;

    if (deviceGrouped(session)){
        // existing group always wins against sole device
        if(!partner_is_group)
            return 1;
    } else {
        // sole device always loses against group
        if(partner_is_group)
            return 0;
    }

    // two groups or two sole are elected based on key age
    // key created first wins

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

PEP_STATUS _storeGroupKeys(
        PEP_SESSION session,
        identity_list *group_keys
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    for (identity_list *il = group_keys; il && il->ident; il = il->next) {

        if (strcmp(il->ident->user_id, PEP_OWN_USERID)!=0) {
            assert(0);
            continue;
        }
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

        status = set_identity(session, il->ident);
        if (status != PEP_STATUS_OK)
            break;
    }

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
        void *group_keys_extra_
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    assert(group_keys_extra_);
    if (!(session && partner && group_keys_extra_))
        return PEP_ILLEGAL_VALUE;

    group_keys_extra_t *group_keys_extra = 
        (group_keys_extra_t*) group_keys_extra_;
    identity_list *group_keys = group_keys_extra->group_keys;
    char *group_id = group_keys_extra->group_id;

    status = _storeGroupKeys(session, group_keys);
    if (status != PEP_STATUS_OK)
        return status;

    // set group id according to given group-id
    status = set_device_group(session, group_id);
    if (status != PEP_STATUS_OK)
        return status;
    
    return status;
}

// storeGroupUpdate() - 
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//      _group_keys (in)    group keys received from partner
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS storeGroupUpdate(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *group_keys_
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    assert(group_keys_);
    if (!(session && partner && group_keys_))
        return PEP_ILLEGAL_VALUE;

    identity_list *group_keys = (identity_list*) group_keys_;

    status = _storeGroupKeys(session, group_keys);


    return status;
}

// makeGroup() - 
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        ignored
//      extra (in)          ignored
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS makeGroup(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    
    // take that new uuid as group-id
    status = set_device_group(session, session->sync_uuid);

    return status;
}

// renewUUID() - 
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        ignored
//      extra (in)          ignored
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS renewUUID(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);

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
