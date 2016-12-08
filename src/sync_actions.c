// Actions for DeviceState state machine

#include <assert.h>
#include "pEp_internal.h"
#include "message.h"
#include "sync_fsm.h"
#include "map_asn1.h"
#include "baseprotocol.h"

// conditions

static const char *sql_stored_group_keys =
        "select count(device_group) from person where id = '" PEP_OWN_USERID "';"; 

static int _stored_group_keys(void *_gc, int count, char **text, char **name)
{
    assert(_gc);
    assert(count == 1);
    assert(text && text[0]);
    if (!(_gc && count == 1 && text && text[0]))
        return -1;

    bool *gc = (bool *) _gc;
    *gc = atoi(text[0]) != 0;
    return 0;
}

int storedGroupKeys(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return invalid_condition; // error

    bool gc = false;
    int int_result = sqlite3_exec(
        session->db,
        sql_stored_group_keys,
        _stored_group_keys,
        &gc,
        NULL
    );
    assert(int_result == SQLITE_OK);
    if (int_result != SQLITE_OK)
        return invalid_condition; // error

    if (gc)
        return 1;
    else
        return 0;
}

int keyElectionWon(PEP_SESSION session, Identity partner)
{
    assert(session);
    assert(partner);
    if (!(session && partner))
        return invalid_condition; // error

    // an already existing group always wins

    if (storedGroupKeys(session)) {
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

static PEP_STATUS _notifyHandshake(
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
        Identity partner,
        void *extra
    )
{
   assert(extra == NULL);
   return _notifyHandshake(session, partner, SYNC_NOTIFY_INIT_ADD_OUR_DEVICE);
}

// dismissHandshake() - kill the handshake dialog of the application
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS dismissHandshake(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
   assert(extra == NULL);
   return _notifyHandshake(session, partner, SYNC_NOTIFY_DISMISSED);
}

// handshakeSuccess() - notify the application that handshake succeeded
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS handshakeSuccess(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
   assert(extra == NULL);
   return _notifyHandshake(session, partner, SYNC_NOTIFY_ACCEPTED_DEVICE_ADDED);
}

// handshakeGroupCreated() - notify the application that initial group was created
//                           and partner's device was included in group
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS handshakeGroupCreated(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
   assert(extra == NULL);
   return _notifyHandshake(session, partner, SYNC_NOTIFY_ACCEPTED_GROUP_CREATED);
}

// handshakeDeviceAdded() - notify the application that partner's device was added to group
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS handshakeDeviceAdded(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
   assert(extra == NULL);
   return _notifyHandshake(session, partner, SYNC_NOTIFY_ACCEPTED_DEVICE_ADDED);
}

// handshakeFailure() - notify the application that handshake failed
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS handshakeFailure(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
   assert(extra == NULL);
   return _notifyHandshake(session, partner, SYNC_NOTIFY_TIMEOUT);
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
        pEp_identity *stored_identity;
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
    
    return status;
}
