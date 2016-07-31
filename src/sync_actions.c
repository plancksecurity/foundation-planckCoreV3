// Actions for DeviceState state machine

#include <assert.h>
#include "pEp_internal.h"
#include "message.h"
#include "sync_fsm.h"
#include "map_asn1.h"

// conditions

static const char *sql_stored_group_keys =
        "select count(device_group) from person where id = "PEP_OWN_USERID";"; 

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

bool storedGroupKeys(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return false;

    bool gc = false;
    int int_result = sqlite3_exec(
        session->db,
        sql_stored_group_keys,
        _stored_group_keys,
        &gc,
        NULL
    );
    assert(int_result == SQLITE_OK);
    return gc;
}

bool keyElectionWon(PEP_SESSION session, Identity partner)
{
    assert(session);
    assert(partner);
    if (!(session && partner))
        return false;

    // an already existing group always wins

    if (storedGroupKeys(session)) {
        assert(!(partner->flags & PEP_idf_devicegroup));
        return true;
    }

    if (partner->flags & PEP_idf_devicegroup)
        return false;

    Identity me = NULL;
    PEP_STATUS status = get_identity(session, partner->address, PEP_OWN_USERID,
            &me);
    if (status != PEP_STATUS_OK)
        return false;

    bool result = false;


the_end:
    free_identity(me);
    return result;
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
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    assert(extra == NULL);

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
    free_identity(partner);
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    free_identity(me);
    free_identity(partner);
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

    free_identity(partner);
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    free_identity(partner);
    // free...
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
    if (!group_keys)
        goto enomem;

    free_identity(partner);
    free_identity_list(group_keys);
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    // free...
    free_identity(partner);
    free_identity_list(group_keys);
    return status;
}

static PEP_STATUS receive_sync_msg(PEP_SESSION session, DeviceGroup_Protocol_t *msg)
{
    assert(session && msg && msg->present != DeviceGroup_Protocol_PR_NOTHING);
    if (!(session && msg && msg->present != DeviceGroup_Protocol_PR_NOTHING))
        return PEP_ILLEGAL_VALUE;

    void *extra = NULL;
    Identity partner = NULL;
    DeviceState_event event = DeviceState_event_NONE;

    switch (msg->present) {
        case DeviceGroup_Protocol_PR_beacon:
            partner = Identity_to_Struct(&msg->choice.beacon.header.me, NULL);
            if (!partner)
                return PEP_OUT_OF_MEMORY;
            event = Beacon;
            break;

        case DeviceGroup_Protocol_PR_handshakeRequest:
            partner = Identity_to_Struct(&msg->choice.handshakeRequest.header.me, NULL);
            if (!partner)
                return PEP_OUT_OF_MEMORY;
            event = HandshakeRequest;
            break;

        case DeviceGroup_Protocol_PR_groupKeys:
            partner = Identity_to_Struct(&msg->choice.groupKeys.header.me, NULL);
            if (!partner)
                return PEP_OUT_OF_MEMORY;
            identity_list *group_keys = IdentityList_to_identity_list(
                    &msg->choice.groupKeys.ownIdentities, NULL);
            if (!group_keys) {
                free_identity(partner);
                return PEP_OUT_OF_MEMORY;
            }
            extra = (void *) group_keys;
            event = GroupKeys;
            break;

        default:
            return PEP_SYNC_ILLEGAL_MESSAGE;
    }

    return fsm_DeviceState_inject(session, event, partner, extra);
}

PEP_STATUS receive_DeviceState_msg(PEP_SESSION session, message *src)
{
    assert(session && src);
    if (!(session && src))
        return PEP_ILLEGAL_VALUE;

    return PEP_STATUS_OK;
}

