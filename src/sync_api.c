// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"

#include <memory.h>
#include <assert.h>

#include "KeySync_fsm.h"

DYNAMIC_API PEP_STATUS register_sync_callbacks(
        PEP_SESSION session,
        void *management,
        notifyHandshake_t notifyHandshake,
        retrieve_next_sync_event_t retrieve_next_sync_event
    )
{
    assert(session && notifyHandshake && retrieve_next_sync_event);
    if (!(session && notifyHandshake && retrieve_next_sync_event))
        return PEP_ILLEGAL_VALUE;

    identity_list *own_identities = NULL;
    PEP_STATUS status = own_identities_retrieve(session, &own_identities);
    if (status)
        return status;
    bool own_identities_available = own_identities && own_identities->ident;
    free_identity_list(own_identities);
    if (!own_identities_available)
        return PEP_SYNC_CANNOT_START;

    session->sync_management = management;
    session->notifyHandshake = notifyHandshake;
    session->retrieve_next_sync_event = retrieve_next_sync_event;

    // start state machine
    return Sync_driver(session, Sync_PR_keysync, Init);
}

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session) {
    // stop state machine
    free_Sync_state(session);

    // unregister
    session->sync_management = NULL;
    session->notifyHandshake = NULL;
    session->retrieve_next_sync_event = NULL;
}

DYNAMIC_API PEP_STATUS deliverHandshakeResult(
        PEP_SESSION session,
        sync_handshake_result result,
        const identity_list *identities_sharing
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    for (const identity_list *_il = identities_sharing; _il && _il->ident;
            _il = _il->next) {
        if (!_il->ident->me || !_il->ident->user_id || !_il->ident->user_id[0]
                || !_il->ident->address || !_il->ident->address[0])
            return PEP_ILLEGAL_VALUE;
    }

    PEP_STATUS status = PEP_STATUS_OK;
    int event;

    switch (result) {
        case SYNC_HANDSHAKE_CANCEL:
            event = Cancel;
            break;
        case SYNC_HANDSHAKE_ACCEPTED:
        {
            event = Accept;
            break;
        }
        case SYNC_HANDSHAKE_REJECTED:
        {
            event = Reject;
            break;
        }
        default:
            return PEP_ILLEGAL_VALUE;
    }

    identity_list *own_identities = NULL;

    if (identities_sharing && identities_sharing->ident) {
        own_identities = identity_list_dup(identities_sharing);
        if (!own_identities)
            return PEP_OUT_OF_MEMORY;
    }
    else {
        status = own_identities_retrieve(session, &own_identities);
    }

    if (!status)
        status = signal_Sync_event(session, Sync_PR_keysync, event, own_identities);
    return status;
}

DYNAMIC_API PEP_STATUS do_sync_protocol(
        PEP_SESSION session,
        void *obj
    )
{
    Sync_event_t *event= NULL;

    assert(session && session->retrieve_next_sync_event);
    if (!(session && session->retrieve_next_sync_event))
        return PEP_ILLEGAL_VALUE;

    log_event(session, "sync_protocol thread started", "pEp sync protocol",
            NULL, NULL);

    while (true) 
    {
        event = session->retrieve_next_sync_event(session->sync_management,
                SYNC_THRESHOLD);
        if (!event)
            break;

        do_sync_protocol_step(session, obj, event);
    }
    session->sync_obj = NULL;

    log_event(session, "sync_protocol thread shutdown", "pEp sync protocol",
            NULL, NULL);

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS do_sync_protocol_step(
        PEP_SESSION session,
        void *obj,
        SYNC_EVENT event
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    if (!event)
        return PEP_STATUS_OK;

    session->sync_obj = obj;

    PEP_STATUS status = recv_Sync_event(session, event);
    return status == PEP_MESSAGE_IGNORE ? PEP_STATUS_OK : status;
}

DYNAMIC_API bool is_sync_thread(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return false;
    return session->retrieve_next_sync_event != NULL;
}

DYNAMIC_API SYNC_EVENT new_sync_timeout_event()
{
    return SYNC_TIMEOUT_EVENT;
}

DYNAMIC_API PEP_STATUS enter_device_group(
        PEP_SESSION session,
        const identity_list *identities_sharing
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    for (const identity_list *_il = identities_sharing; _il && _il->ident;
            _il = _il->next) {
        if (!_il->ident->me || !_il->ident->user_id || !_il->ident->user_id[0]
                || !_il->ident->address || !_il->ident->address[0])
            return PEP_ILLEGAL_VALUE;
    }

    identity_list *own_identities = NULL;
    PEP_STATUS status = own_identities_retrieve(session, &own_identities);
    if (status)
        goto the_end;

    if (identities_sharing && identities_sharing->ident) {
        for (identity_list *_il = own_identities; _il && _il->ident;
                _il = _il->next) {
            bool found = false;

            for (const identity_list *_is = identities_sharing;
                    _is && _is->ident; _is = _is->next) {
                // FIXME: "john@doe.com" and "mailto:john@doe.com" should be equal
                if (strcmp(_il->ident->address, _is->ident->address) == 0
                        && strcmp(_il->ident->user_id, _is->ident->user_id) == 0) {
                    found = true;

                    status = set_identity_flags(session, _il->ident, PEP_idf_devicegroup);
                    if (status)
                        goto the_end;

                    break;
                }
            }
            if (!found) {
                status = unset_identity_flags(session, _il->ident, PEP_idf_devicegroup);
                if (status)
                    goto the_end;
            }
        }
    }
    else {
        for (identity_list *_il = own_identities; _il && _il->ident;
                _il = _il->next) {
            status = set_identity_flags(session, _il->ident, PEP_idf_devicegroup);
            if (status)
                goto the_end;
        }
    }

the_end:
    free_identity_list(own_identities);
    return status;
}

PEP_STATUS disable_sync(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    if (session->inject_sync_event)
        session->inject_sync_event((void *) SHUTDOWN, NULL);

    identity_list *il = NULL;
    PEP_STATUS status = own_identities_retrieve(session, &il);
    if (status)
        goto the_end;

    for (identity_list *_il = il; _il && _il->ident ; _il = _il->next) {
        status = unset_identity_flags(session, _il->ident, PEP_idf_devicegroup);
        if (status)
            goto the_end;
    }

the_end:
    free_identity_list(il);
    return status;
}

DYNAMIC_API PEP_STATUS leave_device_group(PEP_SESSION session) {
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    bool grouped = false;
    PEP_STATUS status = deviceGrouped(session, &grouped);
    if (status)
        return status;

    if (!grouped) {
        if (session->inject_sync_event)
            session->inject_sync_event((void *) SHUTDOWN, NULL);
        return PEP_STATUS_OK;
    }

    return signal_Sync_event(session, Sync_PR_keysync, LeaveDeviceGroup, NULL);
}

DYNAMIC_API PEP_STATUS enable_identity_for_sync(PEP_SESSION session,
        pEp_identity *ident)
{
    assert(session && ident && ident->user_id && ident->user_id[0] && ident->address && ident->address[0]);
    if (!(session && ident && ident->user_id && ident->user_id[0] && ident->address && ident->address[0]))
        return PEP_ILLEGAL_VALUE;

    // safeguard: in case the delivered identity is not valid fetch flags from the database
    //            while doing this check if this is an own identity and return an error if not

    pEp_identity *stored_ident = NULL;
    PEP_STATUS status = get_identity(session, ident->address, ident->user_id, &stored_ident);
    if (status)
        return status;
    assert(stored_ident);
    if (!stored_ident->me) {
        free_identity(stored_ident);
        return PEP_ILLEGAL_VALUE;
    }
    ident->flags = stored_ident->flags;
    free_identity(stored_ident);

    // this is an invalid state; detect while debugging

    assert(!((ident->flags & PEP_idf_devicegroup) && (ident->flags & PEP_idf_not_for_sync)));

    // if we're grouped and this identity is enabled already we can stop here

    if ((ident->flags & PEP_idf_devicegroup) && !(ident->flags & PEP_idf_not_for_sync))
        return PEP_STATUS_OK;

    // if the identity is marked not for sync unset this to enable

    if (ident->flags & PEP_idf_not_for_sync) {
        status = unset_identity_flags(session, ident, PEP_idf_not_for_sync);
        if (status)
            return status;
    }

    // if we're grouped then add the identity to the group

    bool grouped = false;
    status = deviceGrouped(session, &grouped);
    if (status)
        return status;
    if (grouped) {
        status = set_identity_flags(session, ident, PEP_idf_devicegroup);    
        if (status)
            return status;
        // signal we have a new identity in the group
        signal_Sync_event(session, Sync_PR_keysync, KeyGen, NULL);
    }

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS disable_identity_for_sync(PEP_SESSION session,
        pEp_identity *ident)
{
    assert(session && ident);
    if (!(session && ident))
        return PEP_ILLEGAL_VALUE;

    // safeguard: in case the delivered identity is not valid fetch flags from the database
    //            while doing this check if this is an own identity and return an error if not

    pEp_identity *stored_ident = NULL;
    PEP_STATUS status = get_identity(session, ident->address, ident->user_id, &stored_ident);
    if (status)
        return status;
    assert(stored_ident);
    if (!stored_ident->me) {
        free_identity(stored_ident);
        return PEP_ILLEGAL_VALUE;
    }
    ident->flags = stored_ident->flags;
    free_identity(stored_ident);

    // if the identity is not part of a device group just disable it to keep this

    if (!(ident->flags & PEP_idf_devicegroup)) {
        status = set_identity_flags(session, ident, PEP_idf_not_for_sync);
        return status;
    }

    // we are grouped and this identity is part of a device group => key reset in all cases

    status = unset_identity_flags(session, ident, PEP_idf_devicegroup);
    if (status)
        return status;

    status = set_identity_flags(session, ident, PEP_idf_not_for_sync);
    if (status)
        return status;

    status = key_reset_identity(session, ident, NULL);
    return status;
}

DYNAMIC_API PEP_STATUS disable_all_sync_channels(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    identity_list *own_identities = NULL;
    PEP_STATUS status = own_identities_retrieve(session, &own_identities);
    if (status)
        return status;

    for (identity_list *oi = own_identities; oi && oi->ident; oi = oi->next) {
        status = set_identity_flags(session, oi->ident, PEP_idf_not_for_sync);
        if (status)
            break;
    }

    free_identity_list(own_identities);
    return status;
}

