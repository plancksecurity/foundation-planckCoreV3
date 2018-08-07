// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "Sync_impl.h"
#include "pEp_internal.h"
#include "KeySync_fsm.h"

PEP_STATUS Sync_driver(
        PEP_SESSION session,
        Sync_PR fsm,
        int event
    )
{
    assert(session && fsm);
    if (!(session && fsm))
        return PEP_ILLEGAL_VALUE;

    switch (fsm) {
        case Sync_PR_keysync: {
            int state = session->sync_state.keysync.state;
            state = fsm_KeySync(session, state, event);
            if (state > 0)
                session->sync_state.keysync.state = state;
            else if (state < 0)
                return PEP_STATEMACHINE_ERROR - state;
            break;
        }
        
        default:
            return PEP_ILLEGAL_VALUE;
    }

    return PEP_STATUS_OK;
}

PEP_STATUS inject_Sync_event(
        PEP_SESSION session, 
        Sync_PR fsm,
        int event
    )
{
    Sync_t *msg = NULL;
    Sync_event_t *ev = NULL;

    assert(session && fsm > 0 && event > None);
    if (!(session && fsm > 0 && event > None))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    if (!session->inject_sync_msg) {
       status = PEP_SYNC_NO_INJECT_CALLBACK;
       goto error;
    }

    if (event < Extra) {
        msg = new_Sync_message(fsm, event);
        assert(msg);
        if (!msg) {
            status = PEP_OUT_OF_MEMORY;
            goto error;
        }

        status = update_Sync_message(session, fsm, event, msg);
        if (status)
            goto error;
    }

    ev = (Sync_event_t *) calloc(1, sizeof(Sync_event_t));
    assert(ev);
    if (!ev) {
        status = PEP_OUT_OF_MEMORY;
        goto error;
    }
    
    ev->fsm = fsm;
    ev->event = event;
    ev->msg = msg;

    int result = session->inject_sync_msg(ev,
            session->sync_management);
    if (result) {
        status = PEP_STATEMACHINE_ERROR;
        goto error;
    }

    goto the_end;

error:
    free(ev);
    free_Sync_message(msg);

the_end:
    return status;
}

PEP_STATUS Sync_send(
        PEP_SESSION session, 
        Sync_PR fsm,
        int message_type
    )
{
    assert(session && fsm > 0 && message_type > 1 && message_type < Extra);
    if (!(session && fsm > 0 && message_type > 1 && message_type < Extra))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    Sync_t *msg = new_Sync_message(fsm, message_type);
    assert(msg);
    if (!msg) {
        status = PEP_OUT_OF_MEMORY;
        goto error;
    }

    status = update_Sync_message(session, fsm, message_type, msg);
    if (status)
        goto error;

    goto the_end;

error:
    free_Sync_message(msg);

the_end:
    return status;
}

PEP_STATUS recv_Sync_event(
        PEP_SESSION session, 
        Sync_event_t *ev
    )
{
    assert(session && ev);
    if (!(session && ev))
        return PEP_ILLEGAL_VALUE;

    assert(ev->fsm >= None && ev->event >= None);
    if (!(ev->fsm >= None && ev->event >= None))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    if (ev->event < Extra) {
        Sync_PR fsm = (int) None;
        int event = None;

        status = update_Sync_state(session, ev->msg, &fsm, &event);
        if (status)
            goto error;

        if (ev->fsm) {
            if (ev->fsm != fsm || ev->event != event) {
                status = PEP_SYNC_ILLEGAL_MESSAGE;
                goto error;
            }
        }
        else {
            if (ev->event) {
                status = PEP_SYNC_ILLEGAL_MESSAGE;
                goto error;
            }
            ev->fsm = fsm;
            ev->event = event;
        }
    }

    free_Sync_message(ev->msg);
    free(ev);
    status = Sync_driver(session, ev->fsm, ev->event);
    return status;

error:
    free_Sync_message(ev->msg);
    free(ev);
    return status;
}

