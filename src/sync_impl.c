// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "Sync_impl.h"
#include "pEp_internal.h"
#include "Sync_event.h"
#include "Sync_codec.h"
#include "baseprotocol.h"
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

    int next_state = None;
    do {
        switch (fsm) {
            case Sync_PR_keysync: {
                int state = session->sync_state.keysync.state;
                next_state = fsm_KeySync(session, state, event);
                if (next_state > None) {
                    session->sync_state.keysync.state = next_state;
                    event = Init;
                }
                else if (next_state < None) {
                    return PEP_STATEMACHINE_ERROR - state;
                }
                break;
            }
            
            default:
                return PEP_ILLEGAL_VALUE;
        }
    }  while (next_state);

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

    if (!session->inject_sync_event) {
       status = PEP_SYNC_NO_INJECT_CALLBACK;
       goto error;
    }

    if (event < Extra) {
        msg = new_Sync_message(fsm, event);
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

    int result = session->inject_sync_event(ev,
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

PEP_STATUS Sync_notify(
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

PEP_STATUS send_Sync_message(
        PEP_SESSION session, 
        Sync_PR fsm,
        int message_type
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session && fsm > None && message_type > None);
    if (!(session && fsm > None && message_type > None))
        return PEP_ILLEGAL_VALUE;
    
    Sync_t *msg = new_Sync_message(None, None);
    if (!msg)
        return PEP_OUT_OF_MEMORY;

    char *data = NULL;
    message *m = NULL;

    status = update_Sync_message(session, fsm, message_type, msg);
    if (status)
        goto the_end;

    size_t size = 0;
    status = encode_Sync_message(msg, &data, &size);
    if (status)
        goto the_end;

    status = prepare_message(
            session->sync_state.common.from,
            session->sync_state.common.from,
            data,
            size,
            &m
        );
    if (status)
        goto the_end;
    
    session->messageToSend(session->sync_obj, m);

the_end:
    free_message(m);
    free(data);
    free_Sync_message(msg);
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

