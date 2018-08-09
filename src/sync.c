// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"

#include <memory.h>
#include <assert.h>

#include "asn1_helper.h"
#include "KeySync_fsm.h"

// receive_sync_msg is defined in the sync_impl

PEP_STATUS receive_sync_msg(
        PEP_SESSION session,
        sync_msg_t *sync_msg,
        time_t *timeout
    );

DYNAMIC_API PEP_STATUS register_sync_callbacks(
        PEP_SESSION session,
        void *management,
        messageToSend_t messageToSend,
        notifyHandshake_t notifyHandshake,
        inject_sync_msg_t inject_sync_msg,
        retrieve_next_sync_msg_t retrieve_next_sync_msg
    )
{
    assert(session && management && messageToSend && notifyHandshake && inject_sync_msg && retrieve_next_sync_msg);
    if (!(session && management && messageToSend && notifyHandshake && inject_sync_msg && retrieve_next_sync_msg))
        return PEP_ILLEGAL_VALUE;

    session->sync_management = management;
    session->messageToSend = messageToSend;
    session->notifyHandshake = notifyHandshake;
    session->inject_sync_msg = inject_sync_msg;
    session->retrieve_next_sync_msg = retrieve_next_sync_msg;

    // start state machine
    PEP_STATUS status = inject_Sync_event(session, Sync_PR_keysync, Init);
    if (status != PEP_STATUS_OK)
        unregister_sync_callbacks(session);

    return status;
}

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session) {
    // stop state machine
    memset(&session->sync_state, 0, sizeof(session->sync_state));

    // unregister
    session->sync_management = NULL;
    session->messageToSend = NULL;
    session->notifyHandshake = NULL;
    session->inject_sync_msg = NULL;
    session->retrieve_next_sync_msg = NULL;
}

DYNAMIC_API PEP_STATUS deliverHandshakeResult(
        PEP_SESSION session,
        pEp_identity *partner,
        sync_handshake_result result
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    int event;
    bool need_partner = false;

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

    pEp_identity *_partner = NULL;
    if(need_partner){
        _partner = identity_dup(partner);
        if (_partner == NULL)
            return PEP_OUT_OF_MEMORY;
    }
    status = inject_DeviceState_event(session, event, _partner, NULL);

    return status;
}

DYNAMIC_API PEP_STATUS do_sync_protocol(
        PEP_SESSION session,
        void *obj
    )
{
    sync_msg_t *msg = NULL;
    PEP_STATUS status = PEP_STATUS_OK;
    time_t timeout = 0;

    assert(session && session->retrieve_next_sync_msg);
    assert(obj);

    if (!(session && session->retrieve_next_sync_msg) || !obj)
        return PEP_ILLEGAL_VALUE;

    log_event(session, "sync_protocol thread started", "pEp sync protocol", NULL, NULL);

    session->sync_obj = obj;

    while (true) 
    {
        msg = (sync_msg_t *) session->retrieve_next_sync_msg(session->sync_management, &timeout);
        if(msg == NULL && timeout == 0)
            break;
        else if(msg == NULL && timeout != 0){
            status = fsm_DeviceState_inject(session, Timeout, NULL, NULL, &timeout);
#ifndef NDEBUG
            char buffer[MAX_LINELENGTH];
            memset(buffer, 0, MAX_LINELENGTH);
            snprintf(buffer, MAX_LINELENGTH, "problem with timeout event : %d\n", (int) status);
            log_event(session, buffer, "pEp sync protocol", NULL, NULL);
            continue;
#endif
        }
        else {
            status = receive_sync_msg(session, msg, &timeout);
            if (status != PEP_STATUS_OK && status != PEP_MESSAGE_IGNORE) {
#ifndef NDEBUG
                char buffer[MAX_LINELENGTH];
                memset(buffer, 0, MAX_LINELENGTH);
                snprintf(buffer, MAX_LINELENGTH, "problem with msg received: %d\n", (int) status);
                log_event(session, buffer, "pEp sync protocol", NULL, NULL);
#endif
            }
        }
    }

    log_event(session, "sync_protocol thread shutdown", "pEp sync protocol", NULL, NULL);

    session->sync_obj = NULL;

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS decode_sync_msg(
        const char *data,
        size_t size,
        char **text
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(data && text);
    if (!(data && text))
        return PEP_ILLEGAL_VALUE;

    *text = NULL;

    DeviceGroup_Protocol_t *msg = NULL;
    uper_decode_complete(NULL, &asn_DEF_DeviceGroup_Protocol, (void **) &msg,
            data, size);
    if (!msg)
        return PEP_SYNC_ILLEGAL_MESSAGE;

    growing_buf_t *dst = new_growing_buf();
    if (!dst) {
        status = PEP_OUT_OF_MEMORY;
        goto the_end;
    }

    asn_enc_rval_t er = xer_encode(&asn_DEF_DeviceGroup_Protocol, msg,
            XER_F_BASIC, (asn_app_consume_bytes_f *) consume_bytes, (void *) dst);
    if (er.encoded == -1) {
        status = PEP_CANNOT_ENCODE;
        goto the_end;
    }

    *text = dst->data;
    dst->data = NULL;

the_end:
    free_growing_buf(dst);
    ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
    return status;
}

DYNAMIC_API PEP_STATUS encode_sync_msg(
        const char *text,
        char **data,
        size_t *size
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(text && data && size);
    if (!(text && data && size))
        return PEP_ILLEGAL_VALUE;

    *data = NULL;
    *size = 0;

    DeviceGroup_Protocol_t *msg = NULL;
    asn_dec_rval_t dr = xer_decode(NULL, &asn_DEF_DeviceGroup_Protocol,
            (void **) &msg, (const void *) text, strlen(text));
    if (dr.code != RC_OK) {
        status = PEP_SYNC_ILLEGAL_MESSAGE;
        goto the_end;
    }

    char *payload = NULL;
    ssize_t _size = uper_encode_to_new_buffer(&asn_DEF_DeviceGroup_Protocol,
            NULL, msg, (void **) &payload);
    if (_size == -1) {
        status = PEP_CANNOT_ENCODE;
        goto the_end;
    }

    *data = payload;
    *size = (size_t) _size;

the_end:
    ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
    return status;
}

