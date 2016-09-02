#include "pEp_internal.h"

#include <memory.h>
#include <assert.h>

#include "asn1_helper.h"
#include "../asn.1/DeviceGroup-Protocol.h"

// receive_sync_msg is defined in the sync_actions

PEP_STATUS receive_sync_msg(
        PEP_SESSION session,
        DeviceGroup_Protocol_t *msg
    );

DYNAMIC_API PEP_STATUS register_sync_callbacks(
        PEP_SESSION session,
        void *obj,
        messageToSend_t messageToSend,
        showHandshake_t showHandshake,
        inject_sync_msg_t inject_sync_msg,
        retrieve_next_sync_msg_t retrieve_next_sync_msg
    )
{
    unsigned char uuid[16];
    uuid_generate_random(uuid);
    uuid_unparse_upper(uuid, sync_uuid);

    session->sync_obj = obj;
    session->messageToSend = messageToSend;
    session->showHandshake = showHandshake;
    session->inject_sync_msg = inject_sync_msg;
    session->retrieve_next_sync_msg = retrieve_next_sync_msg;

    // start state machine
    session->sync_state = InitState;
    PEP_STATUS status = fsm_DeviceState_inject(session, Init, NULL, NULL);
    if (status != PEP_STATUS_OK)
        unregister_sync_callbacks(session);

    return status;
}

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session) {
    // stop state machine
    session->sync_state = DeviceState_state_NONE;

    // unregister
    session->sync_obj = NULL;
    session->messageToSend = NULL;
    session->showHandshake = NULL;
    session->retrieve_next_sync_msg = NULL;
}

DYNAMIC_API PEP_STATUS deliverHandshakeResult(
        PEP_SESSION session,
        sync_handshake_result result
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    switch (result) {
        case SYNC_HANDSHAKE_CANCEL:
            status = fsm_DeviceState_inject(session, Cancel, NULL, 0);
            break;
        case SYNC_HANDSHAKE_ACCEPTED:
            status = fsm_DeviceState_inject(session, HandshakeAccepted, NULL, 0);
            break;
        case SYNC_HANDSHAKE_REJECTED:
            status = fsm_DeviceState_inject(session, HandshakeRejected, NULL, 0);
            break;
        default:
            return PEP_ILLEGAL_VALUE;
    }

    return status;
}

DYNAMIC_API PEP_STATUS do_sync_protocol(
        PEP_SESSION session,
        void *management
    )
{
    DeviceGroup_Protocol_t *msg = NULL;
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session && session->retrieve_next_sync_msg);
    assert(management);

    if (!(session && session->retrieve_next_sync_msg) || !management)
        return PEP_ILLEGAL_VALUE;

    log_event(session, "sync_protocol thread started", "pEp sync protocol", NULL, NULL);

    while ((msg = (DeviceGroup_Protocol_t *) session->retrieve_next_sync_msg(management))) 
    {
        if ((status = receive_sync_msg(session, msg) != PEP_STATUS_OK)) {
            char buffer[MAX_LINELENGTH];
            memset(buffer, 0, MAX_LINELENGTH);
            snprintf(buffer, MAX_LINELENGTH, "problem with msg received: %d\n", (int) status);
            log_event(session, buffer, "pEp sync protocol", NULL, NULL);
        }
    }

    log_event(session, "sync_protocol thread shutdown", "pEp sync protocol", NULL, NULL);

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

