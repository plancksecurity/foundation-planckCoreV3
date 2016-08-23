#include "../asn.1/DeviceGroup-Protocol.h"
#include "sync_impl.h"
#include "pEp_internal.h"
#include "keymanagement.h"
#include "map_asn1.h"
#include "baseprotocol.h"

PEP_STATUS receive_sync_msg(
        PEP_SESSION session,
        DeviceGroup_Protocol_t *msg
    )
{
    assert(session && msg && msg->payload.present != DeviceGroup_Protocol__payload_PR_NOTHING);
    if (!(session && msg && msg->payload.present != DeviceGroup_Protocol__payload_PR_NOTHING))
        return PEP_ILLEGAL_VALUE;

    void *extra = NULL;
    Identity partner = NULL;
    DeviceState_event event = DeviceState_event_NONE;

    switch (msg->payload.present) {
        case DeviceGroup_Protocol__payload_PR_beacon:
            partner = Identity_to_Struct(&msg->header.me, NULL);
            if (!partner)
                return PEP_OUT_OF_MEMORY;
            event = Beacon;
            break;

        case DeviceGroup_Protocol__payload_PR_handshakeRequest:
            partner = Identity_to_Struct(
                    &msg->header.me, NULL);
            if (!partner)
                return PEP_OUT_OF_MEMORY;
            event = HandshakeRequest;
            break;

        case DeviceGroup_Protocol__payload_PR_groupKeys:
            partner = Identity_to_Struct(&msg->header.me,
                    NULL);
            if (!partner)
                return PEP_OUT_OF_MEMORY;
            identity_list *group_keys = IdentityList_to_identity_list(
                    &msg->payload.choice.groupKeys.ownIdentities, NULL);
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

    bool found = false;

    for (bloblist_t *bl = src->attachments; bl && bl->value; bl = bl->next) {
        if (bl->mime_type && strcasecmp(bl->mime_type, "application/pEp") == 0
                && bl->size) {
            DeviceGroup_Protocol_t *msg;
            uper_decode_complete(NULL, &asn_DEF_DeviceGroup_Protocol,
                    (void **) &msg, bl->value, bl->size);
            if (msg) {
                found = true;
                PEP_STATUS status = session->inject_sync_msg(msg, session->sync_obj);
                ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                if (status != PEP_STATUS_OK)
                    return status;
            }
        }
    }

    if (found) {
        for (stringpair_list_t *spl = src->opt_fields ; spl && spl->value ;
                spl = spl->next) {
            if (spl->value->key &&
                    strcasecmp(spl->value->key, "pEp-auto-consume") == 0) {
                if (spl->value->value &&
                        strcasecmp(spl->value->value, "yes") == 0)
                    return PEP_MESSAGE_CONSUMED;
            }
        }
    }

    return PEP_STATUS_OK;
}

DeviceGroup_Protocol_t *new_DeviceGroup_Protocol_msg(DeviceGroup_Protocol__payload_PR type)
{
    DeviceGroup_Protocol_t *msg = (DeviceGroup_Protocol_t *)
            calloc(1, sizeof(HandshakeRequest_t));
    assert(msg);
    if (!msg)
        return NULL;
    msg->payload.present = type;
    return msg;
}

void free_DeviceGroup_Protocol_msg(DeviceGroup_Protocol_t *msg)
{
    ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
}

PEP_STATUS unicast_msg(
        PEP_SESSION session,
        Identity partner,
        DeviceState_state state,
        DeviceGroup_Protocol_t *msg
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    char *payload = NULL;
    message *_message = NULL;
    pEp_identity *me = NULL;

    assert(session && partner && state && msg);
    if (!(session && partner && state && msg))
        return PEP_ILLEGAL_VALUE;

    assert(session->messageToSend);
    if (!session->messageToSend) {
        status = PEP_SEND_FUNCTION_NOT_REGISTERED;
        goto error;
    }

    int32_t seq;
    status = sequence_value(session, "DeviceGroup", &seq);
    if (status != PEP_STATUS_OK)
        goto error;
    msg->header.sequence = (long) seq;

    bool devicegroup = storedGroupKeys(session);
    if (devicegroup) { // default is FALSE
        BOOLEAN_t *dg = malloc(sizeof(BOOLEAN_t));
        assert(dg);
        if (!dg)
            goto enomem;

        *dg = 1;
        msg->header.devicegroup = dg;
    }

    msg->header.state = (long) state;

    status = get_identity(session, partner->address, PEP_OWN_USERID, &me);
    if (status != PEP_STATUS_OK)
        goto error;
    if (Identity_from_Struct(me, &msg->header.me) == NULL)
        goto enomem;

    if (asn_check_constraints(&asn_DEF_DeviceGroup_Protocol, msg, NULL, NULL)) {
        status = PEP_CONTRAINTS_VIOLATED;
        goto error;
    }

    ssize_t size = uper_encode_to_new_buffer(&asn_DEF_DeviceGroup_Protocol,
            NULL, msg, (void **) &payload);
    if (size == -1) {
        status = PEP_CANNOT_ENCODE;
        goto error;
    }

    status = prepare_message(me, partner, payload, size, &_message);
    if (status != PEP_STATUS_OK)
        goto error;
    payload = NULL;

    free_identity(me);
    me = NULL;

    status = session->messageToSend(session->sync_obj, _message);

    free_identity(partner);
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    free(payload);
    free_message(_message);
    free_identity(me);
    free_identity(partner);
    return status;
}

PEP_STATUS multicast_self_msg(
        PEP_SESSION session,
        DeviceState_state state,
        DeviceGroup_Protocol_t *msg
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session && state && msg);
    if (!(session && state && msg))
        return PEP_ILLEGAL_VALUE;

    identity_list *own_identities = NULL;
    status = own_identities_retrieve(session, &own_identities);
    if (status != PEP_STATUS_OK)
        return status;

    for (identity_list *_i = own_identities; _i && _i->ident; _i = _i->next) {
        pEp_identity *me = _i->ident;

        status = myself(session, me);
        if (status == PEP_OUT_OF_MEMORY)
            goto enomem;
        if (status != PEP_STATUS_OK)
            continue;
     
        // FIXME: no deep copy for multicast supported yet
        DeviceGroup_Protocol_t *_msg = malloc(sizeof(DeviceGroup_Protocol_t));
        assert(_msg);
        if (_msg == NULL)
            goto enomem;
        memcpy(_msg, msg, sizeof(DeviceGroup_Protocol_t));
        status = unicast_msg(session, me, state, _msg);
        free_DeviceGroup_Protocol_msg(_msg);
    }

    free_identity_list(own_identities);
    return PEP_STATUS_OK;

enomem:
    free_identity_list(own_identities);
    return PEP_OUT_OF_MEMORY;
}

