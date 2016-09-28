#include "../asn.1/DeviceGroup-Protocol.h"
#include "sync_impl.h"
#include "pEp_internal.h"
#include "keymanagement.h"
#include "message_api.h"
#include "map_asn1.h"
#include "baseprotocol.h"

#define SYNC_VERSION_MAJOR 1
#define SYNC_VERSION_MINOR 0

struct _sync_msg_t {
    bool is_a_message;
    union {
        DeviceGroup_Protocol_t *message;
        struct {
            DeviceState_event event;
            Identity partner;
            void *extra;
        } event;
    } u;
};

PEP_STATUS receive_sync_msg(
        PEP_SESSION session,
        sync_msg_t *sync_msg
    )
{
    PEP_STATUS status;
    void *extra = NULL;
    Identity partner = NULL;
    DeviceState_event event = DeviceState_event_NONE;
    assert(session && sync_msg);
    if (!(session && sync_msg))
        return PEP_ILLEGAL_VALUE;

    if(sync_msg->is_a_message){
        DeviceGroup_Protocol_t *msg = sync_msg->u.message;
        assert(msg && msg->payload.present != DeviceGroup_Protocol__payload_PR_NOTHING);
        if (!(msg && msg->payload.present != DeviceGroup_Protocol__payload_PR_NOTHING)){
            status = PEP_OUT_OF_MEMORY;
            goto error;
        }

        switch (msg->payload.present) {
            case DeviceGroup_Protocol__payload_PR_beacon:
                partner = Identity_to_Struct(&msg->header.me, NULL);
                if (!partner){
                    status = PEP_OUT_OF_MEMORY;
                    ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                    goto error;
                }
                event = Beacon;
                break;

            case DeviceGroup_Protocol__payload_PR_handshakeRequest:
                partner = Identity_to_Struct(&msg->header.me, NULL);
                if (!partner){
                    status = PEP_OUT_OF_MEMORY;
                    ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                    goto error;
                }
                event = HandshakeRequest;
                break;

            case DeviceGroup_Protocol__payload_PR_groupKeys:
                partner = Identity_to_Struct(&msg->header.me, NULL);
                if (!partner){
                    status = PEP_OUT_OF_MEMORY;
                    ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                    goto error;
                }
                identity_list *group_keys = IdentityList_to_identity_list(
                        &msg->payload.choice.groupKeys.ownIdentities, NULL);
                if (!group_keys) {
                    free_identity(partner);
                    status = PEP_OUT_OF_MEMORY;
                    ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                    goto error;
                }
                extra = (void *) group_keys;
                event = GroupKeys;
                break;

            default:
                status = PEP_SYNC_ILLEGAL_MESSAGE;
                ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                goto error;
        }
    }
    else{
        partner = sync_msg->u.event.partner;
        extra = sync_msg->u.event.extra;
        event = sync_msg->u.event.event;
    }

    status = fsm_DeviceState_inject(session, event, partner, extra);

    free_identity(partner);

error:
    free(sync_msg);

    return status;
}

DYNAMIC_API void free_sync_msg(sync_msg_t *sync_msg)
{
    assert(sync_msg);
    if (!(sync_msg))
        return;

    if(sync_msg->is_a_message){
        DeviceGroup_Protocol_t *msg = sync_msg->u.message;
        assert(msg);
        if (!(msg))
            return;

        ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
    }
    else{
        Identity partner = NULL;
        partner = sync_msg->u.event.partner;
        if(partner != NULL)
            free_identity(partner);
    }

    free(sync_msg);

    return;
}

// from sync.c
int call_inject_sync_msg(PEP_SESSION session, void *msg);

PEP_STATUS inject_DeviceState_event(
    PEP_SESSION session, 
    DeviceState_event event,
    Identity partner,
    void *extra)
{
    PEP_STATUS status;

    assert(session);
    if (!(session))
        return PEP_ILLEGAL_VALUE;

    sync_msg_t *sync_msg = malloc(sizeof(sync_msg_t));
    if(sync_msg == NULL)
        return PEP_OUT_OF_MEMORY;

    sync_msg->is_a_message = false;
    sync_msg->u.event.partner = partner;
    sync_msg->u.event.extra = extra;
    sync_msg->u.event.event = event;

    status = call_inject_sync_msg(session, sync_msg);
    if (status == PEP_SYNC_NO_INJECT_CALLBACK){
        free(sync_msg);
    }

    return status;
}

PEP_STATUS receive_DeviceState_msg(
    PEP_SESSION session, 
    message *src, 
    PEP_rating rating, 
    stringlist_t *keylist)
{
    assert(session && src);
    if (!(session && src))
        return PEP_ILLEGAL_VALUE;

    bool found = false;
    
    bloblist_t *last = NULL;
    for (bloblist_t *bl = src->attachments; bl && bl->value; bl = bl->next) {
        if (bl->mime_type && strcasecmp(bl->mime_type, "application/pEp.sync") == 0
                && bl->size) {
            DeviceGroup_Protocol_t *msg = NULL;
            uper_decode_complete(NULL, &asn_DEF_DeviceGroup_Protocol, (void **)
                    &msg, bl->value, bl->size);
            if (msg) {

                int32_t value = (int32_t) msg->header.sequence;
                char *user_id = strndup((char *) msg->header.me.user_id->buf,
                        msg->header.me.user_id->size);
                assert(user_id);
                if (!user_id) {
                    ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                    return PEP_OUT_OF_MEMORY;
                }

                switch (msg->payload.present) {
                    // HandshakeRequest needs encryption
                    case DeviceGroup_Protocol__payload_PR_handshakeRequest:
                        if (rating < PEP_rating_reliable ||
                            strncmp(sync_uuid,
                                    (const char *)msg->payload.choice.handshakeRequest.partner.user_id->buf,
                                    msg->payload.choice.handshakeRequest.partner.user_id->size) != 0){
                            ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                            free(user_id);
                            return PEP_MESSAGE_DISCARDED;
                        }
                        break;
                    // accepting GroupKeys needs encryption and trust
                    case DeviceGroup_Protocol__payload_PR_groupKeys:
                        if (!keylist || rating < PEP_rating_reliable ||
                            strncmp(sync_uuid,
                                    (const char *)msg->payload.choice.groupKeys.partner.user_id->buf,
                                    msg->payload.choice.groupKeys.partner.user_id->size) != 0){
                            ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                            free(user_id);
                            return PEP_MESSAGE_DISCARDED;
                        }

                        // check trust of identity with the right user_id
                        pEp_identity *_from = new_identity(src->from->address, 
                                                           keylist->value,
                                                           user_id,
                                                           src->from->username);
                        if (_from == NULL){
                            free(user_id);
                            ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                            return PEP_OUT_OF_MEMORY;
                        }
                        PEP_rating this_user_id_rating = PEP_rating_undefined;
                        identity_rating(session, _from, &this_user_id_rating);
                        free_identity(_from);

                        if (this_user_id_rating < PEP_rating_trusted ) {
                            ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                            free(user_id);
                            return PEP_MESSAGE_DISCARDED;
                        }
                        break;
                    default:
                        break;
                }


                PEP_STATUS status = sequence_value(session, (char *) user_id,
                        &value);

                if (status == PEP_STATUS_OK) {
                    found = true;
                    sync_msg_t *sync_msg = malloc(sizeof(sync_msg_t));
                    if(sync_msg == NULL){
                        ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                        return PEP_OUT_OF_MEMORY;
                    }
                    sync_msg->is_a_message = true;
                    sync_msg->u.message = msg;
                    status = call_inject_sync_msg(session, sync_msg);
                    if (status != PEP_STATUS_OK){
                        ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                        if (status == PEP_SYNC_NO_INJECT_CALLBACK){
                            free(sync_msg);
                        }
                        return status;
                    }
                }
                else if (status == PEP_OWN_SEQUENCE) {
                    ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                    return PEP_MESSAGE_DISCARDED;
                }
            }

            if (!session->keep_sync_msg) {
                bloblist_t *blob = bl;
                if (last)
                    last->next = bl->next;
                else
                    src->attachments = bl->next;

                blob->next = NULL;
                free_bloblist(blob);
            }
            else {
                last = bl;
            }
        }
        else {
            last = bl;
        }
    }

    if (found && !session->keep_sync_msg) {
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
            calloc(1, sizeof(DeviceGroup_Protocol_t));
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
        const Identity partner,
        DeviceState_state state,
        DeviceGroup_Protocol_t *msg,
        bool encrypted
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    char *payload = NULL;
    message *_message = NULL;
    pEp_identity *me = NULL;
    pEp_identity *_me = NULL;

    assert(session && partner && state && msg);
    if (!(session && partner && state && msg))
        return PEP_ILLEGAL_VALUE;

    assert(session->messageToSend);
    if (!session->messageToSend) {
        status = PEP_SEND_FUNCTION_NOT_REGISTERED;
        goto error;
    }

    msg->header.version.major = SYNC_VERSION_MAJOR;
    msg->header.version.minor = SYNC_VERSION_MINOR;

    status = get_identity(session, partner->address, PEP_OWN_USERID, &me);
    if (status != PEP_STATUS_OK)
        goto error;
    
    int32_t seq = 0;

    status = sequence_value(session, sync_uuid, &seq);
    if (status != PEP_OWN_SEQUENCE && status != PEP_STATUS_OK)
        goto error;

    msg->header.sequence = (long) seq;

    _me = identity_dup(me);
    if (!_me)
        goto enomem;

    free(_me->user_id);
    _me->user_id = strndup(sync_uuid, 36);
    assert(_me->user_id);
    if (!_me->user_id)
        goto enomem;

    if (Identity_from_Struct(_me, &msg->header.me) == NULL)
        goto enomem;

    free_identity(_me);
    _me = NULL;

    msg->header.state = (long) state;

    bool devicegroup = storedGroupKeys(session);
    if (devicegroup)
        msg->header.devicegroup = 1;
    else
        msg->header.devicegroup = 0;

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

    if (encrypted) {
        if (msg->payload.present == DeviceGroup_Protocol__payload_PR_groupKeys) {
            PEP_rating rating = PEP_rating_undefined;
            status = outgoing_message_rating(session, _message, &rating);
            if (status != PEP_STATUS_OK)
                goto error;
            if (rating < PEP_rating_trusted) {
                status = PEP_SYNC_NO_TRUST;
                goto error;
            }
            
            IdentityList_t *list = &msg->payload.choice.groupKeys.ownIdentities;
            for (int i=0; i<list->list.count; i++) {
                Identity_t *ident = list->list.array[i];
                char *fpr = strndup((const char *)ident->fpr.buf, ident->fpr.size);
                assert(fpr);
                if (!fpr)
                    goto enomem;
                static char filename[MAX_LINELENGTH];
                int result = snprintf(filename, MAX_LINELENGTH, "%s-sec.asc", fpr);
                if (result < 0)
                    goto enomem;
                char *key = NULL;
                size_t size = 0;
                status = export_secrect_key(session, fpr, &key, &size);
                free(fpr);
                if (status != PEP_STATUS_OK)
                    goto error;
                bloblist_t *bl = bloblist_add(_message->attachments,
                        (char *) key, size, "application/pgp-keys", filename);
                if (!bl)
                    goto enomem;
                if (!_message->attachments)
                    _message->attachments = bl;
            }
        }

        message *_encrypted = NULL;
        status = encrypt_message(session, _message, NULL, &_encrypted, PEP_enc_PEP, 0);
        if (status != PEP_STATUS_OK)
            goto error;
        free_message(_message);
        _message = _encrypted;
    }
    else {
        attach_own_key(session, _message);
    }

    status = session->messageToSend(session->sync_obj, _message);
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
error:
    free_identity(_me);
    free(payload);
    free_message(_message);
    free_identity(me);
    return status;
}

PEP_STATUS multicast_self_msg(
        PEP_SESSION session,
        DeviceState_state state,
        DeviceGroup_Protocol_t *msg,
        bool encrypted
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

        // FIXME: no deep copy for multicast supported yet
        DeviceGroup_Protocol_t *_msg = malloc(sizeof(DeviceGroup_Protocol_t));
        assert(_msg);
        if (_msg == NULL)
            goto enomem;
        memcpy(_msg, msg, sizeof(DeviceGroup_Protocol_t));
        status = unicast_msg(session, me, state, _msg, encrypted);
        free_DeviceGroup_Protocol_msg(_msg);
    }

    free_identity_list(own_identities);
    return PEP_STATUS_OK;

enomem:
    free_identity_list(own_identities);
    return PEP_OUT_OF_MEMORY;
}

