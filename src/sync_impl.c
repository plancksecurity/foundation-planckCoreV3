// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "platform.h"

// it seems pEp_internal.h needs to be the first pEp include due to the 
// #define for the dllimport / dllexport DYNAMIC_API stuff.
#include "pEp_internal.h"

#include "../asn.1/DeviceGroup-Protocol.h"
#include "sync_impl.h"
#include "keymanagement.h"
#include "message_api.h"
#include "map_asn1.h"
#include "baseprotocol.h"

#define SYNC_VERSION_MAJOR 1
#define SYNC_VERSION_MINOR 0

#define SYNC_INHIBIT_TIME (60*10)
#define SYNC_MSG_EXPIRE_TIME (60 * 10)

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
        sync_msg_t *sync_msg,
        time_t *timeout
    )
{
    PEP_STATUS status;
    void *extra = NULL;
    Identity partner = NULL;
    DeviceState_event event = DeviceState_event_NONE;
    assert(session && sync_msg);
    if (!(session && sync_msg))
        return PEP_ILLEGAL_VALUE;

    bool msgIsFromGroup = false;
    if(sync_msg->is_a_message){
        DeviceGroup_Protocol_t *msg = sync_msg->u.message;
        assert(msg && msg->payload.present != DeviceGroup_Protocol__payload_PR_NOTHING);
        if (!(msg && msg->payload.present != DeviceGroup_Protocol__payload_PR_NOTHING)){
            status = PEP_OUT_OF_MEMORY;
            goto error;
        }

        msgIsFromGroup = msg->header.devicegroup;

        switch (msg->payload.present) {
            case DeviceGroup_Protocol__payload_PR_beacon:
                event = Beacon;
                break;

            case DeviceGroup_Protocol__payload_PR_handshakeRequest:
                event = HandshakeRequest;
                break;

            case DeviceGroup_Protocol__payload_PR_updateRequest:
                event = UpdateRequest;
                break;

            case DeviceGroup_Protocol__payload_PR_groupKeys:
            case DeviceGroup_Protocol__payload_PR_groupUpdate:
            {
                identity_list *group_keys = IdentityList_to_identity_list(
                        msg->payload.present == 
                          DeviceGroup_Protocol__payload_PR_groupKeys ?
                            &msg->payload.choice.groupKeys.ownIdentities :
                            &msg->payload.choice.groupUpdate.ownIdentities,
                        NULL);
                if (!group_keys) {
                    status = PEP_OUT_OF_MEMORY;
                    ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                    goto error;
                }
                extra = (void *) group_keys;
                event = msg->payload.present == 
                          DeviceGroup_Protocol__payload_PR_groupKeys ?
                            GroupKeys : GroupUpdate;
                break;
            }

            default:
                status = PEP_SYNC_ILLEGAL_MESSAGE;
                ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                goto error;
        }

        partner = Identity_to_Struct(&msg->header.me, NULL);
        if (!partner){
            status = PEP_OUT_OF_MEMORY;
            ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
            goto error;
        }
    }
    else{
        partner = sync_msg->u.event.partner;
        extra = sync_msg->u.event.extra;
        event = sync_msg->u.event.event;
    }

    // Event inhibition, to limit mailbox and prevent cycles
    time_t *last = NULL;
    switch(event){
        case CannotDecrypt:
            last = &session->LastCannotDecrypt;
            break;

        case UpdateRequest:
            last = &session->LastUpdateRequest;
            break;

        default:
            break;
    }
    time_t now = time(NULL);
    if(last != NULL){
        if(*last != 0 && (*last + SYNC_INHIBIT_TIME) > now ){
            free_identity(partner);
            status = PEP_STATEMACHINE_INHIBITED_EVENT;
            goto error;
        }
        *last = now;
    }

    // partner identity must be explicitely added DB to later
    // be able to communicate securely with it.
    if(partner){
        // protect virtual user IDs 
        if((strncmp("TOFU_", partner->user_id, 6) == 0 &&
           strlen(partner->user_id) == strlen(partner->address) + 6 &&
           strcmp(partner->user_id + 6, partner->address)) ||
        // protect own ID 
           (strcmp(PEP_OWN_USERID, partner->user_id) == 0)){
            status = PEP_SYNC_ILLEGAL_MESSAGE;
            goto error;
        }

        // partner IDs are UUIDs bound to session lifespan
        // and therefore partner identities are not supposed
        // to mutate over time, but just not be used anymore.
        // It should then be safe to accept given identity if not 
        // already pre-existing
        pEp_identity *stored_identity = NULL;
        status = get_identity(session,
                              partner->address,
                              partner->user_id,
                              &stored_identity);

        if (!stored_identity) {
            // make a safe copy of partner, with no flags or comm_type
            pEp_identity *tmpident = new_identity(partner->address,
                                                  partner->fpr,
                                                  partner->user_id,
                                                  partner->username);
            if (tmpident == NULL){
                status = PEP_OUT_OF_MEMORY;
                goto error;
            }

            // finaly add partner to DB
            status = set_identity(session, tmpident);
            assert(status == PEP_STATUS_OK);
            if(status == PEP_STATUS_OK && msgIsFromGroup)
                status = set_identity_flags(session, tmpident, PEP_idf_devicegroup);
            free_identity(tmpident);
            assert(status == PEP_STATUS_OK);
            if (status != PEP_STATUS_OK) {
                goto error;
            }
        }
        else if (status == PEP_STATUS_OK) {
            free_identity(stored_identity);
        } 
        else
            goto error;
    }

    status = fsm_DeviceState_inject(session, event, partner, extra, timeout);

    free_identity(partner);

error:
    free(sync_msg);

    return status;
}

// TODO: DYNAMIC_API was here, but broke the windows build. 
// We need to check whether it belongs here or it's a bug.
/* DYNAMIC_API */ void free_sync_msg(sync_msg_t *sync_msg)
{
    if (!sync_msg)
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

    bool consume = false;
    bool discard = false;
    bool force_keep_msg = false;

    for (bloblist_t *bl = src->attachments; bl && bl->value; bl = bl->next) {
        if (bl->mime_type && strcasecmp(bl->mime_type, "application/pEp.sync") == 0
                && bl->size) {
            DeviceGroup_Protocol_t *msg = NULL;
            uper_decode_complete(NULL, &asn_DEF_DeviceGroup_Protocol, (void **)
                    &msg, bl->value, bl->size);

            if (msg) {
                PEP_STATUS status = PEP_STATUS_OK;

                char *user_id = strndup((char *) msg->header.me.user_id->buf,
                        msg->header.me.user_id->size);
                assert(user_id);
                if (!user_id) {
                    ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                    return PEP_OUT_OF_MEMORY;
                }

                // detect and mitigate address spoofing
                Identity check_me = NULL;
                const char* null_terminated_address = 
                    strndup((char *) msg->header.me.address->buf,
                            msg->header.me.address->size);

                status = get_identity(session, 
                                      null_terminated_address, 
                                      PEP_OWN_USERID, 
                                      &check_me);

                if (status == PEP_OUT_OF_MEMORY)
                    goto free_all;

                free_identity(check_me);

                bool not_own_address = status != PEP_STATUS_OK;
                status = PEP_STATUS_OK;

                if (not_own_address || 
                    strncmp(src->from->address,
                            (char *) msg->header.me.address->buf,
                            msg->header.me.address->size) != 0 ||
                    strncmp(src->to->ident->address,
                            (char *) msg->header.me.address->buf,
                            msg->header.me.address->size) != 0) {
                    consume = true;
                    goto free_all;
                }

                // if encrypted, ensure that header.me.fpr match signer's fpr
                if (rating >= PEP_rating_reliable && (
                        !keylist ||
                        !_same_fpr((char *) msg->header.me.fpr.buf,
                                   msg->header.me.fpr.size,
                                   keylist->value,
                                   strlen(keylist->value)))) {
                    consume = true;
                    goto free_all;
                }

                // check message expiry 
                if(src->recv) {
                    time_t expiry = timegm(src->recv) + SYNC_MSG_EXPIRE_TIME;
                    time_t now = time(NULL);
                    if(expiry != 0 && now != 0 && expiry < now){
                        consume = true;
                        goto free_all;
                    }
                }

                int32_t value = (int32_t) msg->header.sequence;
                status = sequence_value(session, (char *) user_id,
                        &value);

                if (status == PEP_STATUS_OK) {
                    switch (msg->payload.present) {
                        // HandshakeRequest needs encryption
                        case DeviceGroup_Protocol__payload_PR_handshakeRequest:
                            if (rating < PEP_rating_reliable ||
                                strncmp(session->sync_uuid,
                                        (const char *)msg->payload.choice.handshakeRequest.partner.user_id->buf,
                                        msg->payload.choice.handshakeRequest.partner.user_id->size) != 0){
                                discard = true;
                                goto free_all;
                            }
                            
                            break;
                        // accepting GroupKeys needs encryption and trust of peer device
                        case DeviceGroup_Protocol__payload_PR_groupKeys:
                        {
                            if (!keylist || rating < PEP_rating_reliable ||
                                // message is only consumed by instance it is addressed to
                                (strncmp(session->sync_uuid,
                                        (const char *)msg->payload.choice.groupKeys.partner.user_id->buf,
                                        msg->payload.choice.groupKeys.partner.user_id->size) != 0)){
                                discard = true;
                                goto free_all;
                            }

                            // check trust of identity using user_id given in msg.header.me
                            // to exacly match identity of device, the one trusted in
                            // case of accepted handshake
                            pEp_identity *_from = new_identity(NULL, 
                                                               keylist->value,
                                                               user_id,
                                                               NULL);
                            if (_from == NULL){
                                status = PEP_OUT_OF_MEMORY;
                                goto free_all;
                            }
                            status = get_trust(session, _from);
                            if (status != PEP_STATUS_OK || _from->comm_type < PEP_ct_strong_encryption) {
                                status = PEP_STATUS_OK;
                                free_identity(_from);
                                discard = true;
                                goto free_all;
                            }
                            free_identity(_from);
                            break;
                        }
                        case DeviceGroup_Protocol__payload_PR_groupUpdate:
                        case DeviceGroup_Protocol__payload_PR_updateRequest:
                        {
                            // inject message but don't consume it, so 
                            // that other group members can also be updated
                            force_keep_msg = true;
                            
                            if (!keylist || rating < PEP_rating_reliable){
                                discard = true;
                                goto free_all;
                            }
                            // GroupUpdate and UpdateRequests come from group.
                            // check trust relation in between signer key and 
                            // own id to be sure.
                            pEp_identity *_from = new_identity(NULL, 
                                                               keylist->value,
                                                               PEP_OWN_USERID,
                                                               NULL);
                            if (_from == NULL){
                                status = PEP_OUT_OF_MEMORY;
                                goto free_all;
                            }
                            status = get_trust(session, _from);
                            if (status != PEP_STATUS_OK || _from->comm_type < PEP_ct_pEp) {
                                status = PEP_STATUS_OK;
                                free_identity(_from);
                                discard = true;
                                goto free_all;
                            }
                            free_identity(_from);
                        }
                        default:
                            break;
                    }


                    consume = true;
                    sync_msg_t *sync_msg = malloc(sizeof(sync_msg_t));
                    if(sync_msg == NULL){
                        status = PEP_OUT_OF_MEMORY;
                        goto free_all;
                    }
                    sync_msg->is_a_message = true;
                    sync_msg->u.message = msg;
                    status = call_inject_sync_msg(session, sync_msg);
                    if (status != PEP_STATUS_OK){
                        if (status == PEP_SYNC_NO_INJECT_CALLBACK){
                            free(sync_msg);
                        }
                        goto free_all;
                    }
                    // don't free message now that it is in the queue
                    goto free_userid;
                }
                else if (status == PEP_OWN_SEQUENCE) {
                    status = PEP_STATUS_OK;
                    discard = true;
                    goto free_all;
                }

            free_all:
                ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
            free_userid:
                free(user_id);

                if (status != PEP_STATUS_OK)
                    return status;
            }
        }
    }

    if (force_keep_msg) {
        return PEP_MESSAGE_IGNORE;
    }

    if (consume && !session->keep_sync_msg) {
        for (stringpair_list_t *spl = src->opt_fields ; spl && spl->value ;
                spl = spl->next) {
            if (spl->value->key &&
                    strcasecmp(spl->value->key, "pEp-auto-consume") == 0) {
                if (spl->value->value &&
                        strcasecmp(spl->value->value, "yes") == 0)
                    return PEP_MESSAGE_CONSUME;
            }
        }
        return PEP_MESSAGE_IGNORE;
    }

    if(discard)
        return PEP_MESSAGE_IGNORE;

    if (!session->keep_sync_msg) {
        bloblist_t *last = NULL;
        for (bloblist_t *bl = src->attachments; bl && bl->value; ) {
            if (bl->mime_type && strcasecmp(bl->mime_type, "application/pEp.sync") == 0) {
                bloblist_t *b = bl;
                bl = bl->next;
                if (!last)
                    src->attachments = bl;
                else
                    last->next = bl;
                free(b->mime_type);
                free(b->filename);
                free(b->value);
                free(b);
            }
            else {
                last = bl;
                bl = bl->next;
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


#ifndef NDEBUG
static int _append(const void *buffer, size_t size, void *appkey)
{
    char **dest_ptr = (char **)appkey;
    size_t osize = strlen(*dest_ptr);
    size_t nsize = size + osize;
    *dest_ptr = realloc(*dest_ptr, nsize + 1);
    if(*dest_ptr == NULL) return -1;
    memcpy(*dest_ptr + osize, buffer, size);
    (*dest_ptr)[nsize] = '\0';
    return 0;
}
#endif

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

    status = sequence_value(session, session->sync_uuid, &seq);
    if (status != PEP_OWN_SEQUENCE && status != PEP_STATUS_OK)
        goto error;

    msg->header.sequence = (long) seq;

    _me = identity_dup(me);
    if (!_me)
        goto enomem;

    free(_me->user_id);
    _me->user_id = strndup(session->sync_uuid, 36);
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

#ifndef NDEBUG
    asn_enc_rval_t er;
    er = xer_encode(&asn_DEF_DeviceGroup_Protocol, msg, 
                    XER_F_BASIC, _append, &_message->longmsg);
    if(er.encoded == -1)
        goto error;
#endif

    if (encrypted) {
        if (msg->payload.present == DeviceGroup_Protocol__payload_PR_groupKeys || 
            msg->payload.present == DeviceGroup_Protocol__payload_PR_groupUpdate) {
            PEP_rating rating = PEP_rating_undefined;
            status = outgoing_message_rating(session, _message, &rating);
            if (status != PEP_STATUS_OK)
                goto error;
            if (rating < PEP_rating_trusted) {
                status = PEP_SYNC_NO_TRUST;
                goto error;
            }
            
            stringlist_t *keylist = NULL;
            status = _own_keys_retrieve(session, &keylist, PEP_idf_not_for_sync);
            if (status != PEP_STATUS_OK)
                goto error;

            for (stringlist_t *_keylist=keylist; _keylist!=NULL; _keylist=_keylist->next) {
                char *fpr = _keylist->value;
                static char filename[MAX_LINELENGTH];
                int result = snprintf(filename, MAX_LINELENGTH, "%s-sec.asc", fpr);
                if (result < 0)
                    goto enomem;
                char *key = NULL;
                size_t size = 0;
                status = export_secrect_key(session, fpr, &key, &size);
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
    status = _own_identities_retrieve(session, &own_identities, PEP_idf_not_for_sync);
    if (status != PEP_STATUS_OK)
        return status;

    for (identity_list *_i = own_identities; _i && _i->ident; _i = _i->next) {
        pEp_identity *me = _i->ident;

        // FIXME: no deep copy for multicast supported yet
        // DeviceGroup_Protocol_t *_msg = malloc(sizeof(DeviceGroup_Protocol_t));
        // assert(_msg);
        // if (_msg == NULL){
        //     status = PEP_OUT_OF_MEMORY;
        //     goto error;
        // }
        // memcpy(_msg, msg, sizeof(DeviceGroup_Protocol_t));
        status = unicast_msg(session, me, state, msg, encrypted);
        //status = unicast_msg(session, me, state, _msg, encrypted);
        //free_DeviceGroup_Protocol_msg(_msg);
    }

    free_identity_list(own_identities);
    return PEP_STATUS_OK;

// error:
//     free_identity_list(own_identities);
//     return status;
}

