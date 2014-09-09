#include "pEp_internal.h"

#include <memory.h>
#include <assert.h>

PEP_STATUS init_transport_system(PEP_SESSION session)
{
    pEpSession *_session = (pEpSession *) session;
    PEP_transport_t* transports = _session->transports;

    assert(PEP_trans__count == 1);
    memset(transports, 0, sizeof(PEP_transport_t) * PEP_trans__count);

    transports[0].id = PEP_trans_auto;

    return PEP_STATUS_OK;
}

void release_transport_system(PEP_SESSION session)
{
    // nothing yet
}

pEp_identity *identity_dup(const pEp_identity *src)
{
    pEp_identity *dup = new_identity(src->address, src->fpr, src->user_id, src->username);
    assert(dup);
    if (dup == NULL)
        return NULL;
    
    dup->address_size = strlen(dup->address);
    dup->fpr_size = strlen(dup->fpr);
    dup->user_id_size = strlen(dup->user_id);
    dup->username_size = strlen(dup->username);
    dup->comm_type = src->comm_type;
    dup->lang[0] = src->lang[0];
    dup->lang[1] = src->lang[1];
    dup->lang[2] = 0;
    dup->me = src->me;
}

identity_list *new_identity_list(const pEp_identity *ident)
{
    identity_list *id_list = calloc(1, sizeof(identity_list));
    assert(id_list);
    if (id_list == NULL)
        return NULL;

    if (ident) {
        id_list->ident = identity_dup(ident);
        assert(id_list->ident);
        if (id_list->ident == NULL) {
            free(id_list);
            return NULL;
        }
    }

    return id_list;
}

void free_identity_list(identity_list *id_list)
{
    if (id_list) {
        free_identity_list(id_list->next);
        free_identity(id_list->ident);
        free(id_list);
    }
}

identity_list *identity_list_add(identity_list *id_list, const pEp_identity *ident)
{
    assert(id_list);
    assert(ident);

    if (id_list->ident == NULL) {
        id_list->ident = identity_dup(ident);
        assert(id_list->ident);
        if (id_list->ident == NULL)
            return NULL;
        else
            return id_list;
    }
    else if (id_list->next == NULL) {
        id_list->next = new_identity_list(ident);
        assert(id_list->next);
        return id_list->next;
    }
    else {
        return identity_list_add(id_list->next, ident);
    }
}

message *new_message(
        msg_direction dir,
        const pEp_identity *from,
        const pEp_identity *to,
        const char *shortmsg
    )
{
    message *msg = calloc(1, sizeof(message));
    assert(msg);
    if (msg == NULL)
        return NULL;

    msg->shortmsg = strdup(shortmsg);
    assert(msg->shortmsg);
    if (msg->shortmsg == NULL) {
        free(msg);
        return NULL;
    }
    msg->shortmsg_size = strlen(msg->shortmsg);

    msg->dir = dir;

    msg->from = identity_dup(from);
    assert(msg->from);
    if (msg->from == NULL) {
        free_message(msg);
        return NULL;
    }

    if (dir == dir_incoming) {
        msg->recv_by = identity_dup(to);
        assert(msg->recv_by);
        if (msg->recv_by == NULL) {
            free_message(msg);
            return NULL;
        }
    }

    msg->to = new_identity_list(to);
    assert(msg->to);
    if (msg->to == NULL) {
        free_message(msg);
        return NULL;
    }

    return msg;
}

void free_message(message *msg)
{
    free(msg->id);
    free(msg->shortmsg);
    free(msg->longmsg);
    free(msg->longmsg_formatted);
    free(msg->rawmsg);
    free_identity_list(msg->to);
    free_identity_list(msg->cc);
    free_identity_list(msg->bcc);
    free(msg->refering_id);
    free_message_ref_list(msg->refered_by);
    free(msg);
}

message_ref_list *new_message_ref_list(message *msg)
{
    message_ref_list *msg_list = calloc(1, sizeof(message_ref_list));
    assert(msg_list);
    if (msg_list == NULL)
        return NULL;

    msg_list->msg_ref = msg;

    return msg_list;
}

void free_message_ref_list(message_ref_list *msg_list)
{
    if (msg_list) {
        free_message_ref_list(msg_list->next);
        free(msg_list);
    }
}

message_ref_list *message_ref_list_add(message_ref_list *msg_list, message *msg)
{
    assert(msg_list);
    assert(msg);

    if (msg_list->msg_ref == NULL) {
        msg_list->msg_ref = msg;
        return msg_list;
    }
    else if (msg_list->next == NULL) {
        msg_list->next = new_message_ref_list(msg);
        assert(msg_list->next);
        return msg_list->next;
    }
    else {
        return message_ref_list_add(msg_list->next, msg);
    }
}

