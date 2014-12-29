#include "pEp_internal.h"

#include <memory.h>
#include <assert.h>

PEP_STATUS init_transport_system(PEP_SESSION session)
{
    assert(session);

    pEpSession *_session = (pEpSession *) session;
    PEP_transport_t* transports = _session->transports;

    assert(PEP_trans__count == 1);
    memset(transports, 0, sizeof(PEP_transport_t) * PEP_trans__count);

    transports[0].id = PEP_trans_auto;

    return PEP_STATUS_OK;
}

void release_transport_system(PEP_SESSION session)
{
    assert(session);
    // nothing yet
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

identity_list *identity_list_dup(const identity_list *src)
{
    assert(src);

    identity_list *id_list = new_identity_list(src->ident);
    assert(id_list);
    if (id_list == NULL)
        return NULL;

    if (src->next) {
        id_list->next = identity_list_dup(src->next);
        if (id_list->next == NULL) {
            free_identity_list(id_list);
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
    assert(ident);

    if (id_list == NULL)
        return new_identity_list(ident);

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

bloblist_t *new_bloblist(char *blob, size_t size)
{
    bloblist_t * bloblist = calloc(1, sizeof(bloblist_t));
    if (bloblist == NULL)
        return NULL;
    bloblist->data_ref = blob;
    bloblist->size = size;
    return bloblist;
}

bloblist_t *bloblist_dup(const bloblist_t *src)
{
    assert(src);

    if (src) {
        bloblist_t * dst = new_bloblist(src->data_ref, src->size);
        if (dst == NULL)
            return NULL;
        dst->next = bloblist_dup(src->next);
        return dst;
    }
    else
        return NULL;
}

void free_bloblist(bloblist_t *bloblist)
{
    if (bloblist && bloblist->next)
        free_bloblist(bloblist->next);
    free(bloblist);
}

bloblist_t *bloblist_add(bloblist_t *bloblist, char *blob, size_t size)
{
    assert(blob);

    if (bloblist == NULL)
        return new_bloblist(blob, size);

    if (bloblist->data_ref == NULL) {
        bloblist->data_ref = blob;
        bloblist->size = size;
        return bloblist;
    }

    if (bloblist->next == NULL) {
        bloblist->next = new_bloblist(blob, size);
        return bloblist->next;
    }

    return bloblist_add(bloblist->next, blob, size);
}

message *new_message(
        PEP_msg_direction dir,
        const pEp_identity *from,
        const identity_list *to,
        const char *shortmsg
    )
{
    message *msg = calloc(1, sizeof(message));
    assert(msg);
    if (msg == NULL)
        return NULL;

    if (msg->shortmsg) {
        msg->shortmsg = strdup(shortmsg);
        assert(msg->shortmsg);
        if (msg->shortmsg == NULL) {
            free(msg);
            return NULL;
        }
        msg->shortmsg_size = strlen(msg->shortmsg);
    }

    msg->dir = dir;

    msg->from = identity_dup(from);
    assert(msg->from);
    if (msg->from == NULL) {
        free_message(msg);
        return NULL;
    }

    msg->to = identity_list_dup(to);
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
    free_bloblist(msg->attachments);
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
    assert(msg);

    if (msg_list == NULL)
        return new_message_ref_list(msg);

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

