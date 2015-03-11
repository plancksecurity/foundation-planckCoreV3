#include "pEp_internal.h"

#include <memory.h>
#include <assert.h>

DYNAMIC_API message *new_message(
        PEP_msg_direction dir,
        pEp_identity *from,
        identity_list *to,
        const char *shortmsg
    )
{
    message *msg = calloc(1, sizeof(message));
    assert(msg);
    if (msg == NULL)
        return NULL;

    if (shortmsg) {
        msg->shortmsg = strdup(shortmsg);
        assert(msg->shortmsg);
        if (msg->shortmsg == NULL) {
            free(msg);
            return NULL;
        }
    }

    msg->dir = dir;
    msg->from = from;
    msg->to = to;

    stringpair_t version;
    version.key = "X-pEp-Version";
    version.value = PEP_VERSION;

    msg->opt_fields = new_stringpair_list(&version);
    if (msg->opt_fields == NULL) {
        free_message(msg);
        return NULL;
    }

    return msg;
}

DYNAMIC_API void free_message(message *msg)
{
    if (msg) {
        free(msg->id);
        free(msg->shortmsg);
        free(msg->longmsg);
        free(msg->longmsg_formatted);
        free_bloblist(msg->attachments);
        free(msg->sent);
        free(msg->recv);
        free_identity(msg->from);
        free_identity_list(msg->to);
        free_identity(msg->recv_by);
        free_identity_list(msg->cc);
        free_identity_list(msg->bcc);
        free_identity_list(msg->reply_to);
        free_stringlist(msg->in_reply_to);
        free_stringlist(msg->references);
        free_stringlist(msg->keywords);
        free(msg->comments);
        free_stringpair_list(msg->opt_fields);
        free(msg);
    }
}

DYNAMIC_API message * message_dup(const message *src)
{
    message * msg = NULL;
    pEp_identity * from = NULL;
    identity_list * to = NULL;

    assert(src);

    from = identity_dup(src->from);
    if (from == NULL)
        goto enomem;

    to = identity_list_dup(src->to);
    if (to == NULL)
        goto enomem;

    msg = new_message(src->dir, from, to, src->shortmsg);
    if (msg == NULL)
        goto enomem;

    if (src->id) {
        msg->id = strdup(src->id);
        assert(msg->id);
        if (msg->id == NULL)
            goto enomem;
    }

    if (src->longmsg) {
        msg->longmsg = strdup(src->longmsg);
        assert(msg->longmsg);
        if (msg->longmsg == NULL)
            goto enomem;
    }
    
    if (src->longmsg_formatted) {
        msg->longmsg_formatted = strdup(src->longmsg_formatted);
        assert(msg->longmsg_formatted);
        if (msg->longmsg_formatted == NULL)
            goto enomem;
    }

    if (src->attachments) {
        msg->attachments = bloblist_dup(src->attachments);
        if (msg->attachments == NULL)
            goto enomem;
    }

    msg->rawmsg_ref = src->rawmsg_ref;
    msg->rawmsg_size = src->rawmsg_size;

    if (src->sent) {
        msg->sent = malloc(sizeof(timestamp));
        if (msg->sent == NULL)
            goto enomem;
        memcpy(msg->sent, src->sent, sizeof(timestamp));
    }

    if (src->recv) {
        msg->recv = malloc(sizeof(timestamp));
        if (msg->recv == NULL)
            goto enomem;
        memcpy(msg->recv, src->recv, sizeof(timestamp));
    }

    if (src->recv_by) {
        msg->recv_by = identity_dup(src->recv_by);
        if (msg->recv_by == NULL)
            goto enomem;
    }

    if (src->cc) {
        msg->cc = identity_list_dup(src->cc);
        if (msg->cc == NULL)
            goto enomem;
    }

    if (src->bcc) {
        msg->bcc = identity_list_dup(src->bcc);
        if (msg->bcc == NULL)
            goto enomem;
    }

    if (src->reply_to) {
        msg->reply_to = identity_list_dup(src->reply_to);
        if (msg->reply_to == NULL)
            goto enomem;
    }

    if (src->in_reply_to) {
        msg->in_reply_to = stringlist_dup(src->in_reply_to);
        assert(msg->in_reply_to);
        if (msg->in_reply_to == NULL)
            goto enomem;
    }

    msg->refering_msg_ref = src->refering_msg_ref;
    
    if (src->references) {
        msg->references = stringlist_dup(src->references);
        if (msg->references == NULL)
            goto enomem;
    }

    if (src->refered_by) {
        msg->refered_by = message_ref_list_dup(src->refered_by);
        if (msg->refered_by == NULL)
            goto enomem;
    }

    if (src->keywords) {
        msg->keywords = stringlist_dup(src->keywords);
        if (msg->keywords == NULL)
            goto enomem;
    }

    if (src->comments) {
        msg->comments = strdup(src->comments);
        assert(msg->comments);
        if (msg->comments == NULL)
            goto enomem;
    }

    if (src->opt_fields) {
        msg->opt_fields = stringpair_list_dup(src->opt_fields);
        if (msg->opt_fields == NULL)
            goto enomem;
    }

    msg->enc_format = src->enc_format;

    return msg;

enomem:
    if (msg) {
        free_message(msg);
    }
    else {
        free_identity(from);
        free_identity_list(to);
    }

    return NULL;
}

DYNAMIC_API message_ref_list *new_message_ref_list(message *msg)
{
    message_ref_list *msg_list = calloc(1, sizeof(message_ref_list));
    assert(msg_list);
    if (msg_list == NULL)
        return NULL;

    msg_list->msg_ref = msg;

    return msg_list;
}

DYNAMIC_API void free_message_ref_list(message_ref_list *msg_list)
{
    if (msg_list) {
        free_message_ref_list(msg_list->next);
        free(msg_list);
    }
}

DYNAMIC_API message_ref_list *message_ref_list_dup(
        const message_ref_list *src
    )
{
    message_ref_list * msg_list = NULL;

    assert(src);

    msg_list = new_message_ref_list(src->msg_ref);
    if (msg_list == NULL)
        goto enomem;

    if (src->next) {
        msg_list->next = message_ref_list_dup(src->next);
        if (msg_list->next == NULL)
            goto enomem;
    }

    return msg_list;

enomem:
    free_message_ref_list(msg_list);
    return NULL;
}

DYNAMIC_API message_ref_list *message_ref_list_add(message_ref_list *msg_list, message *msg)
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

