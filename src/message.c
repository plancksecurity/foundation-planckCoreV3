/**
 * @file    message.c
 * @brief   implementation of the pEp message structure and functions used to represent messages and pass message 
 *          information back and forth between the engine and its customers. Includes memory management
 *          for said structs.
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#include "pEp_internal.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "message.h"

DYNAMIC_API message *new_message(
        PEP_msg_direction dir
    )
{
    message *msg = calloc(1, sizeof(message));
    assert(msg);
    if (msg == NULL)
        return NULL;

    msg->dir = dir;

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
        free_timestamp(msg->sent);
        free_timestamp(msg->recv);
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
        free(msg->_sender_fpr);
        free(msg);
    }
}

DYNAMIC_API message * message_dup(const message *src)
{
    message * msg = NULL;

    assert(src);

    msg = new_message(src->dir);
    if (msg == NULL)
        goto enomem;

    if (src->id) {
        msg->id = strdup(src->id);
        assert(msg->id);
        if (msg->id == NULL)
            goto enomem;
    }

    if (src->shortmsg) {
        msg->shortmsg = strdup(src->shortmsg);
        assert(msg->shortmsg);
        if (msg->shortmsg == NULL)
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
        msg->sent = timestamp_dup(src->sent);
        if (msg->sent == NULL)
            goto enomem;
    }

    if (src->recv) {
        msg->recv = timestamp_dup(src->recv);
        if (msg->recv == NULL)
            goto enomem;
    }

    if (src->from) {
        msg->from = identity_dup(src->from);
        if (msg->from == NULL)
            goto enomem;
    }

    if (src->recv_by) {
        msg->recv_by = identity_dup(src->recv_by);
        if (msg->recv_by == NULL)
            goto enomem;
    }

    if (src->to) {
        msg->to = identity_list_dup(src->to);
        if (msg->to == NULL)
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

    if (src->_sender_fpr) {
        msg->_sender_fpr = strdup(src->_sender_fpr);
        if (msg->_sender_fpr == NULL)
            goto enomem;
    }
    
    msg->enc_format = src->enc_format;

    return msg;

enomem:
    free_message(msg);
    return NULL;
}

DYNAMIC_API void message_transfer(message* dst, message *src)
{
    assert(dst);
    assert(src);

    dst->dir = src->dir;
    dst->rawmsg_ref = src->rawmsg_ref;
    dst->rawmsg_size = src->rawmsg_size;
    dst->refering_msg_ref = src->refering_msg_ref;
    dst->enc_format = src->enc_format;

    /* Strings */
    free(dst->id);
    free(dst->shortmsg);
    free(dst->longmsg);
    free(dst->longmsg_formatted);
    free(dst->comments);
    free(dst->_sender_fpr);
    dst->id = src->id;
    dst->shortmsg = src->shortmsg;
    dst->longmsg = src->longmsg;
    dst->longmsg_formatted = src->longmsg_formatted;
    dst->comments = src->comments;    
    dst->_sender_fpr = src->_sender_fpr;
    src->id = src->shortmsg = src->longmsg = src->longmsg_formatted = NULL;
    src->comments = src->_sender_fpr = NULL;
    
    /* bloblists */
    free_bloblist(dst->attachments);
    dst->attachments = src->attachments;
    src->attachments = NULL;
    
    /* timestamps */
    free_timestamp(dst->sent);
    free_timestamp(dst->recv);
    dst->sent = src->sent;
    dst->recv = src->recv;
    src->sent = src->recv = NULL;
    
    /* identities */
    free_identity(dst->from);
    free_identity(dst->recv_by);
    dst->from = src->from;
    dst->recv_by = src->recv_by;
    src->from = src->recv_by = NULL;
    
    /* identity lists */
    free_identity_list(dst->to);
    free_identity_list(dst->cc);
    free_identity_list(dst->bcc);
    free_identity_list(dst->reply_to);
    dst->to = src->to;
    dst->cc = src->cc;
    dst->bcc = src->bcc;
    dst->reply_to = src->reply_to;
    src->to = src->cc = src->bcc = src->reply_to = NULL;

    /* stringlists */
    free_stringlist(dst->references);
    free_stringlist(dst->keywords);
    free_stringlist(dst->in_reply_to);
    dst->references = src->references;
    dst->keywords = src->keywords;
    dst->in_reply_to = src->in_reply_to;
    src->references = src->keywords = src->in_reply_to = NULL;

    /* message ref list */
    free_message_ref_list(dst->refered_by);
    dst->refered_by = src->refered_by;
    src->refered_by = NULL;
    
    /* stringpair lists */
    free_stringpair_list(dst->opt_fields);
    dst->opt_fields = src->opt_fields;
    src->opt_fields = NULL;
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
