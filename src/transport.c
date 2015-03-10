#include "pEp_internal.h"
#include "trans_auto.h"

#include <memory.h>
#include <assert.h>

PEP_STATUS init_transport_system(PEP_SESSION session, bool in_first)
{
    static PEP_transport_t transports[PEP_trans__count];
    
    assert(session);
    session->transports = transports;

    if (in_first) {
        assert(PEP_trans__count == 1);
        memset(transports, 0, sizeof(PEP_transport_t) * PEP_trans__count);

        transports[PEP_trans_auto].id = PEP_trans_auto;
        transports[PEP_trans_auto].sendto = auto_sendto;
        transports[PEP_trans_auto].readnext = auto_readnext;
    }

    return PEP_STATUS_OK;
}

void release_transport_system(PEP_SESSION session, bool out_last)
{
    assert(session);
    // nothing yet
}

DYNAMIC_API identity_list *new_identity_list(pEp_identity *ident)
{
    identity_list *id_list = calloc(1, sizeof(identity_list));
    assert(id_list);
    if (id_list == NULL)
        return NULL;

    id_list->ident = ident;

    return id_list;
}

DYNAMIC_API identity_list *identity_list_dup(const identity_list *src)
{
    assert(src);

    identity_list *id_list = new_identity_list(identity_dup(src->ident));
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

DYNAMIC_API void free_identity_list(identity_list *id_list)
{
    if (id_list) {
        free_identity_list(id_list->next);
        free_identity(id_list->ident);
        free(id_list);
    }
}

DYNAMIC_API identity_list *identity_list_add(identity_list *id_list, pEp_identity *ident)
{
    assert(ident);

    if (id_list == NULL)
        return new_identity_list(ident);

    if (id_list->ident == NULL) {
        id_list->ident = ident;
        return id_list;
    }
    else if (id_list->next == NULL) {
        id_list->next = new_identity_list(ident);
        return id_list->next;
    }
    else {
        return identity_list_add(id_list->next, ident);
    }
}

DYNAMIC_API bloblist_t *new_bloblist(char *blob, size_t size, const char *mime_type,
        const char *file_name)
{
    bloblist_t * bloblist = calloc(1, sizeof(bloblist_t));
    assert(bloblist);
    if (bloblist == NULL)
        return NULL;

    if (mime_type) {
        bloblist->mime_type = strdup(mime_type);
        if (bloblist->mime_type == NULL) {
            free(bloblist);
            return NULL;
        }
    }

    if (file_name) {
        bloblist->file_name = strdup(file_name);
        if (bloblist->file_name == NULL) {
            free(bloblist->mime_type);
            free(bloblist);
            return NULL;
        }
    }

    bloblist->data = blob;
    bloblist->size = size;

    return bloblist;
}

DYNAMIC_API void free_bloblist(bloblist_t *bloblist)
{
    if (bloblist) {
        if (bloblist->next)
            free_bloblist(bloblist->next);
        free(bloblist->data);
        free(bloblist->mime_type);
        free(bloblist->file_name);
        free(bloblist);
    }
}

DYNAMIC_API bloblist_t *bloblist_dup(const bloblist_t *src)
{
    bloblist_t *bloblist = NULL;

    assert(src);

    bloblist = new_bloblist(src->data, src->size, src->mime_type, src->file_name);
    if (bloblist == NULL)
        goto enomem;

    if (src->next) {
        bloblist->next = bloblist_dup(src->next);
        if (bloblist->next == NULL)
            goto enomem;
    }

    return bloblist;

enomem:
    free_bloblist(bloblist);
    return NULL;
}

DYNAMIC_API bloblist_t *bloblist_add(bloblist_t *bloblist, char *blob, size_t size,
        const char *mime_type, const char *file_name)
{
    assert(blob);

    if (bloblist == NULL)
        return new_bloblist(blob, size, mime_type, file_name);

    if (bloblist->data == NULL) {
        if (mime_type) {
            bloblist->mime_type = strdup(mime_type);
            if (bloblist->mime_type == NULL) {
                free(bloblist);
                return NULL;
            }
        }
        if (file_name) {
            bloblist->file_name = strdup(file_name);
            if (bloblist->file_name == NULL) {
                free(bloblist->mime_type);
                free(bloblist);
                return NULL;
            }
        }
        bloblist->data = blob;
        bloblist->size = size;
        return bloblist;
    }

    if (bloblist->next == NULL) {
        bloblist->next = new_bloblist(blob, size, mime_type, file_name);
        return bloblist->next;
    }

    return bloblist_add(bloblist->next, blob, size, mime_type, file_name);
}

DYNAMIC_API stringpair_t * new_stringpair(const char *key, const char *value)
{
    stringpair_t *pair = NULL;

    assert(key);
    assert(value),

    pair = calloc(1, sizeof(stringpair_t));
    assert(pair);
    if (pair == NULL)
        goto enomem;

    pair->key = strdup(key);
    assert(pair->key);
    if (pair->key == NULL)
        goto enomem;

    pair->value = strdup(value);
    assert(pair->value);
    if (pair->value == NULL)
        goto enomem;

    return pair;

enomem:
    free_stringpair(pair);
    return NULL;
}

DYNAMIC_API void free_stringpair(stringpair_t * pair)
{
    if (pair) {
        free(pair->key);
        free(pair->value);
        free(pair);
    }
}

DYNAMIC_API stringpair_t * stringpair_dup(const stringpair_t *src)
{
    assert(src);
    return new_stringpair(src->key, src->value);
}

DYNAMIC_API stringpair_map_t * new_stringpair_map(const stringpair_t *pair)
{
    stringpair_map_t *map = NULL;

    map = calloc(1, sizeof(stringpair_map_t));
    assert(map);
    if (map == NULL)
        goto enomem;

    if (pair) {
        map->pair = stringpair_dup(pair);
        if (map->pair == NULL)
            goto enomem;
    }

    return map;

enomem:
    free_stringpair_map(map);
    return NULL;
}

DYNAMIC_API void free_stringpair_map(stringpair_map_t *map)
{
    if (map) {
        free_stringpair_map(map->left);
        free_stringpair_map(map->right);
        free_stringpair(map->pair);
        free(map);
    }
}

static stringpair_map_t * _stringpair_map_dup(
        const stringpair_map_t *src,
        stringpair_map_t *parent
    )
{
    stringpair_map_t *map = NULL;   

    assert(src);

    map = new_stringpair_map(src->pair);
    if (map == NULL)
        goto enomem;

    map->color = src->color;

    if (src->left) {
        map->left = _stringpair_map_dup(src->left, map);
        if (map->left == NULL)
            goto enomem;
    }

    if (src->right) {
        map->right = _stringpair_map_dup(src->right, map);
        if (map->right == NULL)
            goto enomem;
    }

    map->parent_ref = parent;

    return map;

enomem:
    free_stringpair_map(map);
    return NULL;
}

DYNAMIC_API stringpair_map_t * stringpair_map_dup(const stringpair_map_t *src)
{
    return _stringpair_map_dup(src, NULL);
}

static bool stringpair_map_is_leave(const stringpair_map_t *node)
{
    assert(node);
    return node->left == NULL && node->right == NULL;
}

DYNAMIC_API stringpair_map_t * stringpair_map_find(
        stringpair_map_t *map,
        const char *key
    )
{
    int c;

    assert(key);

    if (map == NULL || map->pair == NULL) // empty map
        return NULL;

    c = strcmp(map->pair->key, key);

    if (c == 0)
        return map;
    else if (c < 0)
        return stringpair_map_find(map->left, key);
    else
        return stringpair_map_find(map->right, key);
}

static stringpair_map_t * stringpair_map_grandparent(stringpair_map_t *node)
{
    assert(node);

    if (node->parent_ref == NULL)
        return NULL;

    return node->parent_ref->parent_ref;
}

static stringpair_map_t * stringpair_map_uncle(stringpair_map_t *node)
{
    assert(stringpair_map_grandparent(node));

    if (node->parent_ref == stringpair_map_grandparent(node)->left)
        return stringpair_map_grandparent(node)->right;
    else
        return stringpair_map_grandparent(node)->left;
}

static stringpair_map_t * _stringpair_map_add(
        stringpair_map_t *map,
        stringpair_t * pair
    )
{
    int c;

    assert(map);
    assert(pair);

    if (map->pair == NULL) {
        map->pair = stringpair_dup(pair);
        if (map->pair == NULL)
            return NULL;
        return map;
    }

    assert(map->pair->key);
    assert(pair->key);

    c = strcmp(map->pair->key, pair->key);
    if (c == 0) {
        free(map->pair->value);

        assert(pair->value);

        map->pair->value = strdup(pair->value);
        assert(map->pair->value);
        if (map->pair->value == NULL)
            return NULL;
    }
    else if (c < 0) {
        if (map->left == NULL) {
            map->left = new_stringpair_map(pair);
            if (map->left)
                return NULL;
            map = map->left;
        }
        else {
            map = _stringpair_map_add(map->left, pair);
        }
    }
    else {
        if (map->right == NULL) {
            map->right = new_stringpair_map(pair);
            if (map->right)
                return NULL;
            map = map->right;
        }
        else {
            map = _stringpair_map_add(map->right, pair);
        }
    }

    return map;
}

static void stringpair_map_rotate_left(stringpair_map_t *l)
{
    stringpair_map_t * _parent;
    stringpair_map_t * _r;

    assert(l);
    assert(l->parent_ref);
    assert(l->right);

    _parent = l->parent_ref;
    _r = l->right;

    l->right = _r->left;
    _r->left = l;

    if (_parent->left == l)
        _parent->left = _r;
    else
        _parent->right = _r;
}

static void stringpair_map_rotate_right(stringpair_map_t *r)
{
    stringpair_map_t * _parent;
    stringpair_map_t * _l;

    assert(r);
    assert(r->parent_ref);
    assert(r->left);

    _parent = r->parent_ref;
    _l = r->left;

    r->left = _l->right;
    _l->right = r;

    if (_parent->left == r)
        _parent->left = _l;
    else
        _parent->right = _l;
}

static void stringpair_map_case5(stringpair_map_t *map)
{
    map->parent_ref->color = rbt_black;
    stringpair_map_grandparent(map)->color = rbt_red;
    if (map == map->parent_ref->left &&
            map->parent_ref == stringpair_map_grandparent(map)->left) {
        stringpair_map_rotate_right(stringpair_map_grandparent(map));
    }
    else {
        assert(map == map->parent_ref->right &&
                map->parent_ref == stringpair_map_grandparent(map)->right);
        stringpair_map_rotate_left(stringpair_map_grandparent(map));
    }
}

static void stringpair_map_case4(stringpair_map_t *map)
{
    if (map == map->parent_ref->right &&
            map->parent_ref == stringpair_map_grandparent(map)->left) {
        stringpair_map_rotate_left(map->parent_ref);
        map = map->left;
    }
    else if (map == map->parent_ref->left &&
            map->parent_ref == stringpair_map_grandparent(map)->right) {
        stringpair_map_rotate_right(map->parent_ref);
        map = map->right;
    }

    stringpair_map_case5(map);
}

static void stringpair_map_case1(stringpair_map_t *map);

static void stringpair_map_case3(stringpair_map_t *map)
{
    if (stringpair_map_uncle(map) != NULL &&
            stringpair_map_uncle(map)->color == rbt_red) {
        map->parent_ref->color = rbt_black;
        stringpair_map_uncle(map)->color = rbt_black;
        stringpair_map_grandparent(map)->color = rbt_red;

        stringpair_map_case1(stringpair_map_grandparent(map));
    }
    else {
        stringpair_map_case4(map);
    }
}

static void stringpair_map_case2(stringpair_map_t *map)
{
    if (map->parent_ref->color == rbt_black)
        return;
    else
        stringpair_map_case3(map);
}

static void stringpair_map_case1(stringpair_map_t *map)
{
    assert(map);

    if (map->parent_ref == NULL)
        map->color = rbt_black;
    else
        stringpair_map_case2(map);
}

static void stringpair_map_repair(stringpair_map_t *map)
{
    stringpair_map_case1(map);
}

DYNAMIC_API stringpair_map_t * stringpair_map_add(
        stringpair_map_t *map,
        stringpair_t * pair
    )
{
    stringpair_map_t * _map = NULL;

    assert(map);
    assert(pair);

    _map = _stringpair_map_add(map, pair);
    if (_map == NULL)
        return NULL;

    stringpair_map_repair(_map);

    return _map;
}

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

