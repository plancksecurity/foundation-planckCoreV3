/**
 * @file    map_asn1.c
 * @brief   map asn1 to pEp structs and back
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#include "pEp_internal.h"
#include "map_asn1.h"

Identity_t *Identity_from_Struct(
        const pEp_identity *ident,
        Identity_t *result
    )
{
    bool allocated = !result;

    assert(ident);
    if (!ident)
        return NULL;

    if (allocated)
        result = (Identity_t *) calloc(1, sizeof(Identity_t));
    assert(result);
    if (!result)
        return NULL;

    if (ident->address) {
        int r = OCTET_STRING_fromBuf(&result->address, ident->address, -1);
        if (r)
            goto enomem;
    }

    if (ident->fpr) {
        if (OCTET_STRING_fromString(&result->fpr, ident->fpr))
            goto enomem;
    }

    if (ident->user_id) {
        int r = OCTET_STRING_fromBuf(&result->user_id, ident->user_id, -1);
        if (r)
            goto enomem;
    }

    if (ident->username) {
        int r = OCTET_STRING_fromBuf(&result->username, ident->username, -1);
        if (r)
            goto enomem;
    }

    if (ident->comm_type != PEP_ct_unknown) {
        result->comm_type = ident->comm_type;
    }

    if (ident->lang[0]) {
        int r = OCTET_STRING_fromBuf(&result->lang, ident->lang, 2);
        assert(r == 0);
        if(r != 0)
            goto enomem;
    }
    else {
        int r = OCTET_STRING_fromBuf(&result->lang, "en", 2);
        assert(r == 0);
        if(r != 0)
            goto enomem;
    }

    return result;

enomem:
    if (allocated)
        ASN_STRUCT_FREE(asn_DEF_Identity, result);
    return NULL;
}

pEp_identity *Identity_to_Struct(Identity_t *ident, pEp_identity *result)
{
    bool allocated = !result;

    assert(ident);
    if (!ident)
        return NULL;
    
    if (allocated)
        result = new_identity(NULL, NULL, NULL, NULL);
    if (!result)
        return NULL;

    result->address = strndup((char *) ident->address.buf,
            ident->address.size);
    assert(result->address);
    if (!result->address)
        goto enomem;

    result->fpr = strndup((char *) ident->fpr.buf, ident->fpr.size);
    assert(result->fpr);
    if (!result->fpr)
        goto enomem;

    result->user_id = strndup((char *) ident->user_id.buf,
            ident->user_id.size);
    assert(result->user_id);
    if (!result->user_id)
        goto enomem;

    result->username = strndup((char *) ident->username.buf,
            ident->username.size);
    assert(result->username);
    if (!result->username)
        goto enomem;

    result->comm_type = (PEP_comm_type) ident->comm_type;

    if (ident->lang.size == 2) {
        result->lang[0] = ident->lang.buf[0];
        result->lang[1] = ident->lang.buf[1];
        result->lang[2] = 0;
    }

    return result;

enomem:
    if (allocated)
        free_identity(result);
    return NULL;
}

IdentityList_t *IdentityList_from_identity_list(
        const identity_list *list,
        IdentityList_t *result
    )
{
    bool allocated = !result;

    assert(list && list->ident);
    if (!(list && list->ident))
        return NULL;

    if (allocated) {
        result = (IdentityList_t *) calloc(1, sizeof(IdentityList_t));
        assert(result);
        if (!result)
            return NULL;
    }
    else {
        asn_sequence_empty(result);
    }

    for (const identity_list *l = list; l && l->ident; l=l->next) {
        Identity_t *ident = Identity_from_Struct(l->ident, NULL);
        if (ASN_SEQUENCE_ADD(&result->list, ident)) {
            ASN_STRUCT_FREE(asn_DEF_Identity, ident);
            goto enomem;
        }
    }

    return result;

enomem:
    if (allocated)
        ASN_STRUCT_FREE(asn_DEF_IdentityList, result);
    return NULL;
}

identity_list *IdentityList_to_identity_list(IdentityList_t *list, identity_list *result)
{
    bool allocated = !result;

    assert(list);
    if (!list)
        return NULL;

    if (allocated)
        result = new_identity_list(NULL);
    if (!result)
        return NULL;

    identity_list *r = result;
    for (int i=0; i<list->list.count; i++) {
        pEp_identity *ident = Identity_to_Struct(list->list.array[i], NULL);
        r = identity_list_add(r, ident);
        if (!r)
            goto enomem;
    }

    return result;

enomem:
    if (allocated)
        free_identity_list(result);
    return NULL;
}

StringPair_t *StringPair_from_Struct(
        const stringpair_t *value,
        StringPair_t *result
    )
{
    bool allocated = !result;

    assert(value);
    if (!value)
        return NULL;

    if (allocated)
        result = (StringPair_t *) calloc(1, sizeof(StringPair_t));
    assert(result);
    if (!result)
        return NULL;
    
    if (value->key) {
        int r = OCTET_STRING_fromBuf(&result->key, value->key, -1);
        if (r)
            goto enomem;
    }

    if (value->value) {
        int r = OCTET_STRING_fromBuf(&result->value, value->value, -1);
        if (r)
            goto enomem;
    }

    return result;

enomem:
    if (allocated)
        ASN_STRUCT_FREE(asn_DEF_StringPair, result);
    return NULL;
}

stringpair_t *StringPair_to_Struct(StringPair_t *value, stringpair_t *result)
{
    bool allocated = !result;

    assert(value);
    if (!value)
        return NULL;

    if (allocated)
        result = new_stringpair(NULL, NULL);
    if (!result)
        return NULL;

    result->key = strndup((char *) value->key.buf,
            value->key.size);
    assert(result->key);
    if (!result->key)
        goto enomem;

    result->value = strndup((char *) value->value.buf,
            value->value.size);
    assert(result->value);
    if (!result->value)
        goto enomem;

    return result;

enomem:
    if (allocated)
        free_stringpair(result);
    return NULL;
}

StringPairList_t *StringPairList_from_stringpair_list(
        const stringpair_list_t *list,
        StringPairList_t *result
    )
{
    bool allocated = !result;

    assert(list && list->value);
    if (!(list && list->value))
        return NULL;

    if (allocated) {
        result = (StringPairList_t *) calloc(1, sizeof(StringPairList_t));
        assert(result);
        if (!result)
            return NULL;
    }
    else {
        asn_sequence_empty(result);
    }

    for (const stringpair_list_t *l = list; l && l->value; l=l->next) {
        StringPair_t *value = StringPair_from_Struct(l->value, NULL);
        if (ASN_SEQUENCE_ADD(&result->list, value)) {
            ASN_STRUCT_FREE(asn_DEF_StringPair, value);
            goto enomem;
        }
    }

    return result;

enomem:
    if (allocated)
        ASN_STRUCT_FREE(asn_DEF_StringPairList, result);
    return NULL;
}

stringpair_list_t *StringPairList_to_stringpair_list(
        StringPairList_t *list,
        stringpair_list_t *result
    )
{
    bool allocated = !result;

    assert(list);
    if (!list)
        return NULL;

    if (allocated)
        result = new_stringpair_list(NULL);
    if (!result)
        return NULL;

    stringpair_list_t *r = result;
    for (int i=0; i<list->list.count; i++) {
        stringpair_t *value = StringPair_to_Struct(list->list.array[i], NULL);
        r = stringpair_list_add(r, value);
        if (!r)
            goto enomem;
    }

    return result;

enomem:
    if (allocated)
        free_stringpair_list(result);
    return NULL;
}

PStringList_t *PStringList_from_stringlist(
        const stringlist_t *list,
        PStringList_t *result
    )
{
    bool allocated = !result;

    assert(list && list->value);
    if (!(list && list->value))
        return NULL;

    if (allocated) {
        result = (PStringList_t *) calloc(1, sizeof(PStringList_t));
        assert(result);
        if (!result)
            return NULL;
    }
    else {
        asn_sequence_empty(result);
    }

    for (const stringlist_t *l = list; l && l->value; l=l->next) {
        PString_t *element = NULL;
        int r = OCTET_STRING_fromBuf(element, l->value, -1);
        if (r)
            goto enomem;
        if (ASN_SEQUENCE_ADD(&result->list, element)) {
            ASN_STRUCT_FREE(asn_DEF_PString, element);
            goto enomem;
        }
    }

    return result;

enomem:
    if (allocated)
        ASN_STRUCT_FREE(asn_DEF_PStringList, result);
    return NULL;
}

stringlist_t *PStringList_to_stringlist(
        PStringList_t *list,
        stringlist_t *result
    )
{
    bool allocated = !result;

    assert(list);
    if (!list)
        return NULL;

    if (allocated)
        result = new_stringlist(NULL);
    if (!result)
        return NULL;

    for (int i=0; i<list->list.count; i++) {
        result->value = strndup((char *) list->list.array[i]->buf,
                list->list.array[i]->size);
        assert(result->value);
        if (!result->value)
            goto enomem;
    }

    return result;

enomem:
    if (allocated)
        free_stringlist(result);
    return NULL;
}

BlobList_t *BlobList_from_bloblist(
        bloblist_t *list,
        BlobList_t *result,
        bool copy,
        size_t max_blob_size
    )
{
    bool allocated = !result;
    if (!max_blob_size)
        max_blob_size = SIZE_MAX;

    assert(list && list->value);
    if (!(list && list->value))
        return NULL;

    if (allocated) {
        result = (BlobList_t *) calloc(1, sizeof(BlobList_t));
        assert(result);
        if (!result)
            return NULL;
    }
    else {
        asn_sequence_empty(result);
    }

    size_t rest_blob_size = max_blob_size;

    for (bloblist_t *l = list; l && l->value; l=l->next) {
        Blob_t *element = (Blob_t *) calloc(1, sizeof(Blob_t));
        assert(element);
        if (!element)
            goto enomem;

        int r = 0;

        if (l->size > rest_blob_size)
            goto enomem;
        rest_blob_size -= l->size;

        if (copy) {
            r = OCTET_STRING_fromBuf(&element->value, l->value, l->size);
            if (r)
                goto enomem;
        }
        else /* move */ {
#if defined(__CHAR_BIT__) && __CHAR_BIT__ == 8
            element->value.buf = (uint8_t *) l->value;
#else
            // FIXME: this is problematic on platforms with bytes != octets
            // we want this warning
            element->value.buf = l->value;
#endif
            l->value = NULL;
            element->value.size = l->size;
            l->size = 0;
        }

        if (!EMPTYSTR(l->mime_type)) {
            PString_t *_mime_type = (PString_t *) calloc(1, sizeof(PString_t));
            assert(_mime_type);
            if (!_mime_type)
                goto enomem;

            r = OCTET_STRING_fromBuf(_mime_type, l->mime_type, -1);
            if (r)
                goto enomem;
            element->mime_type = _mime_type;
        }

        if (!EMPTYSTR(l->filename)) {
            PString_t *_filename = (PString_t *) calloc(1, sizeof(PString_t));
            assert(_filename);
            if (!_filename)
                goto enomem;

            r = OCTET_STRING_fromBuf(_filename, l->filename, -1);
            if (r)
                goto enomem;
            element->filename = _filename;
        }

        switch (l->disposition) {
            case PEP_CONTENT_DISP_ATTACHMENT:
                element->disposition = ContentDisposition_attachment;
                break;
            case PEP_CONTENT_DISP_INLINE:
                element->disposition = ContentDisposition_inline;
                break;
            case PEP_CONTENT_DISP_OTHER:
                element->disposition = ContentDisposition_other;
                break;
            default:
                assert(0); // should not happen; use default
                element->disposition = ContentDisposition_attachment;
        }

        if (ASN_SEQUENCE_ADD(&result->list, element)) {
            ASN_STRUCT_FREE(asn_DEF_Blob, element);
            goto enomem;
        }
    }
    
    return result;

enomem:
    if (allocated)
        ASN_STRUCT_FREE(asn_DEF_BlobList, result);
    return NULL;
}

bloblist_t *BlobList_to_bloblist(
        BlobList_t *list,
        bloblist_t *result,
        bool copy,
        size_t max_blob_size
    )
{
    bool allocated = !result;
    if (!max_blob_size)
        max_blob_size = SIZE_MAX;

    assert(list);
    if (!list)
        return NULL;

    if (allocated)
        result = new_bloblist(NULL, 0, NULL, NULL);
    if (!result)
        return NULL;

    size_t rest_blob_size = max_blob_size;

    bloblist_t *r = result;
    for (int i=0; i<list->list.count; i++) {
        // this should not happen
        assert(list->list.array[i]);
        if (!list->list.array[i])
            goto enomem;

        if (list->list.array[i]->value.size > rest_blob_size)
            goto enomem;
        rest_blob_size -= list->list.array[i]->value.size;

        char *_mime_type = NULL;
        if (list->list.array[i]->mime_type) {
            _mime_type = strndup((char *) list->list.array[i]->mime_type->buf,
                    list->list.array[i]->mime_type->size);
            assert(_mime_type);
            if (!_mime_type)
                goto enomem;
        }

        char *_filename = NULL;
        if (list->list.array[i]->filename) {
            _filename = strndup((char *) list->list.array[i]->filename->buf,
                    list->list.array[i]->filename->size);
            assert(_filename);
            if (!_filename)
                goto enomem;
        }

#if defined(__CHAR_BIT__) && __CHAR_BIT__ == 8
        char *_data = (char *) list->list.array[i]->value.buf;
#else
        // FIXME: this is problematic on platforms with bytes != octets
        // we want this warning
        char *_data = list->list.array[i]->value.buf;
#endif

        if (copy) {
            _data = strndup(_data, list->list.array[i]->value.size);
            assert(_data);
            if (!_data)
                goto enomem;
        }

        // bloblist_add() has move semantics
        r = bloblist_add(r, _data, list->list.array[i]->value.size, _mime_type,
                _filename);

        if (!copy) {
            list->list.array[i]->value.buf = NULL;
            list->list.array[i]->value.size = 0;
        }

        if (!r)
            goto enomem;

        switch (list->list.array[i]->disposition) {
            case ContentDisposition_attachment:
                r->disposition = PEP_CONTENT_DISP_ATTACHMENT;
                break;
            case ContentDisposition_inline:
                r->disposition = PEP_CONTENT_DISP_INLINE;
                break;
            case ContentDisposition_other:
                r->disposition = PEP_CONTENT_DISP_OTHER;
                break;
            default:
                assert(0); // should not happen; use default
                r->disposition = PEP_CONTENT_DISP_ATTACHMENT;
        }
    }

    return result;

enomem:
    if (allocated)
        free_bloblist(result);
    return NULL;
}

PEPMessage_t *PEPMessage_from_message(
        message *msg,
        PEPMessage_t *result,
        bool copy,
        size_t max_blob_size
    )
{
    bool allocated = !result;
    if (!max_blob_size)
        max_blob_size = SIZE_MAX;

    assert(msg);
    if (!msg)
        return NULL;

    if (allocated) {
        result = (PEPMessage_t *) calloc(1, sizeof(PEPMessage_t));
        assert(result);
        if (!result)
            return NULL;
    }
    else {
        asn_sequence_empty(result);
    }

    // direction will be skipped on the line

    if (!EMPTYSTR(msg->id)) {
        PString_t *str = (PString_t *) calloc(1, sizeof(PString_t));
        assert(str);
        if (!str)
            goto enomem;

        int r = OCTET_STRING_fromBuf(str, msg->id, -1);
        if (r)
            goto enomem;

        result->id = str;
    }

    if (msg->sent) {
        Timestamp_t *ts = asn_time2GT(NULL, msg->sent, 1);
        if (!ts)
            goto enomem;

        result->sent = ts;
    }

    if (msg->recv) {
        Timestamp_t *ts = asn_time2GT(NULL, msg->recv, 1);
        if (!ts)
            goto enomem;

        result->recv = ts;
    }

    if (!msg->from) // from is not optional
        goto enomem;
    Identity_from_Struct(msg->from, &result->from);

    if (msg->to && msg->to->ident) {
        IdentityList_t *l = IdentityList_from_identity_list(msg->to, NULL);
        if (!l)
            goto enomem;

        result->to = l;
    }

    if (msg->cc && msg->cc->ident) {
        IdentityList_t *l = IdentityList_from_identity_list(msg->cc, NULL);
        if (!l)
            goto enomem;

        result->cc = l;
    }

    if (msg->bcc && msg->bcc->ident) {
        IdentityList_t *l = IdentityList_from_identity_list(msg->bcc, NULL);
        if (!l)
            goto enomem;

        result->bcc = l;
    }

    if (msg->recv_by) {
        Identity_t *i = Identity_from_Struct(msg->recv_by, NULL);
        if (!i)
            goto enomem;

        result->recv_by = i;
    }

    if (msg->reply_to && msg->reply_to->ident) {
        IdentityList_t *l = IdentityList_from_identity_list(msg->reply_to, NULL);
        if (!l)
            goto enomem;

        result->reply_to = l;
    }

    if (msg->in_reply_to && msg->in_reply_to->value) {
        PStringList_t *l = PStringList_from_stringlist(msg->in_reply_to, NULL);
        if (!l)
            goto enomem;

        result->in_reply_to = l;
    }

    if (msg->references && msg->references->value) {
        PStringList_t *l = PStringList_from_stringlist(msg->references, NULL);
        if (!l)
            goto enomem;

        result->references = l;
    }

    if (msg->keywords && msg->keywords->value) {
        PStringList_t *l = PStringList_from_stringlist(msg->keywords, NULL);
        if (!l)
            goto enomem;

        result->keywords = l;
    }

    if (!EMPTYSTR(msg->comments)) {
        PString_t *str = (PString_t *) calloc(1, sizeof(PString_t));
        assert(str);
        if (!str)
            goto enomem;

        int r = OCTET_STRING_fromBuf(str, msg->comments, -1);
        if (r)
            goto enomem;

        result->comments = str;
    }

    if (msg->opt_fields && msg->opt_fields->value) {
        StringPairList_t *l = StringPairList_from_stringpair_list(msg->opt_fields, NULL);
        if (!l)
            goto enomem;

        result->opt_fields = l;
    }

    if (!EMPTYSTR(msg->_sender_fpr)) {
        Hash_t *str = (Hash_t *) calloc(1, sizeof(Hash_t));
        assert(str);
        if (!str)
            goto enomem;

        int r = OCTET_STRING_fromBuf(str, msg->_sender_fpr, -1);
        if (r)
            goto enomem;

        result->sender_fpr = str;
    }

    if (!EMPTYSTR(msg->shortmsg)) {
        PString_t *str = (PString_t *) calloc(1, sizeof(PString_t));
        assert(str);
        if (!str)
            goto enomem;

        int r = OCTET_STRING_fromBuf(str, msg->shortmsg, -1);
        if (r)
            goto enomem;

        result->shortmsg = str;
    }

    size_t rest_blob_size = max_blob_size;

    if (!EMPTYSTR(msg->longmsg)) {
        PString_t *str = (PString_t *) calloc(1, sizeof(PString_t));
        assert(str);
        if (!str)
            goto enomem;

        if (copy) {
            int r = OCTET_STRING_fromBuf(str, msg->longmsg, -1);
            if (r)
                goto enomem;
            if (str->size > rest_blob_size)
                goto enomem;
        }
        else /* move */ {
            str->size = strlen(msg->longmsg);
            if (str->size > rest_blob_size)
                goto enomem;

            str->buf = (uint8_t *) msg->longmsg;
            msg->longmsg = NULL;
        }

        rest_blob_size -= str->size;
        result->longmsg = str;
    }

    if (!EMPTYSTR(msg->longmsg_formatted)) {
        PString_t *str = (PString_t *) calloc(1, sizeof(PString_t));
        assert(str);
        if (!str)
            goto enomem;

        if (copy) {
            int r = OCTET_STRING_fromBuf(str, msg->longmsg_formatted, -1);
            if (r)
                goto enomem;
            if (str->size > rest_blob_size)
                goto enomem;
        }
        else /* move */ {
            str->size = strlen(msg->longmsg_formatted);
            if (str->size > rest_blob_size)
                goto enomem;

            str->buf = (uint8_t *) msg->longmsg_formatted;
            msg->longmsg_formatted = NULL;
        }

        rest_blob_size -= str->size;
        result->longmsg_formatted = str;
    }

    if (msg->attachments && msg->attachments->value) {
        BlobList_t *bl = BlobList_from_bloblist(msg->attachments, NULL, copy,
                rest_blob_size);
        if (!bl)
            goto enomem;
        result->attachments = bl;
    }

    return result;

enomem:
    if (allocated)
        ASN_STRUCT_FREE(asn_DEF_PEPMessage, result);
    return NULL;
}

message *PEPMessage_to_message(
        PEPMessage_t *msg,
        message *result,
        bool copy,
        size_t max_blob_size
    )
{
    bool allocated = !result;
    if (!max_blob_size)
        max_blob_size = SIZE_MAX;

    assert(msg);
    if (!msg)
        return NULL;

    if (allocated) {
        result = new_message(PEP_dir_incoming);
        if (!result)
            goto enomem;
    }

    if (msg->direction) {
        switch (*msg->direction) {
            case MessageDirection_incoming:
                result->dir = PEP_dir_incoming;
                break;
            case MessageDirection_outgoing:
                result->dir = PEP_dir_outgoing;
                break;
            default:
                assert(0);
        }
    }

    if (msg->id) {
        result->id = strndup((char *) msg->id->buf, msg->id->size);
        assert(result->id);
        if (!result->id)
            goto enomem;
    }

    if (msg->sent) {
        timestamp *_sent = new_timestamp(0);
        if (!_sent)
            goto enomem;

        if (asn_GT2time(msg->sent, _sent, 1) == -1)
            goto enomem;
        result->sent = _sent;
    }

    if (msg->recv) {
        timestamp *_recv = new_timestamp(0);
        if (!_recv)
            goto enomem;

        if (asn_GT2time(msg->recv, _recv, 1) == -1)
            goto enomem;
        result->recv = _recv;
    }

    // from is mandatory
    result->from = Identity_to_Struct(&msg->from, NULL);
    if (!result->from)
        goto enomem;

    if (msg->to) {
        identity_list *il = IdentityList_to_identity_list(msg->to, NULL);
        if (!il)
            goto enomem;

        result->to = il;
    }

    if (msg->cc) {
        identity_list *il = IdentityList_to_identity_list(msg->cc, NULL);
        if (!il)
            goto enomem;

        result->cc = il;
    }

    if (msg->bcc) {
        identity_list *il = IdentityList_to_identity_list(msg->bcc, NULL);
        if (!il)
            goto enomem;

        result->bcc = il;
    }

    if (msg->recv_by) {
        pEp_identity *i = Identity_to_Struct(msg->recv_by, NULL);
        if (!i)
            goto enomem;

        result->recv_by = i;
    }

    if (msg->reply_to) {
        identity_list *il = IdentityList_to_identity_list(msg->reply_to, NULL);
        if (!il)
            goto enomem;

        result->reply_to = il;
    }

    if (msg->in_reply_to) {
        stringlist_t *l = PStringList_to_stringlist(msg->in_reply_to, NULL);
        if (!l)
            goto enomem;

        result->in_reply_to = l;
    }

    if (msg->references) {
        stringlist_t *l = PStringList_to_stringlist(msg->references, NULL);
        if (!l)
            goto enomem;

        result->references = l;
    }

    if (msg->keywords) {
        stringlist_t *l = PStringList_to_stringlist(msg->keywords, NULL);
        if (!l)
            goto enomem;

        result->keywords = l;
    }

    if (msg->comments) {
        char *s = strndup((char *) msg->comments->buf, msg->comments->size);
        assert(s);
        if (!s)
            goto enomem;

        result->comments = s;
    }

    if (msg->opt_fields) {
        stringpair_list_t *l =
            StringPairList_to_stringpair_list(msg->opt_fields, NULL);
        if (!l)
            goto enomem;

        result->opt_fields = l;
    }

    if (msg->sender_fpr) {
        char *_sender_fpr = strndup((char *) msg->sender_fpr->buf,
                msg->sender_fpr->size);
        if (_sender_fpr)
            goto enomem;

        result->_sender_fpr = _sender_fpr;
    }

    if (msg->shortmsg) {
        char *s = strndup((char *) msg->shortmsg->buf, msg->shortmsg->size);
        assert(s);
        if (!s)
            goto enomem;

        result->shortmsg = s;
    }

    size_t rest_blob_size = max_blob_size;

    if (msg->longmsg) {
        if (msg->longmsg->size > rest_blob_size)
            goto enomem;

        char *s = NULL;

        if (copy) {
            s = strndup((char *) msg->longmsg->buf, msg->longmsg->size);
            if (!s)
                goto enomem;
            rest_blob_size -= msg->longmsg->size;
        }
        else /* move */ {
            s = (char *) msg->longmsg->buf;
            msg->longmsg->buf = NULL;
            rest_blob_size -= msg->longmsg->size;
            msg->longmsg->size = 0;
        }

        result->longmsg = s;
    }

    if (msg->longmsg_formatted) {
        if (msg->longmsg_formatted->size > rest_blob_size)
            goto enomem;

        char *s = NULL;

        if (copy) {
            s = strndup((char *) msg->longmsg_formatted->buf,
                    msg->longmsg_formatted->size);
            if (!s)
                goto enomem;
            rest_blob_size -= msg->longmsg_formatted->size;
        }
        else /* move */ {
            s = (char *) msg->longmsg_formatted->buf;
            msg->longmsg_formatted->buf = NULL;
            rest_blob_size -= msg->longmsg_formatted->size;
            msg->longmsg_formatted->size = 0;
        }

        result->longmsg_formatted = s;
    }

    if (msg->attachments) {
        bloblist_t *a = BlobList_to_bloblist(msg->attachments, NULL, copy,
                rest_blob_size);
        if (!a)
            goto enomem;

        result->attachments = a;
    }

    return result;

enomem:
    if (allocated)
        free_message(result);
    return NULL;
}

