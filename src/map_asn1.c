#include "pEp_internal.h"
#include "map_asn1.h"

Identity_t *Identity_from_Struct(const pEp_identity *ident)
{
    assert(ident);
    if (!ident)
        return NULL;

    Identity_t *result = (Identity_t *) calloc(1, sizeof(Identity_t));
    assert(result);
    if (!result)
        return NULL;

    if (ident->address) {
        result->address = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String,
                ident->address, -1);
        if (ident->address && !result->address)
            goto enomem;
    }

    if (ident->fpr) {
        if (OCTET_STRING_fromString(&result->fpr, ident->fpr))
            goto enomem;
    }

    if (ident->user_id) {
        result->user_id = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String,
                ident->user_id, -1);
        if (ident->user_id && !result->user_id)
            goto enomem;
    }

    if (ident->username) {
        result->username = OCTET_STRING_new_fromBuf(&asn_DEF_UTF8String,
                ident->username, -1);
        if (ident->username && !result->username)
            goto enomem;
    }

    if (ident->comm_type != PEP_ct_unknown) {
        result->comm_type = malloc(sizeof(long));
        assert(result->comm_type);
        if (!result->comm_type)
            goto enomem;
        *result->comm_type = ident->comm_type;
    }

    if (ident->lang[0]) {
        result->lang = OCTET_STRING_new_fromBuf(&asn_DEF_ISO936_1,
                ident->lang, 2);
        if (!result->lang)
            goto enomem;
    }

    return result;

enomem:
    ASN_STRUCT_FREE(asn_DEF_Identity, result);
    return NULL;
}

pEp_identity *Identity_to_Struct(Identity_t *ident)
{
    assert(ident);
    if (!ident)
        return NULL;
    
    pEp_identity *result = new_identity(NULL, NULL, NULL, NULL);
    if (!result)
        return NULL;

    if (ident->address) {
        result->address = strndup((char *) ident->address->buf,
                ident->address->size);
        assert(result->address);
        if (!result->address)
            goto enomem;
    }

    result->fpr = strndup((char *) ident->fpr.buf, ident->fpr.size);
    assert(result->fpr);
    if (!result->fpr)
        goto enomem;

    if (ident->user_id) {
        result->user_id = strndup((char *) ident->user_id->buf,
                ident->user_id->size);
        assert(result->user_id);
        if (!result->user_id)
            goto enomem;
    }

    if (ident->username) {
        result->username = strndup((char *) ident->username->buf,
                ident->username->size);
        assert(result->username);
        if (!result->username)
            goto enomem;
    }

    if (ident->comm_type)
        result->comm_type = (PEP_comm_type) *ident->comm_type;

    if (ident->lang) {
        result->lang[0] = ident->lang->buf[0];
        result->lang[1] = ident->lang->buf[1];
    }

    return result;

enomem:
    free_identity(result);
    return NULL;
}

KeyList_t *KeyList_from_stringlist(const stringlist_t *list)
{
    assert(list);
    if (!list)
        return NULL;

    KeyList_t *result = (KeyList_t *) calloc(1, sizeof(KeyList_t));
    assert(result);
    if (!result)
        return NULL;

    for (const stringlist_t *l = list; l && l->value; l=l->next) {
        Hash_t *key = OCTET_STRING_new_fromBuf(&asn_DEF_Hash, l->value, -1);
        if (!key)
            goto enomem;

        if (ASN_SEQUENCE_ADD(&result->list, key)) {
            ASN_STRUCT_FREE(asn_DEF_Hash, key);
            goto enomem;
        }
    }

    return result;

enomem:
    ASN_STRUCT_FREE(asn_DEF_KeyList, result);
    return NULL;
}

stringlist_t *KeyList_to_stringlist(KeyList_t *list)
{
    assert(list);
    if (!list)
        return NULL;

    stringlist_t *result = new_stringlist(NULL);
    if (!result)
        return NULL;

    stringlist_t *r = result;
    for (int i=0; i<list->list.count; i++) {
        char *str = strndup((char *) list->list.array[i]->buf,
                list->list.array[i]->size);
        assert(str);
        if (!str)
            goto enomem;
        r = stringlist_add(r, str);
        free(str);
        if (!r)
            goto enomem;
    }

    return result;

enomem:
    free_stringlist(result);
    return NULL;
}

