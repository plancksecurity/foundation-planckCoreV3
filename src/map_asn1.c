#include "pEp_internal.h"
#include "map_asn1.h"

Identity_t *Identity_from_Struct(
        const pEp_identity *ident,
        Identity_t *result
    )
{
    assert(ident);
    if (!ident)
        return NULL;

    if (!result)
        result = (Identity_t *) calloc(1, sizeof(Identity_t));
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
        int r = OCTET_STRING_fromBuf(&result->lang, ident->lang, 2);
        assert(r == 0);
    }
    else {
        int r = OCTET_STRING_fromBuf(&result->lang, "en", 2);
        assert(r == 0);
    }

    return result;

enomem:
    ASN_STRUCT_FREE(asn_DEF_Identity, result);
    return NULL;
}

pEp_identity *Identity_to_Struct(Identity_t *ident, pEp_identity *result)
{
    assert(ident);
    if (!ident)
        return NULL;
    
    if (!result)
        result = new_identity(NULL, NULL, NULL, NULL);
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

    if (ident->lang.size == 2) {
        result->lang[0] = ident->lang.buf[0];
        result->lang[1] = ident->lang.buf[1];
        result->lang[2] = 0;
    }

    return result;

enomem:
    free_identity(result);
    return NULL;
}

IdentityList_t *IdentityList_from_identity_list(
        const identity_list *list,
        IdentityList_t *result
    )
{
    assert(list);
    if (!list)
        return NULL;

    if (!result)
        result = (IdentityList_t *) calloc(1, sizeof(IdentityList_t));
    assert(result);
    if (!result)
        return NULL;

    for (const identity_list *l = list; l && l->ident; l=l->next) {
        Identity_t *ident = Identity_from_Struct(l->ident, NULL);
        if (ASN_SEQUENCE_ADD(&result->list, ident)) {
            ASN_STRUCT_FREE(asn_DEF_Identity, ident);
            goto enomem;
        }
    }

    return result;

enomem:
    ASN_STRUCT_FREE(asn_DEF_IdentityList, result);
    return NULL;
}

identity_list *IdentityList_to_identity_list(IdentityList_t *list, identity_list *result)
{
    assert(list);
    if (!list)
        return NULL;

    if (!result)
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
    free_identity_list(result);
    return NULL;
}

timestamp *GeneralizedTime_to_timestamp(GeneralizedTime_t * asntime, timestamp *result)
{
    assert(asntime);
    if (!asntime)
        return NULL;

    time_t smpltime = asn_GT2time(asntime, NULL, 0);

    if (!result){
        result = new_timestamp(smpltime);
    }
    else
        gmtime_r(&smpltime, result);


    return result;
}

time_t GeneralizedTime_to_time_t(GeneralizedTime_t * asntime)
{
    return asn_GT2time(asntime, NULL, 0);
}

GeneralizedTime_t *timestamp_to_GeneralizedTime(timestamp * ts, GeneralizedTime_t *result)
{
    assert(ts);
    if (!ts)
        return NULL;

    GeneralizedTime_t *asntime = asn_time2GT(result, ts, 0);
    return asntime;
}
