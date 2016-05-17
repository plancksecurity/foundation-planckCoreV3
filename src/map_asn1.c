#include "pEp_internal.h"
#include "map_asn1.h"

Identity_t *Identity_from_Struct(const pEp_identity *ident)
{
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
    asn_DEF_UTF8String.free_struct(&asn_DEF_UTF8String, result, 0);
    return NULL;
}

pEp_identity *Identity_to_Struct(Identity_t *ident)
{
    pEp_identity *result = new_identity(NULL, NULL, NULL, NULL);
    if (!result)
        return NULL;

    return result;
}

