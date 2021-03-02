/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

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

PEP_STATUS add_sticky_bit_to_Identity(PEP_SESSION session, Identity_t *ident)
{
    PEP_STATUS status = PEP_STATUS_OK;

    char *fpr = NULL;
    char *user_id = NULL;
    BOOLEAN_t *sticky = NULL;

    fpr = strndup((char *) ident->fpr.buf, ident->fpr.size);
    assert(fpr);
    if (!fpr)
        goto enomem;

    user_id = strndup((char *) ident->user_id.buf, ident->user_id.size);
    assert(user_id);
    if (!user_id)
        goto enomem;

    sticky = (BOOLEAN_t *) calloc(1, sizeof(BOOLEAN_t));
    assert(sticky);
    if (!sticky)
        goto enomem;

    bool _sticky = false;
    status = get_key_sticky_bit_for_user(session, user_id, fpr, &_sticky);
    if (status)
        goto error;

    *sticky = _sticky;

    ident->sticky = sticky;
    free(fpr);
    free(user_id);

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

error:
    free(fpr);
    free(user_id);
    free(sticky);
    return status;
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

    assert(list);
    if (!list)
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

