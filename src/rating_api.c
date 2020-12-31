/**
 * @file    rating_api.c
 * @brief   implementation of rating functions
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */


#include "pEp_internal.h"
#include "rating_api.h"
#include "keymanagement.h"

DYNAMIC_API PEP_rating rating_from_comm_type(PEP_comm_type ct)
{
    if (ct == PEP_ct_unknown)
        return PEP_rating_undefined;

    else if (ct == PEP_ct_key_not_found)
        return PEP_rating_have_no_key;

    else if (ct == PEP_ct_compromised)
        return PEP_rating_under_attack;

    else if (ct == PEP_ct_mistrusted)
        return PEP_rating_mistrust;

    if (ct == PEP_ct_no_encryption || ct == PEP_ct_no_encrypted_channel ||
            ct == PEP_ct_my_key_not_included)
            return PEP_rating_unencrypted;

    if (ct >= PEP_ct_confirmed_enc_anon)
        return PEP_rating_trusted_and_anonymized;

    else if (ct >= PEP_ct_strong_encryption)
        return PEP_rating_trusted;

    else if (ct >= PEP_ct_strong_but_unconfirmed && ct < PEP_ct_confirmed)
        return PEP_rating_reliable;

    else
        return PEP_rating_unreliable;
}

DYNAMIC_API PEP_rating add_rating(PEP_rating rating1, PEP_rating rating2)
{
    if (rating1 == PEP_rating_undefined || rating2 == PEP_rating_undefined)
        return PEP_rating_undefined;

    return rating1 > rating2 ? rating2 : rating1;
}

DYNAMIC_API PEP_STATUS rating_of_new_channel(
            PEP_SESSION session,
            pEp_identity *ident,
            PEP_rating *rating
        )
{
    assert(session && ident && rating);
    if (!(session && ident && rating))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = update_identity(session, ident);
    if (status)
        return status;

    *rating = rating_from_comm_type(ident->comm_type);
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS last_rating_of_channel(
            PEP_SESSION session,
            const pEp_identity *ident,
            PEP_rating *rating
        )
{
    assert(session && ident && rating);
    if (!(session && ident && rating))
        return PEP_ILLEGAL_VALUE;

    assert(!EMPTYSTR(ident->address));
    if (EMPTYSTR(ident->address))
        return PEP_ILLEGAL_VALUE;

    if (ident->comm_type) {
        *rating = rating_from_comm_type(ident->comm_type);
        return PEP_STATUS_OK;
    }

    if (EMPTYSTR(ident->user_id)) {
        free(ident->user_id);
        int r = snprintf(ident->user_id, strlen(ident->address) + 6, "TOFU_%s",
                ident->address);
        if (r<0)
            return PEP_OUT_OF_MEMORY;
    }

    pEp_identity *stored_ident = NULL;
    PEP_STATUS status = get_identity(session, ident->address, ident->user_id, &stored_ident);
    if (status)
        return status;

    *rating = rating_from_comm_type(stored_ident->comm_type);
    free_identity(stored_ident);
    return PEP_STATUS_OK;
}

static PEP_STATUS trust_between_user_and_key(
            PEP_SESSION session,
            const char *user_id,
            const char *fpr,
            PEP_rating *rating
        )
{
    assert(session && user_id && fpr && rating);
    if (!(session && user_id && fpr && rating))
        return PEP_ILLEGAL_VALUE;

    *rating = PEP_rating_undefined;

    PEP_STATUS status = PEP_STATUS_OK;
    return status;
}

DYNAMIC_API PEP_STATUS rating_of_existing_channel(
            PEP_SESSION session,
            const pEp_identity *ident,
            PEP_rating *rating
        )
{
    assert(session && ident && rating);
    if (!(session && ident && rating))
        return PEP_ILLEGAL_VALUE;

    assert(!EMPTYSTR(ident->address));
    if (EMPTYSTR(ident->address))
        return PEP_ILLEGAL_VALUE;

    *rating = PEP_rating_undefined;

    if (EMPTYSTR(ident->user_id)) {
        free(ident->user_id);
        int r = snprintf(ident->user_id, strlen(ident->address) + 6, "TOFU_%s",
                ident->address);
        if (r<0)
            return PEP_OUT_OF_MEMORY;
    }

    PEP_rating keyrating = PEP_rating_undefined;
    PEP_comm_type keycomm_type = PEP_ct_unknown;
    PEP_rating trustrating = PEP_rating_undefined;

    PEP_STATUS status = get_key_rating(session, ident->fpr, &keycomm_type);
    if (status == PEP_KEY_NOT_FOUND) {
        keyrating = PEP_rating_have_no_key;
        status = PEP_STATUS_OK;
    }
    else if (status) {
        goto the_end;
    }
    else {
        keyrating = rating_from_comm_type(keycomm_type);
    }

    status = trust_between_user_and_key(session, ident->user_id, ident->fpr, &trustrating);
    if (status)
        goto the_end;

    *rating = add_rating(keyrating, trustrating);

the_end:
    return status;
}

