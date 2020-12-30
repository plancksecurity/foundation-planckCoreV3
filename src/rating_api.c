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

DYNAMIC_API PEP_STATUS rating_of_new_channel_to_identity(
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

    return rating_of_existing_channel_to_identity(session, ident, rating);
}

DYNAMIC_API PEP_STATUS last_rating_of_channel_to_identity(
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
        if (!r)
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

DYNAMIC_API PEP_STATUS rating_of_existing_channel_to_identity(
            PEP_SESSION session,
            const pEp_identity *ident,
            PEP_rating *rating
        )
{
    assert(session && ident && rating);
    if (!(session && ident && rating))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    *rating = PEP_rating_undefined;

    if (EMPTYSTR(ident->fpr)) {
        *rating = PEP_rating_have_no_key;
        return PEP_STATUS_OK;
    }

    if (ident->comm_type == PEP_ct_unknown) {
        
    }

    return status;
}

