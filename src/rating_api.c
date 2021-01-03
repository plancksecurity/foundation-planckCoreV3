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

DYNAMIC_API PEP_STATUS last_rating_of_new_channel(
            PEP_SESSION session,
            pEp_identity *ident,
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

    pEp_identity *ident = new_identity(NULL, fpr, user_id, NULL);
    if (!ident)
        return PEP_OUT_OF_MEMORY;

    PEP_STATUS status = get_trust(session, ident);
    if (status == PEP_CANNOT_FIND_IDENTITY)
        status = PEP_STATUS_OK;
    else if (status)
        goto the_end;

    if (ident->comm_type == PEP_ct_unknown)
        *rating = PEP_rating_unreliable;
    else
        *rating = rating_from_comm_type(ident->comm_type);

the_end:
    free_identity(ident);
    return status;
}

DYNAMIC_API PEP_STATUS rating_of_existing_channel(
            PEP_SESSION session,
            pEp_identity *ident,
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

static inline bool identity_list_empty(const identity_list *il)
{
    return !(il && il->ident);
}

static PEP_STATUS _rating_sum(PEP_SESSION session, const identity_list *il,
        channel_rating_t channel_rating, PEP_rating *rating)
{
    assert(session && channel_rating && rating);
    if (!(session && channel_rating && rating))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    *rating = PEP_rating_undefined;

    if (identity_list_empty(il))
        goto the_end;

    PEP_rating _rating = PEP_rating_fully_anonymous;
    for (const identity_list *_il = il; _il && _il->ident; _il = _il->next) {
        PEP_rating r = PEP_rating_undefined;
        status = channel_rating(session, _il->ident, &r);
        if (status)
            goto the_end;
        _rating = add_rating(_rating, r);
    }

    *rating = _rating;

the_end:
    return status;
}

static inline bool all_identities_empty(const message *msg)
{
    return identity_list_empty(msg->to)
        && identity_list_empty(msg->cc)
        && identity_list_empty(msg->bcc);
}

static PEP_STATUS rating_sum(PEP_SESSION session, const message *msg,
        channel_rating_t channel_rating, PEP_rating *rating)
{
    assert(session && msg && channel_rating && rating);
    if (!(session && msg && channel_rating && rating))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    *rating = PEP_rating_undefined;

    if (all_identities_empty(msg))
        goto the_end;

    PEP_rating to_rating = PEP_rating_undefined;
    status = _rating_sum(session, msg->to, channel_rating, &to_rating);
    if (status)
        goto the_end;

    PEP_rating cc_rating = PEP_rating_undefined;
    status = _rating_sum(session, msg->to, channel_rating, &cc_rating);
    if (status)
        goto the_end;

    PEP_rating bcc_rating = PEP_rating_undefined;
    status = _rating_sum(session, msg->to, channel_rating, &bcc_rating);
    if (status)
        goto the_end;

    if (!to_rating && !cc_rating && !bcc_rating)
        goto the_end;

    PEP_rating _rating = PEP_rating_fully_anonymous;
    if (to_rating)
        _rating = add_rating(_rating, to_rating);
    if (cc_rating)
        _rating = add_rating(_rating, cc_rating);
    if (bcc_rating)
        _rating = add_rating(_rating, bcc_rating);

    *rating = _rating;

the_end:
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS outgoing_message_rating(
        PEP_SESSION session,
        message *msg,
        PEP_rating *rating
    )
{
    assert(session && msg && rating);
    if (!(session && msg && rating))
        return PEP_ILLEGAL_VALUE;

    if (msg->dir == PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    *rating = PEP_rating_undefined;

    PEP_rating _rating = PEP_rating_undefined;
    status = rating_sum(session, msg, rating_of_new_channel, &_rating);
    if (status)
        goto the_end;

    *rating = _rating;

the_end:
    return status;
}

DYNAMIC_API PEP_STATUS outgoing_message_rating_preview(
        PEP_SESSION session,
        message *msg,
        PEP_rating *rating
    )
{
    assert(session && msg && rating);
    if (!(session && msg && rating))
        return PEP_ILLEGAL_VALUE;

    if (msg->dir == PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    *rating = PEP_rating_undefined;

    PEP_rating _rating = PEP_rating_undefined;
    status = rating_sum(session, msg, last_rating_of_new_channel, &_rating);
    if (status)
        goto the_end;

    *rating = _rating;

the_end:
    return status;
}

DYNAMIC_API PEP_STATUS incoming_message_rating_for_identities(
        PEP_SESSION session,
        message *msg,
        PEP_rating *rating
    )
{
    assert(session && msg && msg->from && rating);
    if (!(session && msg && msg->from && rating))
        return PEP_ILLEGAL_VALUE;

    if (msg->dir != PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    *rating = PEP_rating_undefined;

    PEP_rating from_rating = rating_from_comm_type(msg->from->comm_type);
    if (!from_rating)
        goto the_end;

    PEP_rating _rating = PEP_rating_undefined;
    status = rating_sum(session, msg, rating_of_existing_channel, &_rating);
    if (status)
        goto the_end;

    *rating = add_rating(from_rating, _rating);

the_end:
    return status;
}

