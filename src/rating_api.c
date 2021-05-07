/**
 * @file    rating_api.c
 * @brief   implementation of rating functions
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */


#include "pEp_internal.h"
#include "rating_api.h"
#include "keymanagement.h"
#include "blacklist.h"
#include "baseprotocol.h"
#include "KeySync_fsm.h"
#include "sync_codec.h"

const char * rating_to_string(PEP_rating rating)
{
    switch (rating) {
    case PEP_rating_cannot_decrypt:
        return "cannot_decrypt";
    case PEP_rating_have_no_key:
        return "have_no_key";
    case PEP_rating_unencrypted:
        return "unencrypted";
    case PEP_rating_unreliable:
        return "unreliable";
    case PEP_rating_reliable:
        return "reliable";
    case PEP_rating_trusted:
        return "trusted";
    case PEP_rating_trusted_and_anonymized:
        return "trusted_and_anonymized";
    case PEP_rating_fully_anonymous:
        return "fully_anonymous";
    case PEP_rating_mistrust:
        return "mistrust";
    case PEP_rating_b0rken:
        return "b0rken";
    case PEP_rating_under_attack:
        return "under_attack";
    default:
        return "undefined";
    }
}

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

    PEP_STATUS status = PEP_STATUS_OK;
    if (ident->me)
        status = myself(session, ident);
    else
        status = update_identity(session, ident);
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
    if (stored_ident->comm_type == PEP_ct_unknown) {
        if (EMPTYSTR(stored_ident->fpr))
            stored_ident->comm_type = PEP_ct_key_not_found;
    }

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

    if (EMPTYSTR(ident->fpr)) {
        *rating = PEP_rating_have_no_key;
        return PEP_STATUS_OK;
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
        // if this is reliable then we could have green in case there is trust
        if (keyrating >= PEP_rating_reliable)
            keyrating = PEP_rating_trusted_and_anonymized;
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
    status = _rating_sum(session, msg->cc, channel_rating, &cc_rating);
    if (status)
        goto the_end;

    PEP_rating bcc_rating = PEP_rating_undefined;
    status = _rating_sum(session, msg->bcc, channel_rating, &bcc_rating);
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

static PEP_STATUS _blacklisted_key(PEP_SESSION session, const identity_list *il, bool *listed)
{
    for (const identity_list *_il = il; _il && _il->ident; _il = _il->next) {
        if (_il->ident->comm_type == PEP_ct_OpenPGP_unconfirmed || _il->ident->comm_type == PEP_ct_OpenPGP) {
            if (!EMPTYSTR(_il->ident->fpr)) {
                PEP_STATUS status = blacklist_is_listed(session, _il->ident->fpr, listed);
                if (status)
                    return status;
                if (*listed)
                    return PEP_STATUS_OK;
            }
        }
    }
    return PEP_STATUS_OK;
}

static PEP_STATUS has_blacklisted_key(PEP_SESSION session, const message *msg, bool *listed)
{
    PEP_STATUS status = _blacklisted_key(session, msg->to, listed);
    if (status)
        return status;
    if (*listed)
        return PEP_STATUS_OK;

    status = _blacklisted_key(session, msg->cc, listed);
    if (status)
        return status;
    if (*listed)
        return PEP_STATUS_OK;

    status = _blacklisted_key(session, msg->bcc, listed);
    if (status)
        return status;

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

    bool listed = false;
    status = has_blacklisted_key(session, msg, &listed);
    if (status)
        goto the_end;

    if (listed && _rating > PEP_rating_unencrypted)
        _rating = PEP_rating_unencrypted;

    *rating = (_rating == PEP_rating_have_no_key) ? PEP_rating_unencrypted : _rating;

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

    bool listed = false;
    status = has_blacklisted_key(session, msg, &listed);
    if (status)
        goto the_end;

    if (listed && _rating > PEP_rating_unencrypted)
        _rating = PEP_rating_unencrypted;

    *rating = (_rating == PEP_rating_have_no_key) ? PEP_rating_unencrypted : _rating;

the_end:
    return status;
}

static PEP_STATUS message_rating_for_identities(
        PEP_SESSION session,
        const message *msg,
        PEP_rating *rating
    )
{
    assert(session && msg && msg->from && rating);
    if (!(session && msg && msg->from && rating))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    *rating = PEP_rating_undefined;

    if (msg->dir == PEP_dir_incoming) {
        if (msg->from->me)
            status = myself(session, msg->from);
        else
            status = update_identity(session, msg->from);
    }
    else {
        status = myself(session, msg->from);
    }
    if (status)
        return status;

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

static PEP_STATUS sender_fpr_rating(
        PEP_SESSION session,
        pEp_identity *from,
        const char *sender_fpr,
        PEP_rating *rating
    )
{
    assert(session && rating);
    if (!(session && rating))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    PEP_rating _rating = PEP_rating_undefined;

    if (!from) {
        _rating = PEP_rating_unreliable;
    }
    else if (EMPTYSTR(sender_fpr)) {
        _rating = PEP_rating_unreliable;   
    }
    else {
        if (EMPTYSTR(from->user_id)) {
            if (from->me)
                status = myself(session, from);
            else
                status = update_identity(session, from);
            if (status)
                return status;
        }
        status = trust_between_user_and_key(session, from->user_id, sender_fpr, &_rating);
    }

    if (status)
        return status;

    *rating = _rating == PEP_rating_undefined ? PEP_rating_unreliable : _rating;
    return PEP_STATUS_OK;
}

static PEP_STATUS incoming_message_crypto_rating(
        PEP_SESSION session,
        const message *src,
        const message *dst,
        PEP_rating *rating
    )
{
    assert(session && src && rating);
    if (!(session && src && rating))
        return PEP_ILLEGAL_VALUE;

    if (src->dir != PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;

    if (src->enc_format != PEP_enc_none && !dst) {
        *rating = PEP_rating_cannot_decrypt;
        return PEP_STATUS_OK;
    }

    *rating = PEP_rating_undefined;
    PEP_rating enc_rating = PEP_rating_undefined;

    switch (src->enc_format) {
        case PEP_enc_none:
            enc_rating = PEP_rating_unencrypted;
            break;

        case PEP_enc_pieces:
        case PEP_enc_inline_EA:
            // if there are no attachments this can be trusted
            if (!(src->attachments && src->attachments->value))
                enc_rating = PEP_rating_trusted;
            // in case there are attachments then we cannot check reliability
            else
                enc_rating = PEP_rating_unreliable;
            break;

        case PEP_enc_S_MIME:
            // S/MIME is broken since efail, but we're polite
            enc_rating = PEP_rating_unreliable;
            break;

        case PEP_enc_PGP_MIME:
        case PEP_enc_PEP:
        case PEP_enc_PGP_MIME_Outlook1:
            // this can be trusted
            enc_rating = PEP_rating_trusted;
            break;

        default:
            return PEP_ILLEGAL_VALUE;
    }

    if (dst) {
        PEP_rating sender_rating = PEP_rating_undefined;
        PEP_STATUS status = sender_fpr_rating(session, src->from, dst->_sender_fpr, &sender_rating);
        if (status)
            return status;

        *rating = add_rating(enc_rating, sender_rating);
    }

    return PEP_STATUS_OK;
}

PEP_rating decrypt_rating(PEP_STATUS status)
{
    switch (status) {
    case PEP_UNENCRYPTED:
    case PEP_VERIFIED:
    case PEP_VERIFY_NO_KEY:
    case PEP_VERIFIED_AND_TRUSTED:
        return PEP_rating_unencrypted;

    case PEP_DECRYPTED:
    case PEP_VERIFY_SIGNER_KEY_REVOKED:
    case PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH:
    case PEP_VERFIY_DIFFERENT_KEYS:
        return PEP_rating_unreliable;

    case PEP_DECRYPTED_AND_VERIFIED:
    case PEP_STATUS_OK:
        return PEP_rating_trusted_and_anonymized;

    case PEP_DECRYPT_NO_KEY:
        return PEP_rating_have_no_key;

    case PEP_DECRYPT_WRONG_FORMAT:
    case PEP_CANNOT_DECRYPT_UNKNOWN:
        return PEP_rating_cannot_decrypt;

    default:
        return PEP_rating_undefined;
    }
}

static bool all_known_keys_are_legit(const message *dst,
        const stringlist_t *known_keys)
{
    if (!known_keys)
        return true;
    else if (!dst)
        return false;

    for (const stringlist_t *_nk = known_keys; _nk && !EMPTYSTR(_nk->value);
            _nk = _nk->next) {
        bool found = false;
        for (const identity_list *il = dst->to; il && il->ident;
                il = il->next) {
            if (!EMPTYSTR(il->ident->fpr) && stringlist_search(_nk, il->ident->fpr)) {
                found = true;
                break;
            }
        }
        if (found)
            continue;

        for (const identity_list *il = dst->cc; il && il->ident;
                il = il->next) {
            if (!EMPTYSTR(il->ident->fpr) && stringlist_search(_nk, il->ident->fpr)) {
                found = true;
                break;
            }
        }
        if (found)
            continue;
        else
            return false;
    }

    return true;
}

void replace_opt_field(message *msg,
                       const char *name, 
                       const char *value,
                       bool clobber);

PEP_STATUS get_receiverRating(PEP_SESSION session, message *msg, PEP_rating *rating)
{
    if (!(session && msg && rating))
        return PEP_ILLEGAL_VALUE;

    *rating = PEP_rating_undefined;

    size_t size;
    const char *payload;
    char *fpr;
    PEP_STATUS status = base_extract_message(session, msg, BASE_SYNC, &size, &payload, &fpr);
    if (status)
        return status;
    if (!fpr)
        return PEP_SYNC_NO_CHANNEL;

    bool own_key;
    status = is_own_key(session, fpr, &own_key);
    free(fpr);
    if (status)
        return status;
    if (!own_key)
        return PEP_SYNC_NO_CHANNEL;

    Sync_t *res;
    status = decode_Sync_message(payload, size, &res);
    if (status)
        return status;

    if (!(res->present == Sync_PR_keysync && res->choice.keysync.present == KeySync_PR_receiverRating)) {
        free_Sync_message(res);
        return PEP_SYNC_NO_CHANNEL;
    }

    *rating = res->choice.keysync.choice.receiverRating.rating;
    replace_opt_field(msg, "X-EncStatus", rating_to_string(*rating), true);
    return PEP_STATUS_OK;
}

static bool sync_message_attached(message *msg)
{
    if (!(msg && msg->attachments))
        return false;

    for (bloblist_t *a = msg->attachments; a && a->value ; a = a->next) {
        if (a->mime_type && strcasecmp(a->mime_type, "application/pEp.sync") == 0)
            return true;
    }

    return false;
}

PEP_STATUS set_receiverRating(PEP_SESSION session, message *msg, PEP_rating rating)
{
    if (!(session && msg && rating))
        return PEP_ILLEGAL_VALUE;

    if (!(msg->recv_by && msg->recv_by->fpr && msg->recv_by->fpr[0]))
        return PEP_SYNC_NO_CHANNEL;

    // don't add a second sync message
    if (sync_message_attached(msg))
        return PEP_STATUS_OK;

    Sync_t *res = new_Sync_message(Sync_PR_keysync, KeySync_PR_receiverRating);
    if (!res)
        return PEP_OUT_OF_MEMORY;

    res->choice.keysync.choice.receiverRating.rating = (Rating_t) rating;

    char *payload;
    size_t size;
    PEP_STATUS status = encode_Sync_message(res, &payload, &size);
    free_Sync_message(res);
    if (status)
        return status;

    return base_decorate_message(session, msg, BASE_SYNC, payload, size, msg->recv_by->fpr);
}

DYNAMIC_API PEP_STATUS incoming_message_rating(
        PEP_SESSION session,
        const message *src,
        const message *dst,
        const stringlist_t *known_keys,
        const stringpair_list_t *extra_keys,
        PEP_STATUS decrypt_status,
        PEP_rating *rating
    )
{
    assert(session && src && rating);
    if (!(session && src && rating))
        return PEP_ILLEGAL_VALUE;

    if (src->dir != PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;

    if (extra_keys && extra_keys->value) {
        if (EMPTYSTR(extra_keys->value->key) ||
                EMPTYSTR(extra_keys->value->value))
            return PEP_ILLEGAL_VALUE;
    }

    *rating = PEP_rating_undefined;
    PEP_rating _rating = decrypt_rating(decrypt_status);;

    if (!dst) {
        *rating = _rating;
        return PEP_STATUS_OK;
    }

    if (session->honor_extra_keys == PEP_honor_none) {
        if (extra_keys && extra_keys->value) {
            _rating = add_rating(_rating, PEP_rating_unreliable);
        }
        else if (known_keys && known_keys->value) {
            if (!all_known_keys_are_legit(dst, known_keys))
                _rating = add_rating(_rating, PEP_rating_unreliable);
        }
    }

    PEP_rating crypto_rating = PEP_rating_undefined;
    PEP_STATUS status = incoming_message_crypto_rating(session, src, dst,
            &crypto_rating);
    if (status)
        return status;
    _rating = add_rating(_rating, crypto_rating);

    if (dst) {
        PEP_rating identities_rating = PEP_rating_undefined;
        status = message_rating_for_identities(session, dst,
                &identities_rating);
        if (status)
            return status;
        _rating = add_rating(_rating, identities_rating);
    }

    *rating = _rating;
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS sent_message_rating(
        PEP_SESSION session,
        const message *src,
        const message *dst,
        const stringlist_t *known_keys,
        const stringpair_list_t *extra_keys,
        PEP_STATUS decrypt_status,
        PEP_rating *rating
    )
{
    assert(session && src && src->from && rating);
    if (!(session && src && src->from && rating))
        return PEP_ILLEGAL_VALUE;

    if (src->dir != PEP_dir_outgoing)
        return PEP_ILLEGAL_VALUE;

    if (extra_keys && extra_keys->value) {
        if (EMPTYSTR(extra_keys->value->key) ||
                EMPTYSTR(extra_keys->value->value))
            return PEP_ILLEGAL_VALUE;
    }

    *rating = PEP_rating_undefined;
    PEP_rating _rating = decrypt_rating(decrypt_status);;

    if (session->honor_extra_keys == PEP_honor_none) {
        if (extra_keys && extra_keys->value) {
            _rating = add_rating(_rating, PEP_rating_unreliable);
        }
        else if (known_keys && known_keys->value) {
            if (!all_known_keys_are_legit(dst, known_keys))
                _rating = add_rating(_rating, PEP_rating_unreliable);
        }
    }

    PEP_rating crypto_rating = PEP_rating_undefined;
    PEP_STATUS status = incoming_message_crypto_rating(session, src, dst,
            &crypto_rating);
    if (status)
        return status;
    _rating = add_rating(_rating, crypto_rating);

    if (dst) {
        PEP_rating identities_rating = PEP_rating_undefined;
        status = message_rating_for_identities(session, dst,
                &identities_rating);
        if (status)
            return status;
        _rating = add_rating(_rating, identities_rating);
    }

    *rating = _rating;
    return PEP_STATUS_OK;
}

