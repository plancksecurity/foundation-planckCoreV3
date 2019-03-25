// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "message_api.h"

PEP_STATUS base_decorate_message(
        PEP_SESSION session,
        message *msg,
        char *payload,
        size_t size,
        const char *fpr,
        stringlist_t **keys
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(msg);
    assert(payload);
    assert(size);

    if (!(msg && payload && size))
        return PEP_ILLEGAL_VALUE;

    bloblist_t *bl = bloblist_add(msg->attachments, payload, size,
            "application/pEp.sync", "ignore_this_attachment.pEp");
    if (bl == NULL)
        goto enomem;
    else if (!msg->attachments) {
        msg->attachments = bl;
    }

    if (fpr) {
        char *sign;
        size_t sign_size;
        status = sign_only(session,  payload, size, fpr, &sign, &sign_size);
        if (status)
            goto error;

        assert(sign && sign_size);

        bl = bloblist_add(bl, sign, sign_size,
                "application/pEp.sign", "electronic_signature.asc");
        if (!bl)
            goto enomem;
    }

    if (keys) {
        size_t size = 1;
        for (stringlist_t *sl = *keys; sl && sl->value; sl = sl->next) {
            size += strlen(sl->value);
        }

        char *_keys = calloc(1, size);
        if (!_keys)
            goto enomem;

        char *_k = _keys;
        for (stringlist_t *sl = *keys; sl && sl->value; sl = sl->next) {
            strcpy(_k, sl->value);
            _k += strlen(sl->value);
        }

        bl = bloblist_add(bl, _keys, size, "application/pgp-keys", "keys.asc");
        if (!bl)
            status = PEP_OUT_OF_MEMORY;

        free(_keys);
        free_stringlist(*keys);
        *keys = NULL;
    }

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;

error:
    return status;
}

PEP_STATUS base_prepare_message(
        PEP_SESSION session,
        const pEp_identity *me,
        const pEp_identity *partner,
        char *payload,
        size_t size,
        const char *fpr,
        stringlist_t **keys,
        message **result
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(me);
    assert(partner);
    assert(payload);
    assert(size);
    assert(result);

    if (!(me && partner && payload && size && result))
        return PEP_ILLEGAL_VALUE;

    *result = NULL;

    message *msg = new_message(PEP_dir_outgoing);
    if (!msg)
        goto enomem;

    add_opt_field(msg, "pEp-auto-consume", "yes");

    msg->from = identity_dup(me);
    if (!msg->from)
        goto enomem;

    msg->to = new_identity_list(identity_dup(partner));
    if (!msg->to)
        goto enomem;

    msg->shortmsg = strdup("p≡p synchronization message - please ignore");
    assert(msg->shortmsg);
    if (!msg->shortmsg)
        goto enomem;

    msg->longmsg = strdup("This message is part of p≡p's concept to synchronize.\n\n"
                        "You can safely ignore it. It will be deleted automatically.\n");
    assert(msg->longmsg);
    if (!msg->longmsg)
        goto enomem;

    status = base_decorate_message(session, msg, payload, size, fpr, keys);
    if (status == PEP_STATUS_OK)
        *result = msg;
    return status;

enomem:
    free_message(msg);
    return PEP_OUT_OF_MEMORY;
}

PEP_STATUS base_extract_message(
        PEP_SESSION session,
        message *msg,
        size_t *size,
        const char **payload,
        char **fpr
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session && msg && size && payload && fpr);
    if (!(session && msg && size && payload && fpr))
        return PEP_ILLEGAL_VALUE;

    *size = 0;
    *payload = NULL;
    *fpr = NULL;

    const char *_payload = NULL;
    size_t _payload_size = 0;
    const char *_sign = NULL;
    size_t _sign_size = 0;
    stringlist_t *keylist = NULL;

    for (bloblist_t *bl = msg->attachments; bl ; bl = bl->next) {
        if (bl->mime_type && strcasecmp(bl->mime_type, "application/pEp.sync") == 0) {
            if (!_payload) {
                _payload = bl->value;
                _payload_size = bl->size;
            }
            else {
                status = PEP_DECRYPT_WRONG_FORMAT;
                goto the_end;
            }
        }
        else if (bl->mime_type && strcasecmp(bl->mime_type, "application/pEp.sign") == 0) {
            if (!_sign) {
                _sign = bl->value;
                _sign_size = bl->size;
            }
            else {
                status = PEP_DECRYPT_WRONG_FORMAT;
                goto the_end;
            }
        }
    }
    
    if (!(_payload && _payload_size))
        goto the_end;

    char *_fpr = NULL;
    if (_sign) {
        status = verify_text(session, _payload, _payload_size, _sign, _sign_size, &keylist);
        if (status != PEP_VERIFIED || !keylist || !keylist->value) {
            // signature invalid or does not match; ignore sync message
            status = PEP_STATUS_OK;
            goto the_end;
        }

        _fpr = strdup(keylist->value);
        assert(_fpr);
        if (!_fpr) {
            status = PEP_OUT_OF_MEMORY;
            goto the_end;
        }
    }

    *size = _payload_size;
    *payload = _payload;
    *fpr = _fpr;
    status = PEP_STATUS_OK;

the_end:
    free_stringlist(keylist);
    return status;
}

