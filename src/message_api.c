#include "message_api.h"
#include "keymanagement.h"
#include "mime.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#define NOT_IMPLEMENTED assert(0); return PEP_UNKNOWN_ERROR;

static char * combine_short_and_long(const message * src)
{
    char * ptext;
    char * longmsg;
    assert(src);
    assert(src->shortmsg && strcmp(src->shortmsg, "pEp") != 0);

    if (src->longmsg)
        longmsg = src->longmsg;
    else
        longmsg = "";

    ptext = calloc(1, strlen(src->shortmsg) + strlen(longmsg) + 12);
    if (ptext == NULL)
        return NULL;

    strcpy(ptext, "subject: ");
    strcat(ptext, src->shortmsg);
    strcat(ptext, "\n\n");
    strcat(ptext, longmsg);

    return ptext;
}

static message * clone_empty_message(const message * src)
{
    pEp_identity *from = NULL;
    identity_list *to = NULL;
    message * msg = NULL;

    from = identity_dup(src->from);
    assert(from);
    if (from == NULL)
        goto enomem;

    from->me = true;

    to = identity_list_dup(src->to);
    assert(to);
    if (to == NULL)
        goto enomem;

    msg = new_message(src->dir, from, to, NULL);
    assert(msg);
    if (msg == NULL)
        goto enomem;

    return msg;

enomem:
    free_identity(from);
    free_identity_list(to);
    return NULL;
}

DYNAMIC_API PEP_STATUS encrypt_message(
        PEP_SESSION session,
        const message *src,
        stringlist_t * extra,
        message **dst,
        PEP_enc_format format
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    message * msg = NULL;
    stringlist_t * keys = NULL;

    assert(session);
    assert(src);
    assert(dst);
    *dst = NULL;
    assert(format != PEP_enc_none && format != PEP_enc_none_MIME);

    // TODO: we don't yet support re-encrypting already encrypted messages
    if ((int) src->format >= (int) PEP_enc_pieces) {
        NOT_IMPLEMENTED   
    }

    msg = clone_empty_message(src);
    if (msg == NULL)
        goto enomem;

    msg->enc_format = PEP_enc_pieces;

    status = myself(session, src->from);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    keys = new_stringlist(src->from->fpr);
    if (keys == NULL)
        goto enomem;

    stringlist_t *_k = keys;

    if (extra) {
        _k = stringlist_append(_k, extra);
        if (_k == NULL)
            goto enomem;
    }

    bool dest_keys_found = false;
    identity_list * _il;
    for (_il = msg->to; _il && _il->ident; _il = _il->next) {
        PEP_STATUS status = update_identity(session, _il->ident);
        if (status != PEP_STATUS_OK)
            goto pep_error;

        if (_il->ident->fpr) {
            dest_keys_found = true;
            _k = stringlist_add(_k, _il->ident->fpr);
            if (_k == NULL)
                goto enomem;
        }
        else
            status = PEP_KEY_NOT_FOUND;
    }

    if (dest_keys_found) {
        char *ptext;
        char *ctext = NULL;
        size_t csize = 0;

        switch (format) {
        case PEP_enc_MIME_multipart: {
            bool free_ptext = false;

            msg->enc_format = PEP_enc_MIME_multipart;

            if (src->shortmsg && strcmp(src->shortmsg, "pEp") != 0) {
                ptext = combine_short_and_long(src);
                if (ptext == NULL)
                    goto enomem;
                free_ptext = true;
            }
            else if (src->longmsg) {
                ptext = src->longmsg;
            }

            if (src->format == PEP_enc_none) {
                char *_ptext = ptext;
                status = mime_encode_text(_ptext, src->longmsg_formatted,
                        src->attachments, &ptext);
                assert(status == PEP_STATUS_OK);
                if (free_ptext)
                    free(_ptext);
                assert(ptext);
                if (ptext == NULL)
                    goto pep_error;
                free_ptext = true;
            }
            else if (src->format == PEP_enc_none_MIME) {
                assert(src->longmsg);
                if (src->longmsg == NULL) {
                    status = PEP_ILLEGAL_VALUE;
                    goto pep_error;
                }
                ptext = src->longmsg;
            }

            status = encrypt_and_sign(session, keys, ptext, strlen(ptext),
                    &ctext, &csize);
            if (free_ptext)
                free(ptext);
            if (ctext) {
                msg->longmsg = strdup(ctext);
                if (msg->longmsg == NULL)
                    goto enomem;
            }
            else {
                goto pep_error;
            }
        }
        break;

        case PEP_enc_pieces:
            msg->enc_format = PEP_enc_pieces;

            // TODO: decoding MIME
            if (src->format == PEP_enc_none_MIME) {
                NOT_IMPLEMENTED
            }

            if (src->shortmsg && strcmp(src->shortmsg, "pEp") != 0) {
                ptext = combine_short_and_long(src);
                if (ptext == NULL)
                    goto enomem;

                status = encrypt_and_sign(session, keys, ptext, strlen(ptext),
                        &ctext, &csize);
                free(ptext);
                if (ctext) {
                    msg->longmsg = strdup(ctext);
                    if (msg->longmsg == NULL)
                        goto enomem;
                }
                else {
                    goto pep_error;
                }
            }
            else if (src->longmsg) {
                ptext = src->longmsg;
                status = encrypt_and_sign(session, keys, ptext, strlen(ptext),
                        &ctext, &csize);
                if (ctext) {
                    msg->longmsg = strdup(ctext);
                    if (msg->longmsg == NULL)
                        goto enomem;
                }
                else {
                    goto pep_error;
                }
            }

            if (msg->longmsg_formatted) {
                ptext = src->longmsg_formatted;
                status = encrypt_and_sign(session, keys, ptext, strlen(ptext),
                        &ctext, &csize);
                if (ctext) {
                    msg->longmsg_formatted = strdup(ctext);
                    if (msg->longmsg_formatted == NULL)
                        goto enomem;
                }
                else {
                    goto pep_error;
                }
            }

            if (src->attachments) {
                bloblist_t *_s;
                bloblist_t *_d = new_bloblist(NULL, 0, NULL, NULL);
                if (_d == NULL)
                    goto enomem;

                msg->attachments = _d;
                for (_s = src->attachments; _s && _s->data; _s = _s->next) {
                    int psize = _s->size;
                    ptext = _s->data;
                    status = encrypt_and_sign(session, keys, ptext, psize,
                            &ctext, &csize);
                    if (ctext) {
                        char * _c = strdup(ctext);
                        if (_c == NULL)
                            goto enomem;

                        _d = bloblist_add(_d, _c, csize, _s->mime_type,
                                _s->file_name);
                        if (_d == NULL)
                            goto enomem;
                    }
                    else {
                        goto pep_error;
                    }
                }
            }
            break;

        default:
            assert(0);
            status = PEP_ILLEGAL_VALUE;
            goto pep_error;
        }
    }

    free_stringlist(keys);

    if (msg->shortmsg == NULL)
        msg->shortmsg = strdup("pEp");

    *dst = msg;
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free_stringlist(keys);
    free_message(msg);

    return status;
}

DYNAMIC_API PEP_STATUS decrypt_message(
        PEP_SESSION session,
        const message *src,
        message **dst
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    message *msg = NULL;

    assert(session);
    assert(src);
    assert(dst);

    *dst = NULL;
    
    // msg = new_message(src->dir, from, to, NULL);
    NOT_IMPLEMENTED

    *dst = msg;
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free_message(msg);

    return status;
}

