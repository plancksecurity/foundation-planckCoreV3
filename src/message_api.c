#include "message_api.h"
#include "keymanagement.h"

#include <libetpan/libetpan.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#define NOT_IMPLEMENTED assert(0);

PEP_STATUS encrypt_message(
        PEP_SESSION session,
        const message *src,
        stringlist_t * extra,
        message **dst,
        PEP_enc_format format
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(src);
    assert(src->shortmsg || src->longmsg);
    assert(dst);
    *dst = NULL;
    assert(format != PEP_enc_none);

    message *msg = new_message(src->dir, src->from, src->to, NULL);
    if (msg == NULL)
        return PEP_OUT_OF_MEMORY;

    msg->from->me = true;

    status = myself(session, msg->from);
    if (status != PEP_STATUS_OK) {
        free_message(msg);
        return status;
    }

    stringlist_t * keys = new_stringlist(msg->from->fpr);
    if (keys == NULL) {
        free_message(msg);
        return PEP_OUT_OF_MEMORY;
    }

    stringlist_t *_k = keys;

    if (extra) {
        _k = stringlist_append(_k, extra);
        if (_k == NULL) {
            free_stringlist(keys);
            free_message(msg);
            return PEP_OUT_OF_MEMORY;
        }
    }

    bool dest_keys_found = false;
    identity_list * _il;
    for (_il = msg->to; _il && _il->ident; _il = _il->next) {
        PEP_STATUS _status = update_identity(session, _il->ident);
        if (_status != PEP_STATUS_OK) {
            free_message(msg);
            free_stringlist(keys);
            return _status;
        }
        if (_il->ident->fpr) {
            dest_keys_found = true;
            _k = stringlist_add(_k, _il->ident->fpr);
            if (_k == NULL) {
                free_message(msg);
                free_stringlist(keys);
                return PEP_OUT_OF_MEMORY;
            }
        }
        else
            status = PEP_KEY_NOT_FOUND;
    }

    if (dest_keys_found) {
        char *ptext;
        char *ctext = NULL;
        size_t csize = 0;

        switch (format) {
        case PEP_enc_MIME_multipart:
            NOT_IMPLEMENTED
            break;

        case PEP_enc_pieces:
            if (src->shortmsg && src->longmsg) {
                ptext = calloc(1, strlen(src->shortmsg) + strlen(src->longmsg)
                        + 12);
                if (ptext == NULL) {
                    free_message(msg);
                    free_stringlist(keys);
                    return PEP_OUT_OF_MEMORY;
                }
                strcpy(ptext, "subject: ");
                strcat(ptext, src->shortmsg);
                strcat(ptext, "\n\n");
                strcat(ptext, src->longmsg);
                status = encrypt_and_sign(session, keys, ptext, strlen(ptext),
                        &ctext, &csize);
                if (ctext) {
                    msg->longmsg = ctext;
                    msg->shortmsg = strdup("pEp");
                }
                else {
                    free_message(msg);
                    msg = NULL;
                }
            }
            else if (src->shortmsg) {
                ptext = src->shortmsg;
                status = encrypt_and_sign(session, keys, ptext, strlen(ptext),
                        &ctext, &csize);
                if (ctext) {
                    msg->shortmsg = ctext;
                }
                else {
                    free_message(msg);
                    msg = NULL;
                }
            }
            else if (src->longmsg) {
                ptext = src->longmsg;
                status = encrypt_and_sign(session, keys, ptext, strlen(ptext),
                        &ctext, &csize);
                if (ctext) {
                    msg->longmsg = ctext;
                    msg->shortmsg = strdup("pEp");
                }
                else {
                    free_message(msg);
                    msg = NULL;
                }
            }
            if (msg && msg->longmsg_formatted) {
                ptext = src->longmsg_formatted;
                status = encrypt_and_sign(session, keys, ptext, strlen(ptext),
                        &ctext, &csize);
                if (ctext) {
                    msg->longmsg_formatted = ctext;
                }
                else {
                    free_message(msg);
                    msg = NULL;
                }
            }
            if (msg) {
                bloblist_t *_s;
                bloblist_t *_d = new_bloblist(NULL, 0, NULL, NULL);
                if (_d == NULL) {
                    free_message(msg);
                    free_stringlist(keys);
                    return PEP_OUT_OF_MEMORY;
                }
                msg->attachments = _d;
                for (_s = src->attachments; _s && _s->data_ref; _s = _s->next) {
                    int psize = _s->size;
                    ptext = _s->data_ref;
                    status = encrypt_and_sign(session, keys, ptext, psize,
                            &ctext, &csize);
                    if (ctext) {
                        _d = bloblist_add(_d, ctext, csize, _s->mime_type,
                                _s->file_name);
                        if (_d == NULL) {
                            free_message(msg);
                            free_stringlist(keys);
                            return PEP_OUT_OF_MEMORY;
                        }
                    }
                    else {
                        free_message(msg);
                        msg = NULL;
                        break;
                    }
                }
                msg->enc_format = PEP_enc_pieces;
                *dst = msg;
            }
            break;

        default:
            assert(0);
        }
    }
    else
        free_message(msg);

    free_stringlist(keys);
    return status;
}

PEP_STATUS decrypt_message(
        PEP_SESSION session,
        const message *src,
        message **dst
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    NOT_IMPLEMENTED

    return status;
}

