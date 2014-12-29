#include "message_api.h"
#include "keymanagement.h"

#include <libetpan/libetpan.h>
#include <assert.h>
#include <string.h>

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

    stringlist_t *_x;
    for (_x = extra; _x && _x->value; _x = _x->next) {
        if (stringlist_add(keys, _x->value) == NULL) {
            free_message(msg);
            free_stringlist(keys);
            return PEP_OUT_OF_MEMORY;
        }
    }
    
    identity_list * _il;
    for (_il = msg->to; _il && _il->ident; _il = _il->next) {
        status = update_identity(session, _il->ident);
        if (status != PEP_STATUS_OK) {
            free_message(msg);
            free_stringlist(keys);
            return status;
        }
        if (_il->ident->fpr) {
            if (stringlist_add(keys, _il->ident->fpr) == NULL) {
                free_message(msg);
                free_stringlist(keys);
                return PEP_OUT_OF_MEMORY;
            }
        }
        else
            status = PEP_KEY_NOT_FOUND;
    }

    int _own_keys = 1;
    if (extra)
        _own_keys += stringlist_length(extra);
    
    if (stringlist_length(keys) > _own_keys) {
        char *ptext;
        char *ctext = NULL;
        size_t csize = 0;

        switch (format) {
        case PEP_enc_MIME_multipart:
            break;

        case PEP_enc_pieces:
            if (src->shortmsg && src->longmsg) {
                ptext = calloc(1, strlen(src->shortmsg) + strlen(src->longmsg) + 12);
                if (ptext == NULL) {
                    free_message(msg);
                    free_stringlist(keys);
                    return PEP_OUT_OF_MEMORY;
                }
                strcpy(ptext, "subject: ");
                strcat(ptext, src->shortmsg);
                strcat(ptext, "\n\n");
                strcat(ptext, src->longmsg);
                status = encrypt_and_sign(session, keys, ptext, strlen(ptext), &ctext, &csize);
                if (ctext) {
                    msg->longmsg = ctext;
                    msg->longmsg_size = csize;
                    msg->shortmsg = strdup("pEp");
                }
                else {
                    free_message(msg);
                    msg = NULL;
                }
            }
            else if (src->shortmsg) {
                ptext = src->shortmsg;
                status = encrypt_and_sign(session, keys, ptext, strlen(ptext), &ctext, &csize);
                if (ctext) {
                    msg->shortmsg = ctext;
                    msg->shortmsg_size = csize;
                }
                else {
                    free_message(msg);
                    msg = NULL;
                }
            }
            else if (src->longmsg) {
                ptext = src->longmsg;
                status = encrypt_and_sign(session, keys, ptext, strlen(ptext), &ctext, &csize);
                if (ctext) {
                    msg->longmsg = ctext;
                    msg->longmsg_size = csize;
                    msg->shortmsg = strdup("pEp");
                }
                else {
                    free_message(msg);
                    msg = NULL;
                }
            }
            if (msg && msg->longmsg_formatted) {
                ptext = src->longmsg_formatted;
                status = encrypt_and_sign(session, keys, ptext, strlen(ptext), &ctext, &csize);
                if (ctext) {
                    msg->longmsg_formatted = ctext;
                    msg->longmsg_formatted_size = csize;
                }
                else {
                    free_message(msg);
                    msg = NULL;
                }
            }
            if (msg) {
                bloblist_t *_s;
                bloblist_t *_d = new_bloblist(NULL, 0);
                if (_d == NULL) {
                    free_message(msg);
                    free_stringlist(keys);
                    return PEP_OUT_OF_MEMORY;
                }
                msg->attachments = _d;
                for (_s = src->attachments; _s && _s->data_ref; _s = _s->next) {
                    int psize = _s->size;
                    ptext = _s->data_ref;
                    status = encrypt_and_sign(session, keys, ptext, psize, &ctext, &csize);
                    if (ctext) {
                        _d = bloblist_add(_d, ctext, csize);
                    }
                    else {
                        free_message(msg);
                        msg = NULL;
                        break;
                    }
                }
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

    return status;
}

