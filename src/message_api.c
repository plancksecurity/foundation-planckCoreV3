#include "message_api.h"
#include "keymanagement.h"

#include <libetpan/mailmime.h>
#ifndef mailmime_param_new_with_data
#include <libetpan/mailprivacy_tools.h>
#endif
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#define NOT_IMPLEMENTED assert(0);


DYNAMIC_API PEP_STATUS encrypt_message(
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
    assert(dst);
    *dst = NULL;
    assert(format != PEP_enc_none);

    pEp_identity *from = identity_dup(src->from);
    if (from == NULL)
        return PEP_OUT_OF_MEMORY;

    identity_list *to = identity_list_dup(src->to);
    if (to == NULL) {
        free_identity(from);
        return PEP_OUT_OF_MEMORY;
    }

    message *msg = new_message(src->dir, from, to, NULL);
    if (msg == NULL)
        return PEP_OUT_OF_MEMORY;
    msg->enc_format = PEP_enc_pieces;

    from->me = true;

    status = myself(session, from);
    if (status != PEP_STATUS_OK) {
        free_message(msg);
        return status;
    }

    stringlist_t * keys = new_stringlist(from->fpr);
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
    for (_il = to; _il && _il->ident; _il = _il->next) {
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
        msg->enc_format = PEP_enc_pieces;

        switch (format) {
        case PEP_enc_MIME_multipart: {
            message *interim;
//            status = mime_encode_parts(src, &interim);
//            assert(status == PEP_STATUS_OK);
//            if (status != PEP_STATUS_OK)
//                break;
            msg->enc_format = PEP_enc_MIME_multipart;
        }

        case PEP_enc_pieces:
            if (src->shortmsg && src->longmsg && strcmp(src->shortmsg, "pEp") != 0) {
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
                free(ptext);
                if (ctext) {
                    msg->longmsg = strdup(ctext);
                    msg->shortmsg = strdup("pEp");
                    if (!(msg->longmsg && msg->shortmsg)) {
                        free_message(msg);
                        return PEP_OUT_OF_MEMORY;
                    }
                }
                else {
                    free_message(msg);
                    msg = NULL;
                }
            }
            else if (src->shortmsg && strcmp(src->shortmsg, "pEp") != 0) {
                ptext = calloc(1, strlen(src->shortmsg) + 12);
                if (ptext == NULL) {
                    free_message(msg);
                    free_stringlist(keys);
                    return PEP_OUT_OF_MEMORY;
                }
                strcpy(ptext, "subject: ");
                strcat(ptext, src->shortmsg);
                strcat(ptext, "\n\n");
                status = encrypt_and_sign(session, keys, ptext, strlen(ptext),
                        &ctext, &csize);
                free(ptext);
                if (ctext) {
                    msg->longmsg = strdup(ctext);
                    msg->shortmsg = strdup("pEp");
                    if (!(msg->longmsg && msg->shortmsg)) {
                        free_message(msg);
                        return PEP_OUT_OF_MEMORY;
                    }
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
                    msg->longmsg = strdup(ctext);
                    msg->shortmsg = strdup("pEp");
                    if (!(msg->longmsg && msg->shortmsg)) {
                        free_message(msg);
                        return PEP_OUT_OF_MEMORY;
                    }
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
                    msg->longmsg_formatted = strdup(ctext);
                    if (msg->longmsg_formatted == NULL) {
                        free_message(msg);
                        return PEP_OUT_OF_MEMORY;
                    }
                }
                else {
                    free_message(msg);
                    msg = NULL;
                }
            }
            if (msg) {
                if (src->attachments) {
                    bloblist_t *_s;
                    bloblist_t *_d = new_bloblist(NULL, 0, NULL, NULL);
                    if (_d == NULL) {
                        free_message(msg);
                        free_stringlist(keys);
                        return PEP_OUT_OF_MEMORY;
                    }
                    msg->attachments = _d;
                    for (_s = src->attachments; _s && _s->data; _s = _s->next) {
                        int psize = _s->size;
                        ptext = _s->data;
                        status = encrypt_and_sign(session, keys, ptext, psize,
                                &ctext, &csize);
                        if (ctext) {
                            char * _c = strdup(ctext);
                            if (_c == NULL) {
                                free_message(msg);
                                free_stringlist(keys);
                                return PEP_OUT_OF_MEMORY;
                            }
                            _d = bloblist_add(_d, _c, csize, _s->mime_type,
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

DYNAMIC_API PEP_STATUS decrypt_message(
        PEP_SESSION session,
        const message *src,
        message **dst
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    NOT_IMPLEMENTED

    return status;
}

