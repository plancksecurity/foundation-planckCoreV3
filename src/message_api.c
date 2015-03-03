#include "message_api.h"
#include "keymanagement.h"
#include "mime.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#define NOT_IMPLEMENTED assert(0); return PEP_UNKNOWN_ERROR;

static char * combine_short_and_long(const char *shortmsg, const char *longmsg)
{
    char * ptext;

    assert(shortmsg);
    assert(strcmp(shortmsg, "pEp") != 0);

    if (longmsg == NULL)
        longmsg = "";

    ptext = calloc(1, strlen(shortmsg) + strlen(longmsg) + 12);
    if (ptext == NULL)
        return NULL;

    strcpy(ptext, "subject: ");
    strcat(ptext, shortmsg);
    strcat(ptext, "\n\n");
    strcat(ptext, longmsg);

    return ptext;
}

static int seperate_short_and_long(const char *src, char **shortmsg, char **longmsg)
{
    char *_shortmsg = NULL;
    char *_longmsg = NULL;

    assert(src);
    assert(shortmsg);
    assert(longmsg);

    *shortmsg = NULL;
    *longmsg = NULL;

    if (strncmp(src, "subject: ", 9) == 0) {
        char *line_end = strchr(src, '\n');
        
        if (line_end == NULL) {
            _shortmsg = strdup(src + 9);
            if (_shortmsg == NULL)
                goto enomem;
            // _longmsg = NULL;
        }
        else {
            size_t n = line_end - src;
            if (*(line_end - 1) == '\r')
                _shortmsg = strndup(src + 9, n - 1);
            else
                _shortmsg = strndup(src + 9, n);
            if (_shortmsg == NULL)
                goto enomem;
            _longmsg = strdup(src + n);
            if (_longmsg == NULL)
                goto enomem;
        }
    }
    else {
        _shortmsg = strdup("pEp");
        if (_shortmsg == NULL)
            goto enomem;
        _longmsg = strdup(src);
        if (_longmsg == NULL)
            goto enomem;
    }
    
    *shortmsg = _shortmsg;
    *longmsg = _longmsg;

    return 0;

enomem:
    free(_shortmsg);
    free(_longmsg);

    return -1;
}

static message * clone_to_empty_message(const message * src)
{
    pEp_identity *from = NULL;
    identity_list *to = NULL;

    message * msg = NULL;

    assert(src);
    assert(src->from);
    assert(src->to);

    from = identity_dup(src->from);
    if (from == NULL)
        goto enomem;

    from->me = true;

    to = identity_list_dup(src->to);
    if (to == NULL)
        goto enomem;

    msg = new_message(src->dir, from, to, NULL);
    if (msg == NULL)
        goto enomem;

    msg->dir = src->dir;

    if (src->cc) {
        msg->cc = identity_list_dup(src->cc);
        if (msg->cc == NULL)
            goto enomem;
    }

    if (src->bcc) {
        msg->bcc = identity_list_dup(src->bcc);
        if (msg->bcc == NULL)
            goto enomem;
    }

    if (src->reply_to) {
        msg->reply_to = identity_dup(src->reply_to);
        if (msg->reply_to == NULL)
            goto enomem;
    }

    msg->sent = src->sent;
    msg->recv = src->recv;

    return msg;

enomem:
    if (msg) {
        free_message(msg);
    }
    else {
        free_identity(from);
        free_identity_list(to);
    }

    return NULL;
}

DYNAMIC_API PEP_STATUS encrypt_message(
        PEP_SESSION session,
        const message *src,
        stringlist_t * extra,
        message **dst,
        PEP_enc_format enc_format
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    message * msg = NULL;
    stringlist_t * keys = NULL;

    assert(session);
    assert(src);
    assert(dst);
    assert(enc_format >= PEP_enc_pieces);

    *dst = NULL;

    if (src->enc_format >= PEP_enc_pieces) {
        if (src->enc_format == enc_format) {
            msg = message_dup(src);
            if (msg == NULL)
                goto enomem;
            *dst = msg;
            return PEP_STATUS_OK;
        }
        else {
            // TODO: we don't re-encrypt yet
            NOT_IMPLEMENTED
        }
    }

    msg = clone_to_empty_message(src);
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

        switch (enc_format) {
        case PEP_enc_MIME_multipart: {
            bool free_ptext = false;

            msg->enc_format = PEP_enc_MIME_multipart;

            if (src->shortmsg && strcmp(src->shortmsg, "pEp") != 0) {
                ptext = combine_short_and_long(src->shortmsg, src->longmsg);
                if (ptext == NULL)
                    goto enomem;
                free_ptext = true;
            }
            else if (src->longmsg) {
                ptext = src->longmsg;
            }

            if (src->enc_format == PEP_enc_none) {
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
            else if (src->enc_format == PEP_enc_none_MIME) {
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
            if (src->enc_format == PEP_enc_none_MIME) {
                NOT_IMPLEMENTED
            }

            if (src->shortmsg && strcmp(src->shortmsg, "pEp") != 0) {
                ptext = combine_short_and_long(src->shortmsg, src->longmsg);
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

        case PEP_enc_PEP:
            // TODO: implement
            NOT_IMPLEMENTED

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
        message **dst,
        PEP_enc_format enc_format
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    message *msg = NULL;

    assert(session);
    assert(src);
    assert(src->dir == PEP_dir_incoming);
    assert(dst);
    assert(enc_format < PEP_enc_pieces);

    *dst = NULL;
 
    if (src->enc_format < PEP_enc_pieces) {
        if (enc_format == src->enc_format) {
            msg = message_dup(src);
            if (msg == NULL)
                goto enomem;
            *dst = msg;
            return PEP_STATUS_OK;
        }
        else {
            // TODO: we don't re-encode yet
            NOT_IMPLEMENTED
        }
    }

    msg = clone_to_empty_message(src);
    if (msg == NULL)
        goto enomem;

    switch (enc_format) {
        case PEP_enc_none:
            if (src->enc_format == PEP_enc_PEP) {
                // TODO: implement
                NOT_IMPLEMENTED
            }

            break;

        case PEP_enc_none_MIME:
            if (src->enc_format == PEP_enc_PEP) {
                // TODO: implement
                NOT_IMPLEMENTED
            }

            char *ctext = src->longmsg;
            size_t csize = strlen(src->longmsg);
            char *ptext;
            size_t psize;
            stringlist_t *keylist;

            status = decrypt_and_verify(session, ctext, csize, &ptext, &psize,
                    &keylist);
            if (ptext == NULL)
                goto pep_error;

            if (src->enc_format == PEP_enc_MIME_multipart) {
                if (src->shortmsg == NULL || strcmp(src->shortmsg, "pEp") == 0)
                {
                    char * shortmsg;
                    char * longmsg;

                    int r = seperate_short_and_long(ptext, &shortmsg,
                            &longmsg);
                    free(ptext);
                    if (r == -1)
                        goto enomem;

                    msg->shortmsg = shortmsg;
                    msg->longmsg = longmsg;
                }
                else {
                    msg->shortmsg = strdup(src->shortmsg);
                    if (msg->shortmsg == NULL)
                        goto enomem;
                    msg->longmsg = ptext;
                }
            }
            else {
                
            }
            break;

        default:
            assert(0);
            status = PEP_ILLEGAL_VALUE;
            goto pep_error;
    }

    *dst = msg;
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free_message(msg);

    return status;
}

