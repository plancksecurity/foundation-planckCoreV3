#include "pEp_internal.h"
#include "message_api.h"

#include "platform.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

static char * combine_short_and_long(const char *shortmsg, const char *longmsg)
{
    char * ptext;

    assert(shortmsg);
    assert(strcmp(shortmsg, "pEp") != 0);

    if (longmsg == NULL)
        longmsg = "";

    ptext = calloc(1, strlen(shortmsg) + strlen(longmsg) + 12);
    assert(ptext);
    if (ptext == NULL)
        return NULL;

    strcpy(ptext, "Subject: ");
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

    if (strncasecmp(src, "subject: ", 9) == 0) {
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
        _shortmsg = strdup("");
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

static PEP_STATUS copy_fields(message *dst, const message *src)
{
    assert(dst);
    assert(src);

    free_timestamp(dst->sent);
    dst->sent = NULL;
    if (src->sent) {
        dst->sent = timestamp_dup(src->sent);
        if (dst->sent == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_timestamp(dst->recv);
    dst->recv = NULL;
    if (src->recv) {
        dst->recv = timestamp_dup(src->recv);
        if (dst->recv == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_identity(dst->from);
    dst->from = NULL;
    if (src->from) {
        dst->from = identity_dup(src->from);
        if (dst->from == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_identity_list(dst->to);
    dst->to = NULL;
    if (src->to) {
        dst->to = identity_list_dup(src->to);
        if (dst->to == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_identity(dst->recv_by);
    dst->recv_by = NULL;
    if (src->recv_by) {
        dst->recv_by = identity_dup(src->recv_by);
        if (dst->recv_by == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_identity_list(dst->cc);
    dst->cc = NULL;
    if (src->cc) {
        dst->cc = identity_list_dup(src->cc);
        if (dst->cc == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_identity_list(dst->bcc);
    dst->bcc = NULL;
    if (src->bcc) {
        dst->bcc = identity_list_dup(src->bcc);
        if (dst->bcc == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_identity_list(dst->reply_to);
    dst->reply_to = NULL;
    if (src->reply_to) {
        dst->reply_to = identity_list_dup(src->reply_to);
        if (dst->reply_to == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_stringlist(dst->in_reply_to);
    dst->in_reply_to = NULL;
    if (src->in_reply_to) {
        dst->in_reply_to = stringlist_dup(src->in_reply_to);
        if (dst->in_reply_to == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_stringlist(dst->references);
    dst->references = NULL;
    if (src->references) {
        dst->references = stringlist_dup(src->references);
        if (dst->references == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_stringlist(dst->keywords);
    dst->keywords = NULL;
    if (src->keywords) {
        dst->keywords = stringlist_dup(src->keywords);
        if (dst->keywords == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free(dst->comments);
    dst->comments = NULL;
    if (src->comments) {
        dst->comments = strdup(src->comments);
        assert(dst->comments);
        if (dst->comments == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    return PEP_STATUS_OK;
}

static message * clone_to_empty_message(const message * src)
{
    PEP_STATUS status;
    message * msg = NULL;

    assert(src);

    msg = calloc(1, sizeof(message));
    assert(msg);
    if (msg == NULL)
        goto enomem;

    msg->dir = src->dir;

    status = copy_fields(msg, src);
    if (status != PEP_STATUS_OK)
        goto enomem;

    return msg;

enomem:
    free_message(msg);
    return NULL;
}

DYNAMIC_API PEP_STATUS encrypt_message(
        PEP_SESSION session,
        message *src,
        stringlist_t * extra,
        message **dst,
        PEP_enc_format enc_format
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    message * msg = NULL;
    stringlist_t * keys = NULL;
    bool free_src = false;

    assert(session);
    assert(src);
    assert(dst);
    assert(enc_format >= PEP_enc_pieces);

    *dst = NULL;

    if (src->enc_format >= PEP_enc_pieces) {
        if (src->enc_format == enc_format) {
            assert(0); // the message is encrypted this way already
            msg = message_dup(src);
            if (msg == NULL)
                goto enomem;
            *dst = msg;
            return PEP_STATUS_OK;
        }
        else {
            // decrypt and re-encrypt again
            message * _dst = NULL;
            PEP_MIME_format mime = (enc_format == PEP_enc_PEP) ? PEP_MIME :
                    PEP_MIME_fields_omitted;

            status = decrypt_message(session, src, mime, &_dst);
            if (status != PEP_STATUS_OK)
                goto pep_error;

            src = _dst;
            free_src = true;
        }
    }

    msg = clone_to_empty_message(src);
    if (msg == NULL)
        goto enomem;

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
        case PEP_enc_PGP_MIME: {
            bool free_ptext = false;

            msg->enc_format = PEP_enc_PGP_MIME;

            if (src->mime == PEP_MIME) {
                message *_src = NULL;
                assert(src->longmsg);
                status = mime_decode_message(src->longmsg, &_src);
                if (status != PEP_STATUS_OK)
                    goto pep_error;
                if (free_src)
                    free_message(src);
                src = _src;
                free_src = true;
            }

            if (src->mime == PEP_MIME_none) {
                if (src->shortmsg && strcmp(src->shortmsg, "pEp") != 0) {
                    ptext = combine_short_and_long(src->shortmsg, src->longmsg);
                    if (ptext == NULL)
                        goto enomem;
                    free_ptext = true;
                }
                else if (src->longmsg) {
                    ptext = src->longmsg;
                }
                else {
                    ptext = "pEp";
                }

                message *_src = calloc(1, sizeof(message));
                assert(_src);
                if (_src == NULL)
                    goto enomem;
                _src->longmsg = ptext;
                _src->longmsg_formatted = src->longmsg_formatted;
                _src->attachments = src->attachments;
                _src->enc_format = PEP_enc_PGP_MIME;
                status = mime_encode_message(_src, true, &ptext);
                assert(status == PEP_STATUS_OK);
                if (free_ptext)
                    free(_src->longmsg);
                free(_src);
                assert(ptext);
                if (ptext == NULL)
                    goto pep_error;
                free_ptext = true;
            }
            else /* if (src->mime == PEP_MIME_fields_omitted) */ {
                ptext = src->longmsg;
            }

            status = encrypt_and_sign(session, keys, ptext, strlen(ptext),
                    &ctext, &csize);
            if (free_ptext)
                free(ptext);
            if (ctext == NULL)
                goto pep_error;

            msg->longmsg = strdup(ctext);
            if (msg->longmsg == NULL)
                goto enomem;
        }
        break;

        case PEP_enc_pieces:
            msg->enc_format = PEP_enc_pieces;

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
                                _s->filename);
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
    if (free_src)
        free_message(src);

    if (msg->shortmsg == NULL)
        msg->shortmsg = strdup("pEp");

    *dst = msg;
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free_stringlist(keys);
    free_message(msg);
    if (free_src)
        free_message(src);

    return status;
}

static bool is_encrypted_attachment(const bloblist_t *blob)
{
    char *ext;
 
    assert(blob);

    if (blob->filename == NULL)
        return false;

    ext = strrchr(blob->filename, '.');
    if (ext == NULL)
        return false;

    if (strcmp(blob->mime_type, "application/octet-stream")) {
        if (strcmp(ext, ".pgp") == 0 || strcmp(ext, ".gpg") == 0 ||
                strcmp(ext, ".asc") == 0)
            return true;
    }
    else if (strcmp(blob->mime_type, "text/plain")) {
        if (strcmp(ext, ".asc") == 0)
            return true;
    }

    return false;
}

static bool is_encrypted_html_attachment(const bloblist_t *blob)
{
    assert(blob);
    assert(blob->filename);

    if (strncmp(blob->filename, "PGPexch.htm.", 12) == 0) {
        if (strcmp(blob->filename + 11, ".pgp") == 0 ||
                strcmp(blob->filename + 11, ".asc") == 0)
            return true;
    }

    return false;
}

static char * without_double_ending(const char *filename)
{
    char *ext;

    assert(filename);

    ext = strrchr(filename, '.');
    if (ext == NULL)
        return NULL;

    return strndup(filename, ext - filename);
}

DYNAMIC_API PEP_STATUS decrypt_message(
        PEP_SESSION session,
        message *src,
        PEP_MIME_format mime,
        message **dst
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    message *msg = NULL;
    char *ctext;
    size_t csize;
    char *ptext;
    size_t psize;
    stringlist_t *keylist;
    bool free_src = false;

    assert(session);
    assert(src);
    assert(dst);

    *dst = NULL;
 
    if (src->mime == PEP_MIME_fields_omitted || src->mime == PEP_MIME) {
        message *_src = NULL;
        status = mime_decode_message(src->longmsg, &_src);
        if (status != PEP_STATUS_OK)
            goto pep_error;

        if ( src->mime == PEP_MIME_fields_omitted) {
            status = copy_fields(_src, src);
            if (status != PEP_STATUS_OK) {
                free_message(_src);
                goto pep_error;
            }
        }

        src = _src;
        free_src = true;
    }

    // src message is not MIME encoded (any more)
    assert(src->mime == PEP_MIME_none);

    if (!is_PGP_message_text(src->longmsg)) {
        status = PEP_UNENCRYPTED;
        goto pep_error;
    }

    ctext = src->longmsg;
    csize = strlen(src->longmsg);

    status = decrypt_and_verify(session, ctext, csize, &ptext, &psize,
            &keylist);
    if (ptext == NULL)
        goto pep_error;

    switch (src->enc_format) {
        case PEP_enc_PGP_MIME:
            status = mime_decode_message(ptext, &msg);
            if (status != PEP_STATUS_OK)
                goto pep_error;

            break;

        case PEP_enc_pieces:
            msg = clone_to_empty_message(src);
            if (msg == NULL)
                goto enomem;

            msg->longmsg = strdup(ptext);
            if (msg->longmsg == NULL)
                goto enomem;

            bloblist_t *_m = msg->attachments;
            bloblist_t *_s;
            for (_s = src->attachments; _s; _s = _s->next) {
                if (is_encrypted_attachment(_s)) {
                    ctext = _s->data;
                    csize = _s->size;

                    status = decrypt_and_verify(session, ctext, csize, &ptext,
                            &psize, &keylist);
                    if (ptext == NULL)
                        goto pep_error;
                    
                    if (is_encrypted_html_attachment(_s)) {
                        msg->longmsg_formatted = strdup(ptext);
                        if (msg->longmsg_formatted == NULL)
                            goto pep_error;
                    }
                    else {
                        char * mime_type = "application/octet-stream";
                        char * filename = without_double_ending(_s->filename);
                        if (filename == NULL)
                            goto enomem;

                        _m = bloblist_add(_m, ptext, psize, mime_type, filename);
                        if (_m == NULL)
                            goto enomem;

                       if (msg->attachments == NULL)
                            msg->attachments = _m;
                    }
                }
            }

            break;

        default:
            // BUG: must implement more
            NOT_IMPLEMENTED
    }

    switch (src->enc_format) {
        case PEP_enc_PGP_MIME:
        case PEP_enc_pieces:
            status = copy_fields(msg, src);
            if (status != PEP_STATUS_OK)
                goto pep_error;

            if (src->shortmsg) {
                free(msg->shortmsg);
                msg->shortmsg = strdup(src->shortmsg);
                if (msg->shortmsg == NULL)
                    goto enomem;
            }

            if (msg->shortmsg == NULL || strcmp(msg->shortmsg, "pEp") == 0)
            {
                char * shortmsg;
                char * longmsg;

                int r = seperate_short_and_long(msg->longmsg, &shortmsg,
                        &longmsg);
                if (r == -1)
                    goto enomem;

                free(msg->shortmsg);
                free(msg->longmsg);

                msg->shortmsg = shortmsg;
                msg->longmsg = longmsg;
            }
            else {
                msg->shortmsg = strdup(src->shortmsg);
                if (msg->shortmsg == NULL)
                    goto enomem;
                msg->longmsg = ptext;
            }

        default:
            // BUG: must implement more
            NOT_IMPLEMENTED
    }

    switch (mime) {
        case PEP_MIME_none:
            break;

        case PEP_MIME:
        case PEP_MIME_fields_omitted:
            {
                char *text = NULL;
                status = mime_encode_message(msg,
                        mime == PEP_MIME_fields_omitted, &text);
                if (status != PEP_STATUS_OK)
                    goto pep_error;

                message *_msg = clone_to_empty_message(msg);
                if (_msg == NULL) {
                    free(text);
                    goto enomem;
                }
                _msg->longmsg = text;
                _msg->shortmsg = strdup(msg->shortmsg);
                if (msg->shortmsg == NULL)
                    goto enomem;

                free_message(msg);
                msg = _msg;
            }
    }

    if (free_src)
        free_message(src);
    *dst = msg;
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free_message(msg);
    if (free_src)
        free_message(src);

    return status;
}

