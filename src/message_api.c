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

PEP_STATUS mime_encode_parts(const message *src, message **dst)
{
    struct mailmime * mime_body;

    assert(src);
    assert(src->enc_format == PEP_enc_none);
    assert(dst);

    if (src->enc_format != PEP_enc_none)
        return PEP_ILLEGAL_VALUE;

    *dst = NULL;

    if (src->longmsg && src->longmsg_formatted) {
        struct mailmime * mime_text;
        struct mailmime * mime_html;
        NOT_IMPLEMENTED
    }
    else if (src->longmsg) {
        struct mailmime_fields * mime_fields
                = mailmime_fields_new_encoding(MAILMIME_MECHANISM_8BIT);
        assert(mime_fields);
        if (mime_fields == NULL)
            return PEP_OUT_OF_MEMORY;

        struct mailmime_content * content
                = mailmime_content_new_with_str("text/plain");
        assert(content);
        if (content == NULL) {
            mailmime_fields_free(mime_fields);
            return PEP_OUT_OF_MEMORY;
        }

        struct mailmime_parameter * param
                = mailmime_param_new_with_data("charset", "utf-8");
        assert(param);
        if (param == NULL) {
            mailmime_fields_free(mime_fields);
            mailmime_content_free(content);
            return PEP_OUT_OF_MEMORY;
        }

        int r = clist_append(content->ct_parameters, param);
        if (r < 0) {
            mailmime_fields_free(mime_fields);
            mailmime_content_free(content);
            mailmime_parameter_free(param);
            return PEP_OUT_OF_MEMORY;
        }

        mime_body = mailmime_new_empty(content, mime_fields);
        if (mime_body == NULL) {
            mailmime_fields_free(mime_fields);
            mailmime_content_free(content);
            return PEP_OUT_OF_MEMORY;
        }

        r = mailmime_set_body_text(mime_body, src->longmsg, strlen(src->longmsg));
        if (r != MAILIMF_NO_ERROR) {
            mailmime_free(mime_body);
            return PEP_OUT_OF_MEMORY;
        }
    }
    else if (src->longmsg_formatted) {
        NOT_IMPLEMENTED
    }
 
    char *fn = strdup("/tmp/pEp.XXXXXXXXXX");
    assert(fn);
    if (fn == NULL) {
        mailmime_free(mime_body);
        return PEP_OUT_OF_MEMORY;
    }

    int f = mkstemp(fn);
    assert(f != -1);
    free(fn);
    if (f == -1) {
        mailmime_free(mime_body);
        return PEP_CANNOT_CREATE_TEMP_FILE;
    }

    FILE *fp = fdopen(f, "w+");
    assert(fp);
    if (fp == NULL) {
        return PEP_CANNOT_CREATE_TEMP_FILE;
    }
    // unlink(fn);

    int col = 0;
    int r = mailmime_write_file(fp, &col, mime_body);
    assert(r == MAILIMF_NO_ERROR);
    mailmime_free(mime_body);
    if (r != MAILIMF_NO_ERROR) {
        fclose(fp);
        return PEP_CANNOT_CREATE_TEMP_FILE;
    }

    rewind(fp);

    char *buf = (char *) calloc(1, col + 1);
    assert(buf);
    if (buf == NULL) {
        fclose(fp);
        return PEP_OUT_OF_MEMORY;
    }

    size_t size = fread(buf, col, 1, fp);
    assert(size);
    fclose(fp);
    if (size == 0L) {
        free(buf);
        return PEP_CANNOT_CREATE_TEMP_FILE;
    }

    message *msg = new_message(src->dir, src->from, src->to, src->shortmsg);
    if (msg == NULL) {
        free(buf);
        return PEP_OUT_OF_MEMORY;
    }
    msg->longmsg = buf;

    *dst = msg;
    return PEP_STATUS_OK;
}

PEP_STATUS mime_decode_parts(const message *src, message **dst)
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(src);
    assert(src->enc_format == PEP_enc_none_MIME);
    assert(dst);

    if (src->enc_format != PEP_enc_none_MIME)
        return PEP_ILLEGAL_VALUE;

    *dst = NULL;

    return status;
}

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

        switch (format) {
        case PEP_enc_MIME_multipart: {
            *dst = msg;
            break;
        }

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
            else if (src->shortmsg) {
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

