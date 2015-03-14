#include "mime.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include "etpan_mime.h"
#include "wrappers.h"

#define NOT_IMPLEMENTED assert(0);

static PEP_STATUS render_mime(struct mailmime *mime, char **mimetext)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int fd;
    FILE *file = NULL;
    size_t size;
    char *buf = NULL;
    int col;
    int r;
    char *template = strdup("/tmp/pEp.XXXXXXXXXXXXXXXXXXXX");
    assert(template);
    if (template == NULL)
        goto enomem;

    *mimetext = NULL;

    fd = Mkstemp(template);
    assert(fd != -1);
    if (fd == -1)
        goto err_file;

    r = unlink(template);
    assert(r == 0);
    if (r)
        goto err_file;

    free(template);
    template = NULL;

    file = Fdopen(fd, "w+");
    assert(file);
    if (file == NULL) {
        switch (errno) {
            case ENOMEM:
                goto enomem;
            default:
                goto err_file;
        }
    }

    fd = -1;

    col = 0;
    r = mailmime_write_file(file, &col, mime);
    assert(r == MAILIMF_NO_ERROR);
    if (r == MAILIMF_ERROR_MEMORY)
        goto enomem;
    else if (r != MAILIMF_NO_ERROR)
        goto err_file;

    off_t len = ftello(file);
    assert(len != -1);
    if (len == -1 && errno == EOVERFLOW)
        goto err_file;

    if (len + 1 > SIZE_MAX)
        goto err_buffer;

    size = (size_t) len;

    errno = 0;
    rewind(file);
    assert(errno == 0);
    switch (errno) {
        case 0:
            break;
        case ENOMEM:
            goto enomem;
        default:
            goto err_file;
    }

    buf = calloc(1, size + 1);
    assert(buf);
    if (buf == NULL)
        goto enomem;
 
    size_t _read;
    _read = Fread(buf, size, 1, file);
    assert(_read == size);

    r = Fclose(file);
    assert(r == 0);

    *mimetext = buf;
    return PEP_STATUS_OK;

err_buffer:
    status = PEP_BUFFER_TOO_SMALL;
    goto pep_error;

err_file:
    status = PEP_CANNOT_CREATE_TEMP_FILE;
    goto pep_error;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free(buf);
    free(template);

    if (file) {
        r = Fclose(file);
        assert(r == 0);
    }
    else if (fd != -1) {
        r = Close(fd);
        assert(r == 0);
    }

    return status;
}

static PEP_STATUS mime_html_text(
        const char *plaintext,
        const char *htmltext,
        struct mailmime **result
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct mailmime * mime = NULL;
    struct mailmime * submime = NULL;
    int r;

    assert(plaintext);
    assert(htmltext);
    assert(result);

    *result = NULL;

    mime = part_multiple_new("multipart/alternative", NULL);
    assert(mime);
    if (mime == NULL)
        goto enomem;

    submime = get_text_part("text/plain", plaintext, strlen(plaintext),
            MAILMIME_MECHANISM_QUOTED_PRINTABLE);
    assert(submime);
    if (submime == NULL)
        goto enomem;

    r = mailmime_smart_add_part(mime, submime);
    assert(r == MAILIMF_NO_ERROR);
    if (r == MAILIMF_ERROR_MEMORY) {
        goto enomem;
    }
    else {
        // mailmime_smart_add_part() takes ownership of submime
        submime = NULL;
    }

    submime = get_text_part("text/html", htmltext, strlen(htmltext),
            MAILMIME_MECHANISM_QUOTED_PRINTABLE);
    assert(submime);
    if (submime == NULL)
        goto enomem;

    r = mailmime_smart_add_part(mime, submime);
    assert(r == MAILIMF_NO_ERROR);
    if (r == MAILIMF_ERROR_MEMORY)
        goto enomem;
    else {
        // mailmime_smart_add_part() takes ownership of submime
        submime = NULL;
    }

    *result = mime;
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    if (mime)
        mailmime_free(mime);

    if (submime)
        mailmime_free(submime);

    return status;
}

static PEP_STATUS mime_attachment(
        bloblist_t *blob,
        struct mailmime **result
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct mailmime * mime = NULL;
    char * mime_type;

    assert(blob);
    assert(result);

    *result = NULL;

    if (blob->mime_type == NULL)
        mime_type = "application/octet-stream";
    else
        mime_type = blob->mime_type;

    mime = get_file_part(blob->file_name, mime_type, blob->data, blob->size);
    assert(mime);
    if (mime == NULL)
        goto enomem;

    *result = mime;
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    if (mime)
        mailmime_free(mime);

    return status;
}

static struct mailimf_mailbox * identity_to_mailbox(const pEp_identity *ident)
{
    char *_username = NULL;
    struct mailimf_mailbox *mb;

    _username = mailmime_encode_subject_header("utf-8", ident->username, 0);
    if (_username == NULL)
        goto enomem;

    mb = mailbox_from_string(_username, ident->address);
    if (mb == NULL)
        goto enomem;

    free(_username);
    _username = NULL;

    return mb;

enomem:
    free(_username);
    return NULL;
}

static struct mailimf_mailbox_list * identity_to_mbl(
        const pEp_identity *ident)
{
    struct mailimf_mailbox_list *mbl = NULL;
    struct mailimf_mailbox *mb = NULL;
    clist *list = NULL;
    int r;

    assert(ident);

    list = clist_new();
    if (list == NULL)
        goto enomem;

    mb = identity_to_mailbox(ident);
    if (mb == NULL)
        goto enomem;

    r = clist_append(list, mb);
    if (r)
        goto enomem;

    mbl = mailimf_mailbox_list_new(list);
    if (mbl == NULL)
        goto enomem;

    return mbl;

enomem:
    if (mb)
        mailimf_mailbox_free(mb);

    if (list)
        clist_free(list);

    return NULL;
}

static struct mailimf_address_list * identity_list_to_mal(identity_list *il)
{
    struct mailimf_address_list *mal = NULL;
    struct mailimf_mailbox *mb = NULL;
    struct mailimf_address * addr = NULL;
    clist *list = NULL;
    int r;

    assert(il);

    list = clist_new();
    if (list == NULL)
        goto enomem;

    identity_list *_il;
    for (_il = il; _il; _il = _il->next) {
        mb = identity_to_mailbox(_il->ident);
        if (mb == NULL)
            goto enomem;

        addr = mailimf_address_new(MAILIMF_ADDRESS_MAILBOX, mb, NULL);
        if (addr == NULL)
            goto enomem;
        mb = NULL;

        r = clist_append(list, addr);
        if (r)
            goto enomem;
        addr = NULL;
    }
    mal = mailimf_address_list_new(list);
    if (mal == NULL)
        goto enomem;

    return mal;

enomem:
    if (mb)
        mailimf_mailbox_free(mb);

    if (addr)
        mailimf_address_free(addr);

    if (list)
        clist_free(list);

    return NULL;
}

static clist * stringlist_to_clist(stringlist_t *sl)
{
    clist * cl = clist_new();
    assert(cl);
    if (cl == NULL)
        return NULL;

    stringlist_t *_sl;
    for (_sl = sl; _sl; _sl = _sl->next) {
        int r;
        char * value = mailmime_encode_subject_header("utf-8", _sl->value, 0);
        assert(value);
        if (value == NULL) {
            clist_free(cl);
            return NULL;
        }
        r = clist_append(cl, value);
        assert(r == 0);
        if (r) {
            free(value);
            clist_free(cl);
            return NULL;
        }
    }

    return cl;
}

static PEP_STATUS build_fields(const message *msg, struct mailimf_fields **result)
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct mailimf_fields * fields = NULL;
    int r;
    clist * fields_list = NULL;
    char *subject = msg->shortmsg ? msg->shortmsg : "pEp";

    assert(msg);
    assert(msg->from);
    assert(msg->from->address);
    assert(result);

    *result = NULL;

    fields_list = clist_new();
    assert(fields_list);
    if (fields_list == NULL)
        goto enomem;

    if (msg->id) {
        char *_msgid = strdup(msg->id);
        if (_msgid == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_MESSAGE_ID,
                (_new_func_t) mailimf_message_id_new, _msgid);
        if (r) {
            free(_msgid);
            goto enomem;
        }
    }

    if (msg->sent) {
        struct mailimf_date_time * dt = timestamp_to_etpantime(msg->sent);
        if (dt == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_ORIG_DATE,
                (_new_func_t) mailimf_orig_date_new, dt);
        if (r) {
            mailimf_date_time_free(dt);
            goto enomem;
        }
        dt = NULL;
    }

    /* if (msg->from) */ {
        struct mailimf_mailbox_list *from = identity_to_mbl(msg->from);
        if (from == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_FROM,
                (_new_func_t) mailimf_from_new, from);
        if (r) {
            mailimf_mailbox_list_free(from);
            goto enomem;
        }
    }

    if (msg->to) {
        struct mailimf_address_list *to = identity_list_to_mal(msg->to);
        if (to == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_TO,
                (_new_func_t) mailimf_to_new, to);
        if (r) {
            mailimf_address_list_free(to);
            goto enomem;
        }
    }

    /* if (subject) */ {
        char *_subject = mailmime_encode_subject_header("utf-8", subject, 1);
        if (_subject == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_SUBJECT,
                (_new_func_t) mailimf_subject_new, _subject);
        if (r) {
            free(_subject);
            goto enomem;
        }
    }

    if (msg->cc) {
        struct mailimf_address_list *cc = identity_list_to_mal(msg->cc);
        if (cc == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_CC,
                (_new_func_t) mailimf_cc_new, cc);
        if (r) {
            mailimf_address_list_free(cc);
            goto enomem;
        }
    }
    
    if (msg->bcc) {
        struct mailimf_address_list *bcc = identity_list_to_mal(msg->bcc);
        if (bcc == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_BCC,
                (_new_func_t) mailimf_bcc_new, bcc);
        if (r) {
            mailimf_address_list_free(bcc);
            goto enomem;
        }
    }
    
    if (msg->reply_to) {
        struct mailimf_address_list *reply_to = identity_list_to_mal(msg->reply_to);
        if (reply_to == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_REPLY_TO,
                (_new_func_t) mailimf_reply_to_new, reply_to);
        if (r) {
            mailimf_address_list_free(reply_to);
            goto enomem;
        }
    }

    if (msg->in_reply_to) {
        clist *in_reply_to = stringlist_to_clist(msg->in_reply_to);
        if (in_reply_to == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_IN_REPLY_TO,
                (_new_func_t) mailimf_in_reply_to_new, in_reply_to);
        if (r) {
            clist_free(in_reply_to);
            goto enomem;
        }
    }

    if (msg->references) {
        clist *references = stringlist_to_clist(msg->references);
        if (references == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_REFERENCES,
                (_new_func_t) mailimf_references_new, references);
        if (r) {
            clist_free(references);
            goto enomem;
        }
    }

    if (msg->keywords) {
        clist *keywords = stringlist_to_clist(msg->keywords);
        if (keywords == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_KEYWORDS,
                (_new_func_t) mailimf_keywords_new, keywords);
        if (r) {
            clist_free(keywords);
            goto enomem;
        }
    }

    if (msg->comments) {
        char *comments = mailmime_encode_subject_header("utf-8", msg->comments,
                0);
        if (comments == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_COMMENTS,
                (_new_func_t) mailimf_comments_new, comments);
        if (r) {
            free(comments);
            goto enomem;
        }
    }

    if (msg->opt_fields) {
        stringpair_list_t *_l;
        for (_l = msg->opt_fields; _l; _l = _l->next) {
            char *key = _l->value->key;
            char *value = _l->value->value;
            char *_value = mailmime_encode_subject_header("utf-8", value, 0);
            if (_value == NULL)
                goto enomem;

            r = _append_optional_field(fields_list, key, _value);
            free(_value);
            if (r)
                goto enomem;
        }
    }

    fields = mailimf_fields_new(fields_list);
    assert(fields);
    if (fields == NULL)
        goto enomem;

    *result = fields;

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    if (fields_list)
        clist_free(fields_list);

    if (fields)
        mailimf_fields_free(fields);

    return status;
}

DYNAMIC_API PEP_STATUS mime_encode_message(
        const message *msg,
        char **mimetext
    )
{
    struct mailmime * msg_mime = NULL;
    struct mailmime * mime = NULL;
    struct mailmime * submime = NULL;
    struct mailimf_fields * fields = NULL;
    char *buf = NULL;
    int r;
    PEP_STATUS status;
    char *subject;
    char *plaintext;
    char *htmltext;

    assert(msg);
    assert(mimetext);

    *mimetext = NULL;

    if (msg->enc_format == PEP_enc_none_MIME) {
        assert(0); // why encoding again what is already encoded?
        buf = strdup(msg->longmsg);
        if (buf == NULL)
            return PEP_OUT_OF_MEMORY;
        *mimetext = buf;
        return PEP_STATUS_OK;
    }

    subject = (msg->shortmsg) ? msg->shortmsg : "pEp";
    plaintext = (msg->longmsg) ? msg->longmsg : "";
    htmltext = msg->longmsg_formatted;

    if (htmltext) {
        status = mime_html_text(plaintext, htmltext, &mime);
        if (status != PEP_STATUS_OK)
            goto pep_error;
    }
    else {
        mime = get_text_part("text/plain", plaintext, strlen(plaintext),
                MAILMIME_MECHANISM_QUOTED_PRINTABLE);
        assert(mime);
        if (mime == NULL)
            goto enomem;
    }

    if (msg->attachments) {
        submime = mime;
        mime = part_multiple_new("multipart/mixed", NULL);
        assert(mime);
        if (mime == NULL)
            goto enomem;

        r = mailmime_smart_add_part(mime, submime);
        assert(r == MAILIMF_NO_ERROR);
        if (r == MAILIMF_ERROR_MEMORY) {
            goto enomem;
        }
        else {
            // mailmime_smart_add_part() takes ownership of submime
            submime = NULL;
        }

        bloblist_t *_a;
        for (_a = msg->attachments; _a != NULL; _a = _a->next) {
            char * mime_type;

            assert(_a->data);
            assert(_a->size);

            status = mime_attachment(_a, &submime);
            if (status != PEP_STATUS_OK)
                goto pep_error;

            r = mailmime_smart_add_part(mime, submime);
            assert(r == MAILIMF_NO_ERROR);
            if (r == MAILIMF_ERROR_MEMORY) {
                goto enomem;
            }
            else {
                // mailmime_smart_add_part() takes ownership of submime
                submime = NULL;
            }
        }
    }

    msg_mime = mailmime_new_message_data(NULL);
    assert(msg_mime);
    if (msg_mime == NULL)
        goto enomem;

    r = mailmime_add_part(msg_mime, mime);
    if (r) {
        mailmime_free(mime);
        goto enomem;
    }

    status = build_fields(msg, &fields);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    mailmime_set_imf_fields(msg_mime, fields);

    status = render_mime(msg_mime, &buf);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    mailmime_free(msg_mime);
    *mimetext = buf;

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    if (msg_mime)
        mailmime_free(msg_mime);
    else
        if (mime)
            mailmime_free(mime);

    if (submime)
        mailmime_free(submime);

    return status;
}

static pEp_identity *mailbox_to_identity(const struct mailimf_mailbox * mb)
{
    pEp_identity *ident;
    char *username = NULL;
    size_t index;
    int r;

    index = 0;
    r = mailmime_encoded_phrase_parse("utf-8", mb->mb_display_name,
            strlen(mb->mb_display_name), &index, "utf-8", &username);
    if (r)
        goto enomem;

    ident = new_identity(mb->mb_addr_spec, NULL, NULL, username);
    if (ident == NULL)
        goto enomem;
    free(username);

    return ident;

enomem:
    free(username);

    return NULL;
}

static pEp_identity * mbl_to_identity(const struct mailimf_mailbox_list * mbl)
{
    struct mailimf_mailbox * mb = clist_content(clist_begin(mbl->mb_list));
    return mailbox_to_identity(mb);
}

static identity_list * mal_to_identity_list(
        const struct mailimf_address_list *mal
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    identity_list *il = NULL;
    clist *list = mal->ad_list;
    struct mailimf_address * addr = NULL;
    struct mailimf_mailbox *mb = NULL;
    clistiter *cur;
    int r;

    assert(mal);

    il = new_identity_list(NULL);
    if (il == NULL)
        goto enomem;

    identity_list *_il = il;
    for (cur = clist_begin(list); cur != NULL ; cur = clist_next(cur)) {
        pEp_identity *ident;

        addr = clist_content(cur);
        switch(addr->ad_type) {
            case MAILIMF_ADDRESS_MAILBOX:
                ident = mailbox_to_identity(addr->ad_data.ad_mailbox);
                if (ident == NULL)
                    goto enomem;
                _il = identity_list_add(_il, ident);
                if (_il == NULL)
                    goto enomem;
                break;

            case MAILIMF_ADDRESS_GROUP:
                {
                    clistiter *cur2;
                    struct mailimf_mailbox_list * mbl =
                            addr->ad_data.ad_group->grp_mb_list;
                    for (cur2 = clist_begin(mbl->mb_list); cur2 != NULL;
                            cur2 = clist_next(cur2)) {
                        ident = mailbox_to_identity(clist_content(cur));
                        if (ident == NULL)
                            goto enomem;
                        _il = identity_list_add(_il, ident);
                        if (_il == NULL)
                            goto enomem;
                    }
                }
                break;

            default:
                assert(0);
                goto enomem;
        }
    }

    return il;

enomem:
    free_identity_list(il);

    return NULL;
}

static stringlist_t * clist_to_stringlist(const clist *list)
{
    char *text = NULL;;
    stringlist_t * sl = new_stringlist(NULL);
    if (sl == NULL)
        return NULL;

    clistiter *cur;
    stringlist_t *_sl = sl;
    for (cur = clist_begin(list); cur != NULL; cur = clist_next(cur)) {
        char *phrase = clist_content(cur);
        size_t index;
        int r;

        index = 0;
        r = mailmime_encoded_phrase_parse("utf-8", phrase, strlen(phrase),
                &index, "utf-8", &text);
        if (r)
            goto enomem;

        _sl = stringlist_add(_sl, text);
        if (_sl == NULL)
            goto enomem;

        free(text);
        text = NULL;
    }

    return _sl;

enomem:
    free_stringlist(sl);
    free(text);

    return NULL;
}

static PEP_STATUS read_fields(message *msg, clist *fieldlist)
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct mailimf_field * _field;
    clistiter *cur;
    size_t index;
    int r;
    stringpair_list_t *opt = msg->opt_fields;

    for (cur = clist_begin(fieldlist); cur != NULL; cur = clist_next(cur)) {
        _field = clist_content(cur);

        switch (_field->fld_type) {
            case MAILIMF_FIELD_MESSAGE_ID:
                {
                    char * text = _field->fld_data.fld_message_id->mid_value;
                    index = 0;
                    r = mailmime_encoded_phrase_parse("utf-8", text,
                            strlen(text), &index, "utf-8", &msg->id);
                    if (r)
                        goto enomem;
                }
                break;

            case MAILIMF_FIELD_SUBJECT:
                {
                    char * text = _field->fld_data.fld_subject->sbj_value;
                    index = 0;
                    r = mailmime_encoded_phrase_parse("utf-8", text,
                            strlen(text), &index, "utf-8", &msg->shortmsg);
                    if (r)
                        goto enomem;
                }
                break;

            case MAILIMF_FIELD_ORIG_DATE:
                {
                    struct mailimf_date_time *date =
                        _field->fld_data.fld_orig_date->dt_date_time;
                    msg->sent = etpantime_to_timestamp(date);
                    if (msg->sent == NULL)
                        goto enomem;
                }
                break;

            case MAILIMF_FIELD_FROM:
                {
                    struct mailimf_mailbox_list *mbl =
                            _field->fld_data.fld_from->frm_mb_list;
                    pEp_identity *ident;

                    ident = mbl_to_identity(mbl);
                    if (ident == NULL)
                        goto pep_error;

                    msg->from = ident;
                }
                break;

            case MAILIMF_FIELD_TO:
                {
                    struct mailimf_address_list *mal =
                            _field->fld_data.fld_to->to_addr_list;
                    identity_list *il = mal_to_identity_list(mal);
                    if (il == NULL)
                        goto enomem;
                    msg->to = il;
                }
                break;

            case MAILIMF_FIELD_CC:
                {
                    struct mailimf_address_list *mal =
                            _field->fld_data.fld_cc->cc_addr_list;
                    identity_list *il = mal_to_identity_list(mal);
                    if (il == NULL)
                        goto enomem;
                    msg->cc = il;
                }
                break;

            case MAILIMF_FIELD_BCC:
                {
                    struct mailimf_address_list *mal =
                            _field->fld_data.fld_bcc->bcc_addr_list;
                    identity_list *il = mal_to_identity_list(mal);
                    if (il == NULL)
                        goto enomem;
                    msg->bcc = il;
                }
                break;

            case MAILIMF_FIELD_REPLY_TO:
                {
                    struct mailimf_address_list *mal =
                            _field->fld_data.fld_reply_to->rt_addr_list;
                    identity_list *il = mal_to_identity_list(mal);
                    if (il == NULL)
                        goto enomem;
                    msg->reply_to = il;
                }
                break;

            case MAILIMF_FIELD_IN_REPLY_TO:
                {
                    clist *list = _field->fld_data.fld_in_reply_to->mid_list;
                    stringlist_t *sl = clist_to_stringlist(list);
                    if (sl == NULL)
                        goto enomem;
                    msg->in_reply_to = sl;
                }
                break;

            case MAILIMF_FIELD_REFERENCES:
                {
                    clist *list = _field->fld_data.fld_references->mid_list;
                    stringlist_t *sl = clist_to_stringlist(list);
                    if (sl == NULL)
                        goto enomem;
                    msg->references = sl;
                }
                break;

            case MAILIMF_FIELD_KEYWORDS:
                {
                    clist *list = _field->fld_data.fld_keywords->kw_list;
                    stringlist_t *sl = clist_to_stringlist(list);
                    if (sl == NULL)
                        goto enomem;
                    msg->keywords = sl;
                }
                break;

            case MAILIMF_FIELD_COMMENTS:
                {
                    char * text = _field->fld_data.fld_comments->cm_value;
                    index = 0;
                    r = mailmime_encoded_phrase_parse("utf-8", text,
                            strlen(text), &index, "utf-8", &msg->comments);
                    if (r)
                        goto enomem;
                }
                break;

            case MAILIMF_FIELD_OPTIONAL_FIELD:
                {
                    char * name =
                            _field->fld_data.fld_optional_field->fld_name;
                    char * value =
                            _field->fld_data.fld_optional_field->fld_value;
                    char *_value;

                    index = 0;
                    r = mailmime_encoded_phrase_parse("utf-8", value,
                            strlen(value), &index, "utf-8", &_value);
                    if (r)
                        goto enomem;

                    stringpair_t pair;
                    pair.key = name;
                    pair.value = _value;

                    opt = stringpair_list_add(opt, &pair);
                    free(_value);
                    if (opt == NULL)
                        goto enomem;

                    if (msg->opt_fields == NULL)
                        msg->opt_fields = opt;
                }
                break;
        }
    }

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    return status;
}

DYNAMIC_API PEP_STATUS mime_decode_message(
        const char *mimetext,
        message **msg
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct mailmime * mime = NULL;
    int r;
    message *_msg = NULL;
    size_t index;

    assert(mimetext);
    assert(msg);

    *msg = NULL;
    
    index = 0;
    r = mailmime_parse(mimetext, strlen(mimetext), &index, &mime);
    assert(r == 0);
    assert(mime);
    if (r) {
        if (r == MAILIMF_ERROR_MEMORY)
            goto enomem;
        else
            goto err_mime;
    }

    _msg = calloc(1, sizeof(message));
    assert(_msg);
    if (_msg == NULL)
        goto enomem;

    clist * _fieldlist = mime->mm_data.mm_message.mm_fields->fld_list;
    status = read_fields(_msg, _fieldlist);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    mailmime_free(mime);
    *msg = _msg;

    return status;

err_mime:
    status = PEP_ILLEGAL_VALUE;
    goto pep_error;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free_message(_msg);

    if (mime)
        mailmime_free(mime);

    return status;
}

