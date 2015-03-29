#include "pEp_internal.h"
#include "mime.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "etpan_mime.h"
#include "wrappers.h"

DYNAMIC_API bool is_PGP_message_text(const char *text)
{
    assert(text);
    if (text == NULL)
        return false;

    return strncmp(text, "-----BEGIN PGP MESSAGE-----", 27) == 0;
}

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

    mime = part_multiple_new("multipart/alternative");
    assert(mime);
    if (mime == NULL)
        goto enomem;

    submime = get_text_part("msg.txt", "text/plain", plaintext, strlen(plaintext),
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

    submime = get_text_part("msg.html", "text/html", htmltext, strlen(htmltext),
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

    mime = get_file_part(blob->filename, mime_type, blob->data, blob->size);
    assert(mime);
    if (mime == NULL)
        goto enomem;

    *result = mime;
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

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

    if (fields_list)
        clist_free(fields_list);

    if (fields)
        mailimf_fields_free(fields);

    return status;
}

static PEP_STATUS mime_encode_message_plain(
        const message *msg,
        bool omit_fields,
        struct mailmime **result
    )
{
    struct mailmime * mime = NULL;
    struct mailmime * submime = NULL;
    int r;
    PEP_STATUS status;
    char *subject;
    char *plaintext;
    char *htmltext;

    assert(msg);
    assert(result);

    subject = (msg->shortmsg) ? msg->shortmsg : "pEp";
    plaintext = (msg->longmsg) ? msg->longmsg : "";
    htmltext = msg->longmsg_formatted;

    if (htmltext) {
        status = mime_html_text(plaintext, htmltext, &mime);
        if (status != PEP_STATUS_OK)
            goto pep_error;
    }
    else {
        if (is_PGP_message_text(plaintext))
            mime = get_text_part("msg.asc", "application/octet-stream", plaintext,
                    strlen(plaintext), MAILMIME_MECHANISM_7BIT);
        else
            mime = get_text_part("msg.txt", "text/plain", plaintext, strlen(plaintext),
                    MAILMIME_MECHANISM_QUOTED_PRINTABLE);
        assert(mime);
        if (mime == NULL)
            goto enomem;
    }

    if (msg->attachments) {
        submime = mime;
        mime = part_multiple_new("multipart/mixed");
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

static PEP_STATUS mime_encode_message_PGP_MIME(
        const message * msg,
        bool omit_fields,
        struct mailmime **result
    )
{
    struct mailmime * mime = NULL;
    struct mailmime * submime = NULL;
	struct mailmime_parameter * param;
    int r;
    PEP_STATUS status;
    char *subject;
    char *plaintext;

    assert(msg->longmsg);

    subject = (msg->shortmsg) ? msg->shortmsg : "pEp";
    plaintext = msg->longmsg;

    mime = part_multiple_new("multipart/encrypted");
    assert(mime);
    if (mime == NULL)
        goto enomem;

    param = mailmime_param_new_with_data("protocol", "application/pgp-encrypted");
    clist_append(mime->mm_content_type->ct_parameters, param);

    submime = get_pgp_encrypted_part();
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

    submime = get_text_part("msg.asc", "application/octet-stream", plaintext,
            strlen(plaintext), MAILMIME_MECHANISM_7BIT);
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

    *result = mime;
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

    if (mime)
        mailmime_free(mime);

    if (submime)
        mailmime_free(submime);

    return status;
}

DYNAMIC_API PEP_STATUS mime_encode_message(
        const message * msg,
        bool omit_fields,
        char **mimetext
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct mailmime * msg_mime = NULL;
    struct mailmime * mime = NULL;
    struct mailimf_fields * fields = NULL;
    char *buf = NULL;
    int r;

    assert(msg);
    assert(msg->mime == PEP_MIME_none);
    assert(mimetext);

    *mimetext = NULL;

    switch (msg->enc_format) {
        case PEP_enc_none:
            status = mime_encode_message_plain(msg, omit_fields, &mime);
            break;

        case PEP_enc_pieces:
            status = mime_encode_message_plain(msg, omit_fields, &mime);
            break;

        case PEP_enc_S_MIME:
            NOT_IMPLEMENTED
                
        case PEP_enc_PGP_MIME:
            status = mime_encode_message_PGP_MIME(msg, omit_fields, &mime);
            break;

        case PEP_enc_PEP:
            NOT_IMPLEMENTED
    }

    if (status != PEP_STATUS_OK)
        goto pep_error;

    msg_mime = mailmime_new_message_data(NULL);
    assert(msg_mime);
    if (msg_mime == NULL)
        goto enomem;

    r = mailmime_add_part(msg_mime, mime);
    if (r) {
        mailmime_free(mime);
        goto enomem;
    }
    mime = NULL;

    if (!omit_fields) {
        status = build_fields(msg, &fields);
        if (status != PEP_STATUS_OK)
            goto pep_error;

        mailmime_set_imf_fields(msg_mime, fields);
    }

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

    return status;
}

static pEp_identity *mailbox_to_identity(const struct mailimf_mailbox * mb)
{
    pEp_identity *ident;
    char *username = NULL;
    size_t index;
    int r;

    assert(mb);
    assert(mb->mb_addr_spec);

    if (mb->mb_addr_spec == NULL)
        return NULL;

    if (mb->mb_display_name) {
        index = 0;
        r = mailmime_encoded_phrase_parse("utf-8", mb->mb_display_name,
                strlen(mb->mb_display_name), &index, "utf-8", &username);
        if (r)
            goto enomem;
    }

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

                    free(msg->id);
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

                    free(msg->shortmsg);
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

                    free_timestamp(msg->sent);
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

                    free_identity(msg->from);
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

                    free_identity_list(msg->to);
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

                    free_identity_list(msg->cc);
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

                    free_identity_list(msg->bcc);
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

                    free_identity_list(msg->reply_to);
                    msg->reply_to = il;
                }
                break;

            case MAILIMF_FIELD_IN_REPLY_TO:
                {
                    clist *list = _field->fld_data.fld_in_reply_to->mid_list;
                    stringlist_t *sl = clist_to_stringlist(list);
                    if (sl == NULL)
                        goto enomem;

                    free_stringlist(msg->in_reply_to);
                    msg->in_reply_to = sl;
                }
                break;

            case MAILIMF_FIELD_REFERENCES:
                {
                    clist *list = _field->fld_data.fld_references->mid_list;
                    stringlist_t *sl = clist_to_stringlist(list);
                    if (sl == NULL)
                        goto enomem;

                    free_stringlist(msg->references);
                    msg->references = sl;
                }
                break;

            case MAILIMF_FIELD_KEYWORDS:
                {
                    clist *list = _field->fld_data.fld_keywords->kw_list;
                    stringlist_t *sl = clist_to_stringlist(list);
                    if (sl == NULL)
                        goto enomem;

                    free_stringlist(msg->keywords);
                    msg->keywords = sl;
                }
                break;

            case MAILIMF_FIELD_COMMENTS:
                {
                    char * text = _field->fld_data.fld_comments->cm_value;

                    free(msg->comments);
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

static PEP_STATUS interpret_body(struct mailmime *part, char **longmsg, size_t *size)
{
    const char *text;
    char *_longmsg;
    size_t length;
    size_t _size;
    int code;
    int r;
    size_t index;
    char *type = NULL;
    char *charset = NULL;

    assert(part);
    assert(longmsg);

    *longmsg = NULL;
    if (size)
        *size = 0;

    if (part->mm_body == NULL)
        return PEP_ILLEGAL_VALUE;

    text = part->mm_body-> dt_data.dt_text.dt_data;
    if (text == NULL)
        return PEP_ILLEGAL_VALUE;

    length = part->mm_body->dt_data.dt_text.dt_length;

    if (part->mm_body->dt_encoded) {
        code = part->mm_body->dt_encoding;
        index = 0;
        r = mailmime_part_parse(text, length, &index, code, &_longmsg, &_size);
        switch (r) {
            case MAILIMF_NO_ERROR:
                break;
            case MAILIMF_ERROR_MEMORY:
                return PEP_OUT_OF_MEMORY;
            default:
                return PEP_ILLEGAL_VALUE;
        }
    }
    else {
        _size = length;
        _longmsg = strndup(text, _size);
        if (_longmsg == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    if (part->mm_content_type) {
        if (_get_content_type(part->mm_content_type, &type, &charset) == 0) {
            if (charset && strcmp(charset, "utf-8") != 0) {
                char * _text;
                int r = charconv("utf-8", charset, _longmsg, _size, &_text);
                switch (r) {
                    case MAILIMF_NO_ERROR:
                        break;
                    case MAILIMF_ERROR_MEMORY:
                        return PEP_OUT_OF_MEMORY;
                    default:
                        return PEP_ILLEGAL_VALUE;
                }
                free(_longmsg);
                _longmsg = _text;
            }
        }
    }

    *longmsg = _longmsg;
    if (size)
        *size = _size;

    return PEP_STATUS_OK;
}

static PEP_STATUS interpret_MIME(
        struct mailmime *mime,
        message *msg
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(mime);
    assert(msg);

    struct mailmime_content *content = mime->mm_content_type;
    if (content) {
        if (_is_multipart(content, "alternative")) {
            clist *partlist = mime->mm_data.mm_multipart.mm_mp_list;
            if (partlist == NULL)
                return PEP_ILLEGAL_VALUE;

            clistiter *cur;
            for (cur = clist_begin(partlist); cur; cur = clist_next(cur)) {
                size_t index;
                int r;
                struct mailmime *part = clist_content(cur);
                if (part == NULL)
                    return PEP_ILLEGAL_VALUE;

                content = part->mm_content_type;
                assert(content);
                if (content == NULL)
                    return PEP_ILLEGAL_VALUE;

                if (_is_text_part(content, "plain") && msg->longmsg == NULL) {
                    status = interpret_body(part, &msg->longmsg, NULL);
                    if (status)
                        return status;
                }
                else if (_is_text_part(content, "html") &&
                        msg->longmsg_formatted == NULL) {
                    status = interpret_body(part, &msg->longmsg_formatted,
                            NULL);
                    if (status)
                        return status;
                }
                else /* add as attachment */ {
                    status = interpret_MIME(part, msg);
                    if (status)
                        return status;
                }
            }
        }
        else if (_is_multipart(content, NULL)) {
            clist *partlist = mime->mm_data.mm_multipart.mm_mp_list;
            if (partlist == NULL)
                return PEP_ILLEGAL_VALUE;

            clistiter *cur;
            for (cur = clist_begin(partlist); cur; cur = clist_next(cur)) {
                struct mailmime *part= clist_content(cur);
                if (part == NULL)
                    return PEP_ILLEGAL_VALUE;

                status = interpret_MIME(part, msg);
                if (status != PEP_STATUS_OK)
                    return status;
            }
        }
        else {
            if (_is_text_part(content, NULL) && msg->longmsg == NULL) {
                status = interpret_body(mime, &msg->longmsg, NULL);
                if (status)
                    return status;
            }
            else {
                char *data = NULL;
                size_t size = 0;
                char * mime_type;
                char * charset;
                char * filename;
                int r;

                r = _get_content_type(content, &mime_type, &charset);
                switch (r) {
                    case 0:
                        break;
                    case EINVAL:
                        return PEP_ILLEGAL_VALUE;
                    case ENOMEM:
                        return PEP_OUT_OF_MEMORY;
                    default:
                        return PEP_UNKNOWN_ERROR;
                }

                assert(mime_type);

                status = interpret_body(mime, &data, &size);
                if (status)
                    return status;

                filename = _get_filename(mime);

                msg->attachments = bloblist_add(msg->attachments, data, size,
                        mime_type, filename);
                if (msg->attachments == NULL)
                    return PEP_OUT_OF_MEMORY;
            }
        }
    }

    return PEP_STATUS_OK;
}

static PEP_STATUS interpret_PGP_MIME(struct mailmime *mime, message *msg)
{
    assert(mime);
    assert(msg);

    clist *partlist = mime->mm_data.mm_multipart.mm_mp_list;
    if (partlist == NULL)
        return PEP_ILLEGAL_VALUE;

    clistiter *cur = clist_begin(partlist);
    if (cur == NULL)
        return PEP_ILLEGAL_VALUE;

    cur = clist_next(cur);
    if (cur == NULL)
        return PEP_ILLEGAL_VALUE;

    struct mailmime *second = clist_content(cur);
    if (second == NULL)
        return PEP_ILLEGAL_VALUE;

    if (second->mm_body == NULL)
        return PEP_ILLEGAL_VALUE;

    const char *text = second->mm_body->dt_data.dt_text.dt_data;
    if (text == NULL)
        return PEP_ILLEGAL_VALUE;

    char *_text = strdup(text);
    if (_text == NULL)
        return PEP_OUT_OF_MEMORY;

    msg->mime = PEP_MIME_fields_omitted;
    msg->enc_format = PEP_enc_PGP_MIME;

    free(msg->longmsg);
    msg->longmsg = _text;

    return PEP_STATUS_OK;
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

    clist * _fieldlist = _get_fields(mime);
    if (_fieldlist) {
        status = read_fields(_msg, _fieldlist);
        if (status != PEP_STATUS_OK)
            goto pep_error;
    }

    struct mailmime_content *content = _get_content(mime);

    if (content) {
        if (_is_PGP_MIME(content)) {
            status = interpret_PGP_MIME(mime->mm_data.mm_message.mm_msg_mime,
                    _msg);
            if (status != PEP_STATUS_OK)
                goto pep_error;
        }
        else {
            status = interpret_MIME(mime->mm_data.mm_message.mm_msg_mime,
                    _msg);
            if (status != PEP_STATUS_OK)
                goto pep_error;
        }
    }

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

