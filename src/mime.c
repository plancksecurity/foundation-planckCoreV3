#include "mime.h"

#include <libetpan/mailmime.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include "etpan_mime.h"
#include "wrappers.h"

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

static struct mailimf_mailbox_list * mbl_from_identity(const pEp_identity *ident)
{
    struct mailimf_mailbox_list *mbl = NULL;
    struct mailimf_mailbox *mb = NULL;
    clist *list = NULL;
    int r;

    assert(ident);

    list = clist_new();
    if (list == NULL)
        goto enomem;

    mb = mailbox_from_string(ident->username, ident->address);
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

static struct mailimf_address_list * mal_from_identity_list(identity_list *il)
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
        mb = mailbox_from_string(_il->ident->username, _il->ident->address);
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

static clist * clist_from_stringlist(stringlist_t *sl)
{
    clist * cl = clist_new();
    assert(cl);
    if (cl == NULL)
        return NULL;

    stringlist_t *_sl;
    for (_sl = sl; _sl; _sl = _sl->next) {
        int r;
        char * value = strdup(_sl->value);
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

    /* if (subject) */ {
        char *_subject = strdup(subject);
        if (_subject == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_SUBJECT,
                (_new_func_t) mailimf_subject_new, _subject);
        if (r) {
            free(_subject);
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
        struct mailimf_mailbox_list *from = mbl_from_identity(msg->from);
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
        struct mailimf_address_list *to = mal_from_identity_list(msg->to);
        if (to == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_TO,
                (_new_func_t) mailimf_to_new, to);
        if (r) {
            mailimf_address_list_free(to);
            goto enomem;
        }
    }

    if (msg->cc) {
        struct mailimf_address_list *cc = mal_from_identity_list(msg->cc);
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
        struct mailimf_address_list *bcc = mal_from_identity_list(msg->bcc);
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
        struct mailimf_mailbox_list *reply_to= mbl_from_identity(msg->reply_to);
        if (reply_to == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_REPLY_TO,
                (_new_func_t) mailimf_reply_to_new, reply_to);
        if (r) {
            mailimf_mailbox_list_free(reply_to);
            goto enomem;
        }
    }

    if (msg->in_reply_to) {
        char *in_reply_to = strdup(msg->in_reply_to);
        if (in_reply_to == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_IN_REPLY_TO,
                (_new_func_t) mailimf_in_reply_to_new, in_reply_to);
        if (r) {
            free(in_reply_to);
            goto enomem;
        }
    }

    if (msg->references) {
        clist *references = clist_from_stringlist(msg->references);
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
        clist *keywords = clist_from_stringlist(msg->keywords);
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
        char *comments = strdup(msg->comments);
        if (comments == NULL)
            goto enomem;

        r = _append_field(fields_list, MAILIMF_FIELD_COMMENTS,
                (_new_func_t) mailimf_comments_new, comments);
        if (r) {
            free(comments);
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

DYNAMIC_API PEP_STATUS mime_decode_message(
        const char *mimetext,
        message **msg
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct mailmime * mime = NULL;
    int r;

    assert(mimetext);
    assert(msg);

    *msg = NULL;
    
    size_t index = 0;
    r = mailmime_parse(mimetext, strlen(mimetext), &index, &mime);
    assert(r == 0);
    assert(mime);
    if (r) {
        if (r == MAILIMF_ERROR_MEMORY)
            goto enomem;
        else
            goto err_mime;
    }

    mailmime_free(mime);

    return status;

err_mime:
    status = PEP_ILLEGAL_VALUE;
    goto pep_error;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    if (mime)
        mailmime_free(mime);

    return status;
}

