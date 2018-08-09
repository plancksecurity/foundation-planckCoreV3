// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "mime.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "resource_id.h"
#include "etpan_mime.h"
#include "wrappers.h"

static bool is_whitespace(char c)
{
    switch (c) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
            return true;

        default:
            return false;
    }
}

DYNAMIC_API bool is_PGP_message_text(const char *text)
{
    if (text == NULL)
        return false;

    for (; *text && is_whitespace(*text); text++);

    return strncmp(text, "-----BEGIN PGP MESSAGE-----", 27) == 0;
}

#define TMP_TEMPLATE "pEp.XXXXXXXXXXXXXXXXXXXX"
#ifdef _WIN32
#define PATH_SEP '\\'
#else
#define PATH_SEP '/'
#endif

// This function was rewritten to use in-memory buffers instead of
// temporary files when the pgp/mime support was implemented for
// outlook, as the existing code did not work well on windows.

static PEP_STATUS render_mime(struct mailmime *mime, char **mimetext)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int col;
    int r;
	size_t len;
	char* buf = NULL;

	MMAPString* buffer;

	buffer = mmap_string_new(NULL);
	if (buffer == NULL)
		goto enomem;
	
	col = 0;
	r = mailmime_write_mem(buffer, &col, mime);
	assert(r == MAILIMF_NO_ERROR);
	if (r == MAILIMF_ERROR_MEMORY)
		goto enomem;
	else if (r != MAILIMF_NO_ERROR)
		goto err_file;

	// we overallocate by 1 byte, so we have a terminating 0.
	len = buffer->len;
	buf = calloc(len + 1, 1);
	if (buf == NULL)
		goto enomem;

	memcpy(buf, buffer->str, len);
	mmap_string_free(buffer);

    *mimetext = buf;
    return PEP_STATUS_OK;

err_file:
    status = PEP_CANNOT_CREATE_TEMP_FILE;
    goto pEp_error;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_error:
	if (buffer)
		mmap_string_free(buffer);
	if (buf)
		free(buf);
    return status;
}

static PEP_STATUS mime_attachment(
        bloblist_t *blob,
        struct mailmime **result,
        bool transport_encode
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct mailmime * mime = NULL;
    char * mime_type;
    assert(blob);
    assert(result);

    *result = NULL;

// TODO: It seems the pEp COM server adapter sends an empty string here,
// which leads to a crash later. Thus, we workaround here by treating an
// empty string as NULL. We need to check whether the bug really is here,
// or the pEp COM server adapter needs to be changed.
    if (blob->mime_type == NULL || blob->mime_type[0] == '\0')
        mime_type = "application/octet-stream";
    else
        mime_type = blob->mime_type;

    pEp_rid_list_t* resource = parse_uri(blob->filename);

    bool already_ascii = !(must_chunk_be_encoded(blob->value, blob->size, true));

    mime = get_file_part(resource, mime_type, blob->value, blob->size, 
                          (already_ascii ? false : transport_encode));
    free_rid_list(resource);
    
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

static PEP_STATUS mime_html_text(
        const char *plaintext,
        const char *htmltext,
        bloblist_t *attachments,
        struct mailmime **result,
        bool transport_encode
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct mailmime * top_level_html_mime = NULL;
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

    pEp_rid_list_t* resource = new_rid_node(PEP_RID_FILENAME, "msg.txt");
    
    int encoding_type = (transport_encode ? MAILMIME_MECHANISM_QUOTED_PRINTABLE : 0);
    submime = get_text_part(NULL, "text/plain", plaintext, strlen(plaintext),
            encoding_type);
    free_rid_list(resource);
    resource = NULL;
    
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

    bool inlined_attachments = false;
    
    bloblist_t* traversal_ptr = attachments;
    
    while (traversal_ptr) {
        if (traversal_ptr->disposition == PEP_CONTENT_DISP_INLINE) {
            inlined_attachments = true;
            break;
        }
        traversal_ptr = traversal_ptr->next;
    }

    if (inlined_attachments) {
        /* Noooooo... dirk, why do you do this to me? */
        submime = part_multiple_new("multipart/related");
        assert(submime);
        if (submime == NULL)
            goto enomem;

        top_level_html_mime = submime;
        
        r = mailmime_smart_add_part(mime, top_level_html_mime);
        assert(r == MAILIMF_NO_ERROR);
        if (r == MAILIMF_ERROR_MEMORY) {
            goto enomem;
        }
        else {
            // mailmime_smart_add_part() takes ownership of submime
            submime = NULL;
        }
    }
    else {
        top_level_html_mime = mime;
    }

//    resource = new_rid_node(PEP_RID_FILENAME, "msg.html");
    submime = get_text_part(NULL, "text/html", htmltext, strlen(htmltext),
            encoding_type);
    free_rid_list(resource);
    resource = NULL;
    
    assert(submime);
    if (submime == NULL)
        goto enomem;

    r = mailmime_smart_add_part(top_level_html_mime, submime);
    assert(r == MAILIMF_NO_ERROR);
    if (r == MAILIMF_ERROR_MEMORY)
        goto enomem;
    else {
        // mailmime_smart_add_part() takes ownership of submime
        submime = NULL;
    }

    bloblist_t *_a;
    for (_a = attachments; _a != NULL; _a = _a->next) {
        if (_a->disposition != PEP_CONTENT_DISP_INLINE)
            continue;
        status = mime_attachment(_a, &submime, transport_encode);
        if (status != PEP_STATUS_OK)
            return PEP_UNKNOWN_ERROR; // FIXME

        r = mailmime_smart_add_part(top_level_html_mime, submime);
        assert(r == MAILIMF_NO_ERROR);
        if (r == MAILIMF_ERROR_MEMORY) {
            goto enomem;
        }
        else {
            // mailmime_smart_add_part() takes ownership of submime
            submime = NULL;
        }
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


// FIXME: maybe need to add transport_encode field here
static struct mailimf_mailbox * identity_to_mailbox(const pEp_identity *ident)
{
    char *_username = NULL;
    struct mailimf_mailbox *mb;

    if (!ident->username)
        _username = strdup("");
    else
        _username = must_field_value_be_encoded(ident->username) ?
                    mailmime_encode_subject_header("utf-8", ident->username, 0) : 
                    strdup(ident->username);
                  
    assert(_username);
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
    for (_il = il; _il && _il->ident; _il = _il->next) {
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

static clist * stringlist_to_clist(stringlist_t *sl, bool transport_encode)
{
    clist * cl = clist_new();
    assert(cl);
    if (cl == NULL)
        return NULL;

    if (!sl || ((!sl->value || sl->value[0] == '\0') && sl->next == NULL))
        return cl;
        
    stringlist_t *_sl;
    for (_sl = sl; _sl; _sl = _sl->next) {
        int r;
        char * value = ((transport_encode && must_field_value_be_encoded(_sl->value)) ?
                        mailmime_encode_subject_header("utf-8", _sl->value, 0) :
                        strdup(_sl->value));
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
    unsigned char pEpstr[] = PEP_SUBJ_STRING; // unsigned due to UTF-8 byte fun
#ifdef WIN32
    char* altstr = "pEp";
#else
    char* altstr = (char*)pEpstr;
#endif        
    char *subject = msg->shortmsg ? msg->shortmsg : altstr;

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
        assert(_msgid);
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

    char* _subject = NULL;
    if (!must_field_value_be_encoded(subject)) {
        _subject = strdup(subject);
        assert(_subject);
    }
    else {
        _subject = mailmime_encode_subject_header("utf-8", subject, 1);
    }
    if (_subject == NULL)
        goto enomem;

    r = _append_field(fields_list, MAILIMF_FIELD_SUBJECT,
            (_new_func_t) mailimf_subject_new, _subject);
    if (r) {
        free(_subject);
        goto enomem;
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
        clist *in_reply_to = stringlist_to_clist(msg->in_reply_to, true);
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
        clist *references = stringlist_to_clist(msg->references, true);
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
        clist *keywords = stringlist_to_clist(msg->keywords, true);
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
        char *comments = NULL;
        if (!must_field_value_be_encoded(msg->comments)) {
            comments = strdup(msg->comments);
            assert(comments);
        }
        else  {
            comments = mailmime_encode_subject_header("utf-8", msg->comments, 0);
        }
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
        for (_l = msg->opt_fields; _l && _l->value; _l = _l->next) {
            char *key = _l->value->key;
            char *value = _l->value->value;
            if (key && value) {
                r = _append_optional_field(fields_list, key, value);

                if (r)
                    goto enomem;
            }
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

static bool has_exceptional_extension(char* filename) {
    if (!filename)
        return false;
    int len = strlen(filename);
    if (len < 4)
        return false;
    char* ext_start = filename + (len - 4);
    if (strcmp(ext_start, ".pgp") == 0 || strcmp(ext_start, ".gpg") == 0 ||
        strcmp(ext_start, ".asc") == 0 || strcmp(ext_start, ".pEp") == 0)
        return true;
    return false;
}

static pEp_rid_list_t* choose_resource_id(pEp_rid_list_t* rid_list) {
    pEp_rid_list_t* retval = rid_list;
    
    /* multiple elements - least common case */
    if (rid_list && rid_list->next) {
        pEp_rid_list_t* rid_list_curr = rid_list;
        retval = rid_list; 
        
        while (rid_list_curr) {
            pEp_resource_id_type rid_type = rid_list_curr->rid_type;
            if (rid_type == PEP_RID_CID)
                retval = rid_list_curr;
            else if (rid_type == PEP_RID_FILENAME && has_exceptional_extension(rid_list_curr->rid))
                return rid_list_curr;
            rid_list_curr = rid_list_curr->next;
        }
    } 
    return retval;
}

// static void split_inlined_and_attached(bloblist_t** inlined, bloblist_t** attached) {
//     bloblist_t** curr_pp = attached;
//     bloblist_t* curr = *curr_pp;
//     
//     bloblist_t* inline_ret = NULL;
//     bloblist_t** inline_curr_pp = &inline_ret;
//     
//     bloblist_t* att_ret = NULL;
//     bloblist_t** att_curr_pp = &att_ret;
//     
//     while (curr) {
//         if (curr->disposition == PEP_CONTENT_DISP_INLINE) {
//             *inline_curr_pp = curr;
//             inline_curr_pp = &(curr->next);
//         }
//         else {
//             *att_curr_pp = curr;
//             att_curr_pp = &(curr->next);            
//         }
//         *curr_pp = curr->next;
//         curr->next = NULL;
//         curr = *curr_pp;
//     }
//     
//     *inlined = inline_ret;
//     *attached = att_ret;
// }


static PEP_STATUS mime_encode_message_plain(
        const message *msg,
        bool omit_fields,
        struct mailmime **result,
        bool transport_encode
    )
{
    struct mailmime * mime = NULL;
    struct mailmime * submime = NULL;
    int r;
    PEP_STATUS status;
    //char *subject;
    char *plaintext;
    char *htmltext;

    assert(msg);
    assert(result);
    
    //subject = (msg->shortmsg) ? msg->shortmsg : "pEp";  // not used, yet.
    plaintext = (msg->longmsg) ? msg->longmsg : "";
    htmltext = msg->longmsg_formatted;

    if (htmltext && (htmltext[0] != '\0')) {
        /* first, we need to strip out the inlined attachments to ensure this
           gets set up correctly */
           
        status = mime_html_text(plaintext, htmltext, msg->attachments, &mime,
                                transport_encode);
                
        if (status != PEP_STATUS_OK)
            goto pEp_error;
    }
    else {
        pEp_rid_list_t* resource = NULL;
        if (is_PGP_message_text(plaintext)) {
            resource = new_rid_node(PEP_RID_FILENAME, "msg.asc");
            int encoding_type = (transport_encode ? MAILMIME_MECHANISM_7BIT : 0);
            mime = get_text_part(resource, "application/octet-stream", plaintext,
                    strlen(plaintext), encoding_type);
        }
        else {
            resource = new_rid_node(PEP_RID_FILENAME, "msg.txt");
            int encoding_type = (transport_encode ? MAILMIME_MECHANISM_QUOTED_PRINTABLE : 0);
            mime = get_text_part(resource, "text/plain", plaintext, strlen(plaintext),
                    encoding_type);
        }
        free_rid_list(resource);
        
        assert(mime);
        if (mime == NULL)
            goto enomem;
    }

    bool normal_attachments = false;
    
    bloblist_t* traversal_ptr = msg->attachments;
    
    while (traversal_ptr) {
        if (traversal_ptr->disposition != PEP_CONTENT_DISP_INLINE) {
            normal_attachments = true;
            break;
        }
        traversal_ptr = traversal_ptr->next;
    }

    if (normal_attachments) {
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

            if (_a->disposition == PEP_CONTENT_DISP_INLINE)
                continue;

            status = mime_attachment(_a, &submime, transport_encode);
            if (status != PEP_STATUS_OK)
                goto pEp_error;

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

pEp_error:
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
    char *plaintext;
    size_t plaintext_size;

    assert(msg->attachments && msg->attachments->next &&
            msg->attachments->next->value);

    plaintext = msg->attachments->next->value;
    plaintext_size = msg->attachments->next->size;

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

    pEp_rid_list_t* resource = new_rid_node(PEP_RID_FILENAME, "msg.asc");
    submime = get_text_part(resource, "application/octet-stream", plaintext,
            plaintext_size, MAILMIME_MECHANISM_7BIT);
            
    free_rid_list(resource);
    
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
    return _mime_encode_message_internal(msg, omit_fields, mimetext, true);
}

PEP_STATUS _mime_encode_message_internal(
        const message * msg,
        bool omit_fields,
        char **mimetext,
        bool transport_encode
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct mailmime * msg_mime = NULL;
    struct mailmime * mime = NULL;
    struct mailimf_fields * fields = NULL;
    char *buf = NULL;
    int r;

    assert(msg);
    assert(mimetext);

    if (!(msg && mimetext))
        return PEP_ILLEGAL_VALUE;

    *mimetext = NULL;

    switch (msg->enc_format) {
        case PEP_enc_none:
            status = mime_encode_message_plain(msg, omit_fields, &mime, transport_encode);
            break;

        case PEP_enc_pieces:
            status = mime_encode_message_plain(msg, omit_fields, &mime, transport_encode);
            break;

        case PEP_enc_S_MIME:
            NOT_IMPLEMENTED
                
        case PEP_enc_PGP_MIME:
            status = mime_encode_message_PGP_MIME(msg, omit_fields, &mime);
            break;

        case PEP_enc_PEP:
            NOT_IMPLEMENTED

        default:
            NOT_IMPLEMENTED
    }

    if (status != PEP_STATUS_OK)
        goto pEp_error;

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
            goto pEp_error;

        mailmime_set_imf_fields(msg_mime, fields);
    }

    status = render_mime(msg_mime, &buf);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    mailmime_free(msg_mime);
    *mimetext = buf;

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_error:
    if (msg_mime)
        mailmime_free(msg_mime);
    else
        if (mime)
            mailmime_free(mime);

    return status;
}

static pEp_identity *mailbox_to_identity(const struct mailimf_mailbox * mb)
{
    char *username = NULL;

    assert(mb);
    assert(mb->mb_addr_spec);

    if (mb->mb_addr_spec == NULL)
        return NULL;

    if (mb->mb_display_name) {
        size_t index = 0;
        const int r = mailmime_encoded_phrase_parse("utf-8", mb->mb_display_name,
                strlen(mb->mb_display_name), &index, "utf-8", &username);
        if (r)
            goto enomem;
    }

    pEp_identity *ident = new_identity(mb->mb_addr_spec, NULL, NULL, username);
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
    assert(mal);
    clist *list = mal->ad_list;

    identity_list *il = new_identity_list(NULL);
    if (il == NULL)
        goto enomem;

    identity_list *_il = il;
    for (clistiter *cur = clist_begin(list); cur != NULL ; cur = clist_next(cur)) {
        pEp_identity *ident;

        struct mailimf_address *addr = clist_content(cur);
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
                    struct mailimf_mailbox_list * mbl =
                            addr->ad_data.ad_group->grp_mb_list;
                    for (clistiter *cur2 = clist_begin(mbl->mb_list); cur2 != NULL;
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

    stringlist_t *_sl = sl;
    for (clistiter *cur = clist_begin(list); cur != NULL; cur = clist_next(cur)) {
        char *phrase = clist_content(cur);
        size_t index = 0;
        
        const int r = mailmime_encoded_phrase_parse("utf-8", phrase, strlen(phrase),
                &index, "utf-8", &text);
        if (r)
            goto enomem;

        _sl = stringlist_add(_sl, text);
        if (_sl == NULL)
            goto enomem;

        free(text);
        text = NULL;
    }

    return sl;

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

    if (!fieldlist)
        return PEP_STATUS_OK;
        
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
                        goto pEp_error;

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

                    stringpair_t *pair = new_stringpair(name, _value);
                    if (pair == NULL)
                        goto enomem;

                    opt = stringpair_list_add(opt, pair);
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

pEp_error:
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
        _size = length + 1;
        _longmsg = strndup(text, length);
        if (_longmsg == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    if (part->mm_content_type) {
        if (_get_content_type(part->mm_content_type, &type, &charset) == 0) {
            if (charset && strncasecmp(charset, "utf-8", 5) != 0) {
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
    // FIXME: KG - we now have the text we want.
    // Now we need to strip sigs and process them if they are there..
    

    *longmsg = _longmsg;
    if (size)
        *size = _size;

    return PEP_STATUS_OK;
}

// THIS IS A BEST-EFFORT ONLY FUNCTION, AND WE ARE NOT DOING MORE THAN THE
// SUBJECT FOR NOW.
static PEP_STATUS interpret_protected_headers(
        struct mailmime* mime, 
        message* msg
    )
{
    // N.B. this is *very much* enigmail output specific, and right now,
    // we only care about subject replacement.
    const char* header_string = "Content-Type: text/rfc822-headers; protected-headers=\"v1\"\nContent-Disposition: inline\n\n";
    size_t content_length = mime->mm_length;
    size_t header_strlen = strlen(header_string);
    if (header_strlen < content_length) {
        const char* headerblock = mime->mm_mime_start;
        size_t subject_len = 0;
        headerblock = strstr(headerblock, header_string);
        if (headerblock) {
            const char* subj_start = "Subject: ";
            size_t subj_len = strlen(subj_start);
            headerblock = strstr(headerblock, subj_start);
            if (headerblock) {
                headerblock += subj_len;
                char* end_pt = strstr(headerblock, "\n");
                if (end_pt) {
                    if (end_pt != mime->mm_mime_start && *(end_pt - 1) == '\r')
                        end_pt--;
                    subject_len = end_pt - headerblock;
                    char* new_subj = (char*)calloc(subject_len + 1, 1);
                    if (new_subj) {
                        strlcpy(new_subj, headerblock, subject_len + 1);
                        free(msg->shortmsg);
                        msg->shortmsg = new_subj;
                    }    
                } // if there's no endpoint, there's something wrong here so we ignore all
                  // This is best effort.
            }
        }
    }
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
                else if (_is_text_part(content, "rfc822-headers")) {
                    status = interpret_protected_headers(part, msg);
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
        else if (_is_multipart(content, "encrypted")) {
            if (msg->longmsg == NULL)
                msg->longmsg = strdup("");
            assert(msg->longmsg);
            if (!msg->longmsg)
                return PEP_OUT_OF_MEMORY;

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
            if (_is_text_part(content, "html") &&
                msg->longmsg_formatted == NULL) {
                status = interpret_body(mime, &msg->longmsg_formatted,
                                        NULL);
                if (status)
                    return status;
            }
            else if (_is_text_part(content, "rfc822-headers")) {
                status = interpret_protected_headers(mime, msg);
                if (status)
                    return status;
            }
            else if (_is_text_part(content, NULL) && msg->longmsg == NULL) {
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

                pEp_rid_list_t* resource_id_list = _get_resource_id_list(mime);
                pEp_rid_list_t* chosen_resource_id = choose_resource_id(resource_id_list);
                
                //filename = _get_filename_or_cid(mime);
                char *_filename = NULL;
                
                if (chosen_resource_id) {
                    filename = chosen_resource_id->rid;
                    size_t index = 0;
                    /* NOTA BENE */
                    /* The prefix we just added shouldn't be a problem - this is about decoding %XX (RFC 2392) */
                    /* If it becomes one, we have some MESSY fixing to do. :(                                  */
                    r = mailmime_encoded_phrase_parse("utf-8", filename,
                            strlen(filename), &index, "utf-8", &_filename);
                    if (r) {
                        goto enomem;
                    }
                    char* file_prefix = NULL;
                    
                    /* in case there are others later */
                    switch (chosen_resource_id->rid_type) {
                        case PEP_RID_CID:
                            file_prefix = "cid";
                            break;
                        case PEP_RID_FILENAME:
                            file_prefix = "file";
                            break;
                        default:
                            break;
                    }

                    
                    if (file_prefix) {
                        filename = build_uri(file_prefix, _filename);
                        free(_filename);
                        _filename = filename;
                    }
                }

                bloblist_t *_a = bloblist_add(msg->attachments, data, size,
                        mime_type, _filename);
                free(_filename);
                free_rid_list(resource_id_list);
                resource_id_list = NULL;
                if (_a == NULL)
                    return PEP_OUT_OF_MEMORY;
                if (msg->attachments == NULL)
                    msg->attachments = _a;
            }
        }
    }

    return PEP_STATUS_OK;

enomem:
    return PEP_OUT_OF_MEMORY;
}

DYNAMIC_API PEP_STATUS mime_decode_message(
        const char *mimetext,
        size_t size,
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

    if (!(mimetext && msg))
        return PEP_ILLEGAL_VALUE;

    *msg = NULL;

    index = 0;
    r = mailmime_parse(mimetext, size, &index, &mime);
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
            goto pEp_error;
    }

    struct mailmime_content *content = _get_content(mime);

    if (content) {
        status = interpret_MIME(mime->mm_data.mm_message.mm_msg_mime,
                _msg);
        if (status != PEP_STATUS_OK)
            goto pEp_error;
    }

    mailmime_free(mime);
    *msg = _msg;

    return status;

err_mime:
    status = PEP_ILLEGAL_VALUE;
    goto pEp_error;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_error:
    free_message(_msg);

    if (mime)
        mailmime_free(mime);

    return status;
}
