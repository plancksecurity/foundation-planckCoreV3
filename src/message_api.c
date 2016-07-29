#include "pEp_internal.h"
#include "message_api.h"

#include "platform.h"
#include "mime.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>


#ifndef MIN
#define MIN(A, B) ((B) > (A) ? (A) : (B))
#endif
#ifndef MAX
#define MAX(A, B) ((B) > (A) ? (B) : (A))
#endif


static bool string_equality(const char *s1, const char *s2)
{
    if (s1 == NULL || s2 == NULL)
        return false;

    assert(s1 && s2);

    return strcmp(s1, s2) == 0;
}

static bool is_mime_type(const bloblist_t *bl, const char *mt)
{
    assert(mt);

    return bl && string_equality(bl->mime_type, mt);
}

//
// This function presumes the file ending is a proper substring of the
// filename (i.e. if bl->filename is "a.pgp" and fe is ".pgp", it will
// return true, but if bl->filename is ".pgp" and fe is ".pgp", it will
// return false. This is desired behaviour.
//
static bool is_fileending(const bloblist_t *bl, const char *fe)
{
    assert(fe);
    
    if (bl == NULL || bl->filename == NULL || fe == NULL)
        return false;

    assert(bl && bl->filename);

    size_t fe_len = strlen(fe);
    size_t fn_len = strlen(bl->filename);

    if (fn_len <= fe_len)
        return false;

    assert(fn_len > fe_len);

    return strcmp(bl->filename + (fn_len - fe_len), fe) == 0;
}

static void add_opt_field(message *msg, const char *name, const char *value)
{
    assert(msg);

    if (msg && name && value) {
        stringpair_t *pair = new_stringpair(name, value);
        if (pair == NULL)
            return;

        stringpair_list_t *field = stringpair_list_add(msg->opt_fields, pair);
        if (field == NULL)
        {
            free_stringpair(pair);
            return;
        }

        if (msg->opt_fields == NULL)
            msg->opt_fields = field;
    }
}

static char * combine_short_and_long(const char *shortmsg, const char *longmsg)
{
    char * ptext;

    assert(shortmsg);
    assert(strcmp(shortmsg, "pEp") != 0);

    if (!shortmsg || strcmp(shortmsg, "pEp") == 0) {
        if (!longmsg) {
            return NULL;
        }
        else {
            char *result = strdup(longmsg);
            assert(result);
            return result;
        }
    }
        
    if (longmsg == NULL)
        longmsg = "";

    const char * const subject = "Subject: ";
    const size_t SUBJ_LEN = 9;
    const char * const newlines = "\n\n";
    const size_t NL_LEN = 2;

    size_t bufsize = SUBJ_LEN + strlen(shortmsg) + NL_LEN + strlen(longmsg) + 1;
    ptext = calloc(1, bufsize);
    assert(ptext);
    if (ptext == NULL)
        return NULL;

    strlcpy(ptext, subject, bufsize);
    strlcat(ptext, shortmsg, bufsize);
    strlcat(ptext, newlines, bufsize);
    strlcat(ptext, longmsg, bufsize);

    return ptext;
}

static int separate_short_and_long(const char *src, char **shortmsg, char **longmsg)
{
    char *_shortmsg = NULL;
    char *_longmsg = NULL;

    assert(src);
    assert(shortmsg);
    assert(longmsg);
    
    if (src == NULL || shortmsg == NULL || longmsg == NULL)
        return -1;

    *shortmsg = NULL;
    *longmsg = NULL;

    if (strncasecmp(src, "subject: ", 9) == 0) {
        char *line_end = strchr(src, '\n');

        if (line_end == NULL) {
            _shortmsg = strdup(src + 9);
            assert(_shortmsg);
            if (_shortmsg == NULL)
                goto enomem;
            // _longmsg = NULL;
        }
        else {
            size_t n = line_end - src;

            if (*(line_end - 1) == '\r')
                _shortmsg = strndup(src + 9, n - 10);
            else
                _shortmsg = strndup(src + 9, n - 9);
            assert(_shortmsg);
            if (_shortmsg == NULL)
                goto enomem;

            while (*(src + n) && (*(src + n) == '\n' || *(src + n) == '\r'))
                ++n;

            if (*(src + n)) {
                _longmsg = strdup(src + n);
                assert(_longmsg);
                if (_longmsg == NULL)
                    goto enomem;
            }
        }
    }
    else {
        _shortmsg = strdup("");
        assert(_shortmsg);
        if (_shortmsg == NULL)
            goto enomem;
        _longmsg = strdup(src);
        assert(_longmsg);
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

    if(!(dst && src))
        return PEP_ILLEGAL_VALUE;

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
    if (src->to && src->to->ident) {
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
    if (src->cc && src->cc->ident) {
        dst->cc = identity_list_dup(src->cc);
        if (dst->cc == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_identity_list(dst->bcc);
    dst->bcc = NULL;
    if (src->bcc && src->bcc->ident) {
        dst->bcc = identity_list_dup(src->bcc);
        if (dst->bcc == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_identity_list(dst->reply_to);
    dst->reply_to = NULL;
    if (src->reply_to && src->reply_to->ident) {
        dst->reply_to = identity_list_dup(src->reply_to);
        if (dst->reply_to == NULL)
            return PEP_OUT_OF_MEMORY;
    }

    free_stringlist(dst->in_reply_to);
    dst->in_reply_to = NULL;
    if (src->in_reply_to && src->in_reply_to->value) {
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
    if (src->keywords && src->keywords->value) {
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
    if (src == NULL)
        return NULL;

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

static PEP_STATUS encrypt_PGP_MIME(
    PEP_SESSION session,
    const message *src,
    stringlist_t *keys,
    message *dst
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    bool free_ptext = false;
    char *ptext = NULL;
    char *ctext = NULL;
    char *mimetext = NULL;
    size_t csize;
    assert(dst->longmsg == NULL);
    dst->enc_format = PEP_enc_PGP_MIME;

    if (src->shortmsg && strcmp(src->shortmsg, "pEp") != 0) {
        if (session->unencrypted_subject) {
            dst->shortmsg = strdup(src->shortmsg);
            assert(dst->shortmsg);
            if (dst->shortmsg == NULL)
                goto enomem;
            ptext = src->longmsg;
        }
        else {
            ptext = combine_short_and_long(src->shortmsg, src->longmsg);
            if (ptext == NULL)
                goto enomem;
            free_ptext = true;
        }
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
    _src->enc_format = PEP_enc_none;
    status = mime_encode_message(_src, true, &mimetext);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        goto pep_error;
    
    if (free_ptext){
        free(ptext);
        free_ptext=0;
    }
    free(_src);
    assert(mimetext);
    if (mimetext == NULL)
        goto pep_error;

    status = encrypt_and_sign(session, keys, mimetext, strlen(mimetext),
        &ctext, &csize);
    free(mimetext);
    if (ctext == NULL)
        goto pep_error;

    dst->longmsg = strdup("this message was encrypted with p≡p "
        "https://pEp-project.org");
    assert(dst->longmsg);
    if (dst->longmsg == NULL)
        goto enomem;

    char *v = strdup("Version: 1");
    assert(v);
    if (v == NULL)
        goto enomem;

    bloblist_t *_a = new_bloblist(v, strlen(v), "application/pgp-encrypted", NULL);
    if (_a == NULL)
        goto enomem;
    dst->attachments = _a;

    _a = bloblist_add(_a, ctext, csize, "application/octet-stream",
        "msg.asc");
    if (_a == NULL)
        goto enomem;

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    if (free_ptext)
        free(ptext);
    free(ctext);
    return status;
}

static PEP_STATUS encrypt_PGP_in_pieces(
    PEP_SESSION session,
    const message *src,
    stringlist_t *keys,
    message *dst
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    char *ctext = NULL;
    size_t csize;
    char *ptext = NULL;
    bool free_ptext = false;

    assert(dst->longmsg == NULL);
    assert(dst->attachments == NULL);

    dst->enc_format = PEP_enc_pieces;

    if (src->shortmsg && src->shortmsg[0] && strcmp(src->shortmsg, "pEp") != 0) {
        if (session->unencrypted_subject) {
            dst->shortmsg = strdup(src->shortmsg);
            assert(dst->shortmsg);
            if (dst->shortmsg == NULL)
                goto enomem;
            ptext = src->longmsg;
        }
        else {
            ptext = combine_short_and_long(src->shortmsg, src->longmsg);
            if (ptext == NULL)
                goto enomem;
            free_ptext = true;
        }

        status = encrypt_and_sign(session, keys, ptext, strlen(ptext), &ctext,
            &csize);
        if (free_ptext)
            free(ptext);
        free_ptext = false;
        if (ctext) {
            dst->longmsg = ctext;
        }
        else {
            goto pep_error;
        }
    }
    else if (src->longmsg && src->longmsg[0]) {
        ptext = src->longmsg;
        status = encrypt_and_sign(session, keys, ptext, strlen(ptext), &ctext,
            &csize);
        if (ctext) {
            dst->longmsg = ctext;
        }
        else {
            goto pep_error;
        }
    }
    else {
        dst->longmsg = strdup("");
        assert(dst->longmsg);
        if (dst->longmsg == NULL)
            goto enomem;
    }

    if (src->longmsg_formatted && src->longmsg_formatted[0]) {
        ptext = src->longmsg_formatted;
        status = encrypt_and_sign(session, keys, ptext, strlen(ptext), &ctext,
            &csize);
        if (ctext) {

            bloblist_t *_a = bloblist_add(dst->attachments, ctext, csize,
                "application/octet-stream", "PGPexch.htm.pgp");
            if (_a == NULL)
                goto enomem;
            if (dst->attachments == NULL)
                dst->attachments = _a;
        }
        else {
            goto pep_error;
        }
    }

    if (src->attachments) {
        if (dst->attachments == NULL) {
            dst->attachments = new_bloblist(NULL, 0, NULL, NULL);
            if (dst->attachments == NULL)
                goto enomem;
        }

        bloblist_t *_s = src->attachments;
        bloblist_t *_d = dst->attachments;

        for (int n = 0; _s; _s = _s->next) {
            if (_s->value == NULL && _s->size == 0) {
                _d = bloblist_add(_d, NULL, 0, _s->mime_type, _s->filename);
                if (_d == NULL)
                    goto enomem;
            }
            else {
                size_t psize = _s->size;
                ptext = _s->value;
                status = encrypt_and_sign(session, keys, ptext, psize, &ctext,
                    &csize);
                if (ctext) {
                    char *filename = NULL;

                    if (_s->filename) {
                        size_t len = strlen(_s->filename);
                        filename = calloc(1, len + 5);
                        if (filename == NULL)
                            goto enomem;

                        strlcpy(filename, _s->filename, len);
                        strlcpy(filename + len, ".pgp", 5);
                    }
                    else {
                        filename = calloc(1, 20);
                        if (filename == NULL)
                            goto enomem;

                        ++n;
                        n &= 0xffff;
                        snprintf(filename, 20, "Attachment%d.pgp", n);
                    }

                    _d = bloblist_add(_d, ctext, csize, "application/octet-stream",
                        filename);
                    free(filename);
                    if (_d == NULL)
                        goto enomem;
                }
                else {
                    goto pep_error;
                }
            }
        }
    }

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    if (free_ptext)
        free(ptext);
    return status;
}

static char * keylist_to_string(const stringlist_t *keylist)
{
    if (keylist) {
        size_t size = stringlist_length(keylist);

        const stringlist_t *_kl;
        for (_kl = keylist; _kl && _kl->value; _kl = _kl->next) {
            size += strlen(_kl->value);
        }

        char *result = calloc(1, size);
        if (result == NULL)
            return NULL;

        char *_r = result;
        for (_kl = keylist; _kl && _kl->value; _kl = _kl->next) {
            _r = stpcpy(_r, _kl->value);
            if (_kl->next && _kl->next->value)
                _r = stpcpy(_r, ",");
        }

        return result;
    }
    else {
        return NULL;
    }
}

static const char * color_to_string(PEP_color color)
{
    switch (color) {
    case PEP_rating_cannot_decrypt:
        return "cannot_decrypt";
    case PEP_rating_have_no_key:
        return "have_no_key";
    case PEP_rating_unencrypted:
        return "unencrypted";
    case PEP_rating_unencrypted_for_some:
        return "unencrypted_for_some";
    case PEP_rating_unreliable:
        return "unreliable";
    case PEP_rating_reliable:
        return "reliable";
    case PEP_rating_trusted:
        return "trusted";
    case PEP_rating_trusted_and_anonymized:
        return "trusted_and_anonymized";
    case PEP_rating_fully_anonymous:
        return "fully_anonymous";
    case PEP_rating_mistrust:
        return "mistrust";
    case PEP_rating_b0rken:
        return "b0rken";
    case PEP_rating_under_attack:
        return "unter_attack";
    default:
        return "undefined";
    }
}

static void decorate_message(
    message *msg,
    PEP_color color,
    stringlist_t *keylist
    )
{
    assert(msg);

    add_opt_field(msg, "X-pEp-Version", PEP_VERSION);
    
    if (color != PEP_rating_undefined)
        add_opt_field(msg, "X-EncStatus", color_to_string(color));

    if (keylist) {
        char *_keylist = keylist_to_string(keylist);
        add_opt_field(msg, "X-KeyList", _keylist);
        free(_keylist);
    }
}

static PEP_color _rating(PEP_comm_type ct, PEP_color color)
{
    if (ct == PEP_ct_unknown)
        return PEP_rating_undefined;

    else if (ct == PEP_ct_compromized)
        return PEP_rating_under_attack;

    else if (ct == PEP_ct_mistrusted)
        return PEP_rating_mistrust;
    
    if (color == PEP_rating_unencrypted_for_some)
        return PEP_rating_unencrypted_for_some;

    if (ct == PEP_ct_no_encryption || ct == PEP_ct_no_encrypted_channel ||
            ct == PEP_ct_my_key_not_included) {
        if (color > PEP_rating_unencrypted_for_some)
            return PEP_rating_unencrypted_for_some;
        else
            return PEP_rating_unencrypted;
    }

    if (color == PEP_rating_unencrypted)
        return PEP_rating_unencrypted_for_some;

    if (ct >= PEP_ct_confirmed_enc_anon)
        return PEP_rating_trusted_and_anonymized;

    else if (ct >= PEP_ct_strong_encryption)
        return PEP_rating_trusted;

    else if (ct >= PEP_ct_strong_but_unconfirmed && ct < PEP_ct_confirmed)
        return PEP_rating_reliable;

    else
        return PEP_rating_unreliable;
}

static bool is_encrypted_attachment(const bloblist_t *blob)
{
    char *ext;

    assert(blob);

    if (blob == NULL || blob->filename == NULL)
        return false;
    
    ext = strrchr(blob->filename, '.');
    if (ext == NULL)
        return false;

    if (strcmp(blob->mime_type, "application/octet-stream") == 0) {
        if (strcmp(ext, ".pgp") == 0 || strcmp(ext, ".gpg") == 0 ||
            strcmp(ext, ".asc") == 0)
            return true;
    }
    else if (strcmp(blob->mime_type, "text/plain") == 0) {
        if (strcmp(ext, ".asc") == 0)
            return true;
    }

    return false;
}

static bool is_encrypted_html_attachment(const bloblist_t *blob)
{
    assert(blob);
    assert(blob->filename);
    if (blob == NULL || blob->filename == NULL)
        return false;

    if (strncmp(blob->filename, "PGPexch.htm.", 12) == 0) {
        if (strcmp(blob->filename + 11, ".pgp") == 0 ||
            strcmp(blob->filename + 11, ".asc") == 0)
            return true;
    }

    return false;
}

static char * without_double_ending(const char *filename)
{
    assert(filename);
    if (filename == NULL)
        return NULL;
    
    char *ext = strrchr(filename, '.');
    if (ext == NULL)
        return NULL;

    char *result = strndup(filename, ext - filename);
    assert(result);
    return result;
}

static PEP_color decrypt_color(PEP_STATUS status)
{
    switch (status) {
    case PEP_UNENCRYPTED:
    case PEP_VERIFIED:
    case PEP_VERIFY_NO_KEY:
    case PEP_VERIFIED_AND_TRUSTED:
        return PEP_rating_unencrypted;

    case PEP_DECRYPTED:
        return PEP_rating_unreliable;

    case PEP_DECRYPTED_AND_VERIFIED:
        return PEP_rating_reliable;

    case PEP_DECRYPT_NO_KEY:
        return PEP_rating_have_no_key;

    case PEP_DECRYPT_WRONG_FORMAT:
    case PEP_CANNOT_DECRYPT_UNKNOWN:
        return PEP_rating_cannot_decrypt;

    default:
        return PEP_rating_undefined;
    }
}

static PEP_color key_color(PEP_SESSION session, const char *fpr)
{
    PEP_comm_type comm_type = PEP_ct_unknown;

    assert(session);
    assert(fpr);
    
    if (session == NULL || fpr == NULL)
        return PEP_rating_undefined;

    PEP_STATUS status = get_key_rating(session, fpr, &comm_type);
    if (status != PEP_STATUS_OK)
        return PEP_rating_undefined;

    return _rating(comm_type, PEP_rating_undefined);
}

static PEP_color keylist_color(PEP_SESSION session, stringlist_t *keylist)
{
    PEP_color color = PEP_rating_reliable;

    assert(keylist && keylist->value);
    if (keylist == NULL || keylist->value == NULL)
        return PEP_rating_undefined;

    stringlist_t *_kl;
    for (_kl = keylist; _kl && _kl->value; _kl = _kl->next) {
        PEP_comm_type ct;
        PEP_STATUS status;

        PEP_color _color = key_color(session, _kl->value);
        if (_color <= PEP_rating_mistrust)
            return _color;

        if (color == PEP_rating_undefined)
            color = _color;

        if (_color >= PEP_rating_reliable) {
            status = least_trust(session, _kl->value, &ct);
            if (status != PEP_STATUS_OK)
                return PEP_rating_undefined;
            if (ct == PEP_ct_unknown)
                color = PEP_rating_unencrypted_for_some;
            else
                color = _rating(ct, color);
        }
        else if (_color == PEP_rating_unencrypted) {
            if (color > PEP_rating_unencrypted_for_some)
                color = PEP_rating_unencrypted_for_some;
        }
    }

    return color;
}

static PEP_comm_type _get_comm_type(
    PEP_SESSION session,
    PEP_comm_type max_comm_type,
    pEp_identity *ident
    )
{
    PEP_STATUS status = update_identity(session, ident);

    if (max_comm_type == PEP_ct_compromized)
        return PEP_ct_compromized;
    
    if (max_comm_type == PEP_ct_mistrusted)
        return PEP_ct_mistrusted;

    if (status == PEP_STATUS_OK) {
        if (ident->comm_type == PEP_ct_compromized)
            return PEP_ct_compromized;
        else if (ident->comm_type == PEP_ct_mistrusted)
            return PEP_ct_mistrusted;
        else
            return MIN(max_comm_type, ident->comm_type);
    }
    else {
        return PEP_ct_unknown;
    }
}

static void free_bl_entry(bloblist_t *bl)
{
    if (bl) {
        free(bl->value);
        free(bl->mime_type);
        free(bl->filename);
        free(bl);
    }
}

static bool is_key(const bloblist_t *bl)
{
    return (// workaround for Apple Mail bugs
            (is_mime_type(bl, "application/x-apple-msg-attachment") &&
             is_fileending(bl, ".asc")) ||
            // as binary, by file name
            ((bl->mime_type == NULL ||
              is_mime_type(bl, "application/octet-stream")) &&
             (is_fileending(bl, ".pgp") || is_fileending(bl, ".gpg") ||
                    is_fileending(bl, ".key") || is_fileending(bl, ".asc"))) ||
            // explicit mime type 
            is_mime_type(bl, "application/pgp-keys") ||
            // as text, by file name
            (is_mime_type(bl, "text/plain") &&
             (is_fileending(bl, ".pgp") || is_fileending(bl, ".gpg") ||
                    is_fileending(bl, ".key") || is_fileending(bl, ".asc")))
           );
}

static void remove_attached_keys(message *msg)
{
    if (msg) {
        bloblist_t *last = NULL;
        for (bloblist_t *bl = msg->attachments; bl && bl->value; ) {
            bloblist_t *next = bl->next;

            if (is_key(bl)) {
                if (last) {
                    last->next = next;
                }
                else {
                    msg->attachments = next;
                }
                free_bl_entry(bl);
            }
            else {
                last = bl;
            }
            bl = next;
        }
    }
}

bool import_attached_keys(
        PEP_SESSION session, 
        const message *msg,
        identity_list **private_idents
    )
{
    assert(session);
    assert(msg);
    
    if (session == NULL || msg == NULL)
        return false;

    bool remove = false;

    bloblist_t *bl;
    int i = 0;
    for (bl = msg->attachments; i < MAX_KEYS_TO_IMPORT && bl && bl->value;
            bl = bl->next, i++) 
    {
        if (bl && bl->value && bl->size && bl->size < MAX_KEY_SIZE
                && is_key(bl)) 
        {
            import_key(session, bl->value, bl->size, private_idents);
            remove = true;
        }
    }
    return remove;
}


PEP_STATUS _attach_key(PEP_SESSION session, const char* fpr, message *msg)
{
    char *keydata;
    size_t size;
    bloblist_t *bl;

    PEP_STATUS status = export_key(session, fpr, &keydata, &size);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        return status;
    assert(size);
    
    bl = bloblist_add(msg->attachments, keydata, size, "application/pgp-keys",
                      "pEpkey.asc");
    
    if (msg->attachments == NULL && bl)
        msg->attachments = bl;

    return PEP_STATUS_OK;
}

#define ONE_WEEK (7*24*3600)

void attach_own_key(PEP_SESSION session, message *msg)
{
    assert(session);
    assert(msg);
    
    if (msg->dir == PEP_dir_incoming)
        return;

    assert(msg->from && msg->from->fpr);
    if (msg->from == NULL || msg->from->fpr == NULL)
        return;

    if(_attach_key(session, msg->from->fpr, msg) != PEP_STATUS_OK)
        return;
    
    char *revoked_fpr = NULL;
    uint64_t revocation_date = 0;
    
    if(get_revoked(session, msg->from->fpr,
                   &revoked_fpr, &revocation_date) == PEP_STATUS_OK &&
       revoked_fpr != NULL)
    {
        time_t now = time(NULL);
        
        if (now < (time_t)revocation_date + ONE_WEEK)
        {
            _attach_key(session, revoked_fpr, msg);
        }
    }
    free(revoked_fpr);
}

PEP_cryptotech determine_encryption_format(message *msg)
{
    assert(msg);
    
    if (is_PGP_message_text(msg->longmsg)) {
        msg->enc_format = PEP_enc_pieces;
        return PEP_crypt_OpenPGP;
    }
    else if (msg->attachments && msg->attachments->next &&
            is_mime_type(msg->attachments, "application/pgp-encrypted") &&
            is_PGP_message_text(msg->attachments->next->value)
        ) {
        msg->enc_format = PEP_enc_PGP_MIME;
        return PEP_crypt_OpenPGP;
    }
    else {
        msg->enc_format = PEP_enc_none;
        return PEP_crypt_none;
    }
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

    assert(session);
    assert(src);
    assert(dst);
    assert(enc_format != PEP_enc_none);

    if (!(session && src && dst && enc_format != PEP_enc_none))
        return PEP_ILLEGAL_VALUE;

    if (src->dir == PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;
    
    determine_encryption_format(src);
    if (src->enc_format != PEP_enc_none)
        return PEP_ILLEGAL_VALUE;

    *dst = NULL;

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

    bool dest_keys_found = true;
    PEP_comm_type max_comm_type = PEP_ct_pEp;

    identity_list * _il;
    
    if ((_il = src->bcc) && _il->ident)
    {
        // BCC limited support:
        //     - App splits mails with BCC in multiple mails.
        //     - Each email is encrypted separately
        
        if(_il->next || (src->to && src->to->ident) || (src->cc && src->cc->ident))
        {
            // Only one Bcc with no other recipient allowed for now
            return PEP_ILLEGAL_VALUE;
        }
        
        PEP_STATUS _status = update_identity(session, _il->ident);
        if (_status != PEP_STATUS_OK) {
            status = _status;
            goto pep_error;
        }
        
        if (_il->ident->fpr && _il->ident->fpr[0]) {
            _k = stringlist_add(_k, _il->ident->fpr);
            if (_k == NULL)
                goto enomem;
            max_comm_type = _get_comm_type(session, max_comm_type,
                                           _il->ident);
        }
        else {
            dest_keys_found = false;
            status = PEP_KEY_NOT_FOUND;
        }        
    }
    else
    {
        for (_il = src->to; _il && _il->ident; _il = _il->next) {
            PEP_STATUS _status = update_identity(session, _il->ident);
            if (_status != PEP_STATUS_OK) {
                status = _status;
                goto pep_error;
            }

            if (_il->ident->fpr && _il->ident->fpr[0]) {
                _k = stringlist_add(_k, _il->ident->fpr);
                if (_k == NULL)
                    goto enomem;
                max_comm_type = _get_comm_type(session, max_comm_type,
                                               _il->ident);
            }
            else {
                dest_keys_found = false;
                status = PEP_KEY_NOT_FOUND;
            }
        }

        for (_il = src->cc; _il && _il->ident; _il = _il->next) {
            PEP_STATUS _status = update_identity(session, _il->ident);
            if (_status != PEP_STATUS_OK)
            {
                status = _status;
                goto pep_error;
            }

            if (_il->ident->fpr && _il->ident->fpr[0]) {
                _k = stringlist_add(_k, _il->ident->fpr);
                if (_k == NULL)
                    goto enomem;
                max_comm_type = _get_comm_type(session, max_comm_type,
                                               _il->ident);
            }
            else {
                dest_keys_found = false;
                status = PEP_KEY_NOT_FOUND;
            }
        }
    }
    
    if (!dest_keys_found ||
        stringlist_length(keys) == 0 ||
        _rating(max_comm_type,
                PEP_rating_undefined) < PEP_rating_reliable)
    {
        free_stringlist(keys);
        if (!session->passive_mode)
            attach_own_key(session, src);
        return PEP_UNENCRYPTED;
    }
    else {
        msg = clone_to_empty_message(src);
        if (msg == NULL)
            goto enomem;

        attach_own_key(session, src);

        switch (enc_format) {
        case PEP_enc_PGP_MIME:
        case PEP_enc_PEP: // BUG: should be implemented extra
            status = encrypt_PGP_MIME(session, src, keys, msg);
            break;

        case PEP_enc_pieces:
            status = encrypt_PGP_in_pieces(session, src, keys, msg);
            break;

        /* case PEP_enc_PEP:
            // TODO: implement
            NOT_IMPLEMENTED */

        default:
            assert(0);
            status = PEP_ILLEGAL_VALUE;
            goto pep_error;
        }
        
        if (status == PEP_OUT_OF_MEMORY)
            goto enomem;
        
        if (status != PEP_STATUS_OK)
            goto pep_error;
    }

    free_stringlist(keys);

    if (msg && msg->shortmsg == NULL) {
        msg->shortmsg = strdup("pEp");
        assert(msg->shortmsg);
        if (msg->shortmsg == NULL)
            goto enomem;
    }

    if (msg)
        decorate_message(msg, PEP_rating_undefined, NULL);

    *dst = msg;
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free_stringlist(keys);
    free_message(msg);

    return status;
}

static bool is_a_pEpmessage(const message *msg)
{
    for (stringpair_list_t *i = msg->opt_fields; i && i->value ; i=i->next) {
        if (strcasecmp(i->value->key, "X-pEp-Version") == 0)
            return true;
    }
    return false;
}

// update comm_type to pEp_ct_pEp if needed

static PEP_STATUS _update_identity_for_incoming_message(
        PEP_SESSION session,
        const message *src
    )
{
    PEP_STATUS status;
    if (src->from && src->from->address) {
        status = update_identity(session, src->from);
        if (status == PEP_STATUS_OK
                && is_a_pEpmessage(src)
                && src->from->comm_type >= PEP_ct_OpenPGP_unconfirmed
                && src->from->comm_type != PEP_ct_pEp_unconfirmed
                && src->from->comm_type != PEP_ct_pEp)
        {
            src->from->comm_type |= PEP_ct_pEp_unconfirmed;
            status = update_identity(session, src->from);
        }
        return status;
    }
    return PEP_ILLEGAL_VALUE;
}

DYNAMIC_API PEP_STATUS _decrypt_message(
        PEP_SESSION session,
        message *src,
        message **dst,
        stringlist_t **keylist,
        PEP_color *color,
        PEP_decrypt_flags_t *flags, 
        identity_list **private_il
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    PEP_STATUS decrypt_status = PEP_CANNOT_DECRYPT_UNKNOWN;
    message *msg = NULL;
    char *ctext;
    size_t csize;
    char *ptext = NULL;
    size_t psize;
    stringlist_t *_keylist = NULL;

    assert(session);
    assert(src);
    assert(dst);
    assert(keylist);
    assert(color);
    assert(flags);

    if (!(session && src && dst && keylist && color && flags))
        return PEP_ILLEGAL_VALUE;

    *flags = 0;

    // Private key in unencrypted mail are ignored -> NULL
    bool imported_keys = import_attached_keys(session, src, NULL);

    // Update src->from in case we just imported a key
    // we would need to check signature
    status = _update_identity_for_incoming_message(session, src);
    if(status != PEP_STATUS_OK)
        return status;

    PEP_cryptotech crypto = determine_encryption_format(src);

    *dst = NULL;
    *keylist = NULL;
    *color = PEP_rating_undefined;
 
    switch (src->enc_format) {
        case PEP_enc_none:
            *color = PEP_rating_unencrypted;
            if (imported_keys)
                remove_attached_keys(src);
            return PEP_UNENCRYPTED;

        case PEP_enc_PGP_MIME:
            ctext = src->attachments->next->value;
            csize = src->attachments->next->size;
            break;

        case PEP_enc_pieces:
            ctext = src->longmsg;
            csize = strlen(ctext);
            break;

        default:
            NOT_IMPLEMENTED
    }
    status = cryptotech[crypto].decrypt_and_verify(session, ctext,
                                                   csize, &ptext, &psize, &_keylist);
    if (status > PEP_CANNOT_DECRYPT_UNKNOWN)
        goto pep_error;

    decrypt_status = status;

    bool imported_private_key_address = false; 

    if (ptext) {
        switch (src->enc_format) {
            case PEP_enc_PGP_MIME:
                status = mime_decode_message(ptext, psize, &msg);
                if (status != PEP_STATUS_OK)
                    goto pep_error;
                break;

            case PEP_enc_pieces:
                msg = clone_to_empty_message(src);
                if (msg == NULL)
                    goto enomem;

                msg->longmsg = ptext;
                ptext = NULL;

                bloblist_t *_m = msg->attachments;
                if (_m == NULL && src->attachments && src->attachments->value) {
                    msg->attachments = new_bloblist(NULL, 0, NULL, NULL);
                    _m = msg->attachments;
                }

                bloblist_t *_s;
                for (_s = src->attachments; _s; _s = _s->next) {
                    if (_s->value == NULL && _s->size == 0){
                        _m = bloblist_add(_m, NULL, 0, _s->mime_type, _s->filename);
                        if (_m == NULL)
                            goto enomem;

                    }
                    else if (is_encrypted_attachment(_s)) {
                        stringlist_t *_keylist = NULL;
                        char *attctext  = _s->value;
                        size_t attcsize = _s->size;

                        free(ptext);
                        ptext = NULL;

                        status = decrypt_and_verify(session, attctext, attcsize,
                                &ptext, &psize, &_keylist);
                        free_stringlist(_keylist);

                        if (ptext) {
                            if (is_encrypted_html_attachment(_s)) {
                                msg->longmsg_formatted = ptext;
                                ptext = NULL;
                            }
                            else {
                                static const char * const mime_type = "application/octet-stream";
                                char * const filename =
                                    without_double_ending(_s->filename);
                                if (filename == NULL)
                                    goto enomem;

                                _m = bloblist_add(_m, ptext, psize, mime_type,
                                    filename);
                                free(filename);
                                if (_m == NULL)
                                    goto enomem;

                                ptext = NULL;

                                if (msg->attachments == NULL)
                                    msg->attachments = _m;
                            }
                        }
                        else {
                            char *copy = malloc(_s->size);
                            assert(copy);
                            if (copy == NULL)
                                goto enomem;
                            memcpy(copy, _s->value, _s->size);
                            _m = bloblist_add(_m, copy, _s->size, _s->mime_type, _s->filename);
                            if (_m == NULL)
                                goto enomem;
                        }
                    }
                    else {
                        char *copy = malloc(_s->size);
                        assert(copy);
                        if (copy == NULL)
                            goto enomem;
                        memcpy(copy, _s->value, _s->size);
                        _m = bloblist_add(_m, copy, _s->size, _s->mime_type, _s->filename);
                        if (_m == NULL)
                            goto enomem;
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

                if (src->shortmsg == NULL || strcmp(src->shortmsg, "pEp") == 0)
                {
                    char * shortmsg;
                    char * longmsg;

                    int r = separate_short_and_long(msg->longmsg, &shortmsg,
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
                    assert(msg->shortmsg);
                    if (msg->shortmsg == NULL)
                        goto enomem;
                }
                break;

            default:
                // BUG: must implement more
                NOT_IMPLEMENTED
        }
       
        // check for private key in decrypted message attachement while inporting
        identity_list *_private_il = NULL;
        imported_keys = import_attached_keys(session, msg, &_private_il);
        if (_private_il && 
            identity_list_length(_private_il) == 1 &&
            _private_il->ident->address)
        {
            imported_private_key_address = true;
        }

        if(private_il && imported_private_key_address){
            *private_il = _private_il;
        }else{
            free_identity_list(_private_il);
        }
         
        if(decrypt_status == PEP_DECRYPTED){

            // TODO optimize if import_attached_keys didn't import any key
            
            // In case message did decrypt, but no valid signature could be found
            // then retry decrypt+verify after importing key.

            // Update msg->from in case we just imported a key
            // we would need to check signature

            status = _update_identity_for_incoming_message(session, src);
            if(status != PEP_STATUS_OK)
                goto pep_error;
            
            char *re_ptext = NULL;
            size_t re_psize;
            
            free_stringlist(_keylist);
            _keylist = NULL;

            status = cryptotech[crypto].decrypt_and_verify(session, ctext,
                csize, &re_ptext, &re_psize, &_keylist);
            
            free(re_ptext);
            
            if (status > PEP_CANNOT_DECRYPT_UNKNOWN)
                goto pep_error;
            
            decrypt_status = status;
        }
        
        *color = decrypt_color(decrypt_status);
        
        if (*color > PEP_rating_mistrust) {
            PEP_color kl_color = PEP_rating_undefined;
            
            if (_keylist)
                kl_color = keylist_color(session, _keylist);
            
            if (kl_color <= PEP_rating_mistrust) {
                *color = kl_color;
            }
            else if (*color >= PEP_rating_reliable &&
                     kl_color < PEP_rating_reliable) {
                *color = PEP_rating_unreliable;
            }
            else if (*color >= PEP_rating_reliable &&
                     kl_color >= PEP_rating_reliable) {
                if (!(src->from && src->from->user_id && src->from->user_id[0])) {
                    *color = PEP_rating_unreliable;
                }
                else {
                    char *fpr = _keylist->value;
                    pEp_identity *_from = new_identity(src->from->address, fpr,
                                                       src->from->user_id, src->from->username);
                    if (_from == NULL)
                        goto enomem;
                    status = update_identity(session, _from);
                    if (_from->comm_type != PEP_ct_unknown)
                        *color = _rating(_from->comm_type, PEP_rating_undefined);
                    free_identity(_from);
                    if (status != PEP_STATUS_OK)
                        goto pep_error;
                }
            }
        }
    }
    else
    {
        *color = decrypt_color(decrypt_status);
        goto pep_error;
    }

    // Case of own key imported from own trusted message
    if (// Message have been reliably decrypted 
        msg &&
        *color >= PEP_rating_green &&
        imported_private_key_address &&
        // to is [own]
        msg->to->ident->user_id &&
        strcmp(msg->to->ident->user_id, PEP_OWN_USERID) == 0 
        )
    {
        *flags |= PEP_decrypt_flag_own_private_key;
    }

    if (msg) {
        decorate_message(msg, *color, _keylist);
        if (imported_keys)
            remove_attached_keys(msg);
    }

    *dst = msg;
    *keylist = _keylist;

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free(ptext);
    free_message(msg);
    free_stringlist(_keylist);

    return status;
}

DYNAMIC_API PEP_STATUS decrypt_message(
        PEP_SESSION session,
        message *src,
        message **dst,
        stringlist_t **keylist,
        PEP_color *color,
        PEP_decrypt_flags_t *flags 
    )
{
    return _decrypt_message( session, src, dst, keylist, color, flags, NULL );
}

DYNAMIC_API PEP_STATUS own_message_private_key_details(
        PEP_SESSION session,
        message *msg,
        pEp_identity **ident 
    )
{
    assert(session);
    assert(msg);
    assert(ident);

    if (!(session && msg && ident))
        return PEP_ILLEGAL_VALUE;

    message *dst; 
    stringlist_t *keylist;
    PEP_color color;
    PEP_decrypt_flags_t flags; 

    *ident = NULL;

    identity_list *private_il = NULL;
    PEP_STATUS status = _decrypt_message(session, msg,  &dst, &keylist, &color, &flags, &private_il);

    if (status == PEP_STATUS_OK &&
        flags & PEP_decrypt_flag_own_private_key &&
        private_il)
    {
        *ident = identity_dup(private_il->ident);
    }

    free_identity_list(private_il);

    return status;

}

static void _max_comm_type_from_identity_list(
        identity_list *identities, 
        PEP_SESSION session,
        PEP_comm_type *max_comm_type,
        bool *comm_type_determined
    )
{
    identity_list * il;
    for (il = identities; il != NULL; il = il->next)
    {
        if (il->ident)
        {
            PEP_STATUS status = update_identity(session, il->ident);
            if (status == PEP_STATUS_OK)
            {
                *max_comm_type = _get_comm_type(session, *max_comm_type,
                        il->ident);
                *comm_type_determined = true;
            }
        }
    }
}

DYNAMIC_API PEP_STATUS outgoing_message_color(
        PEP_SESSION session,
        message *msg,
        PEP_color *color
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    PEP_comm_type max_comm_type = PEP_ct_pEp;
    bool comm_type_determined = false;

    assert(session);
    assert(msg);
    assert(msg->from);
    assert(msg->dir == PEP_dir_outgoing);
    assert(color);

    if (!(session && msg && color))
        return PEP_ILLEGAL_VALUE;

    if (msg->from == NULL || msg->dir != PEP_dir_outgoing)
        return PEP_ILLEGAL_VALUE;

    *color = PEP_rating_undefined;

    status = myself(session, msg->from);
    if (status != PEP_STATUS_OK)
        return status;

    _max_comm_type_from_identity_list(msg->to, session,
                                      &max_comm_type, &comm_type_determined);

    _max_comm_type_from_identity_list(msg->cc, session,
                                      &max_comm_type, &comm_type_determined);
        
    _max_comm_type_from_identity_list(msg->bcc, session,
                                      &max_comm_type, &comm_type_determined);

    if (comm_type_determined == false)
        *color = PEP_rating_undefined;
    else
        *color = MAX(_rating(max_comm_type, PEP_rating_undefined),
                PEP_rating_unencrypted);

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS identity_color(
        PEP_SESSION session,
        pEp_identity *ident,
        PEP_color *color
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(ident);
    assert(color);

    if (!(session && ident && color))
        return PEP_ILLEGAL_VALUE;

    if (ident->me)
        status = myself(session, ident);
    else
        status = update_identity(session, ident);

    if (status == PEP_STATUS_OK)
        *color = _rating(ident->comm_type, PEP_rating_undefined);

    return status;
}

DYNAMIC_API PEP_STATUS get_binary_path(PEP_cryptotech tech, const char **path)
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(path);
    if (path == NULL)
        return PEP_ILLEGAL_VALUE;

    if (cryptotech[tech].binary_path == NULL)
        *path = NULL;
    else
        status = cryptotech[tech].binary_path(path);

    return status;
}

