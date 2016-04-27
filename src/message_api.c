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

static bool is_fileending(const bloblist_t *bl, const char *fe)
{
    assert(fe);

    if (bl == NULL || bl->filename == NULL)
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
            return;

        if (msg->opt_fields == NULL)
            msg->opt_fields = field;
    }
}

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
    char *ctext;
    char *_ctext = NULL;
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

    bloblist_t *_a = new_bloblist(v, 11, "application/pgp-encrypted", NULL);
    if (_a == NULL)
        goto enomem;
    dst->attachments = _a;

    _ctext = malloc(csize);
    assert(_ctext);
    if (_ctext == NULL)
        goto enomem;
    memcpy(_ctext, ctext, csize);

    _a = bloblist_add(_a, _ctext, csize, "application/octet-stream",
        "msg.asc");
    if (_a == NULL)
        goto enomem;

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    if (free_ptext)
        free(ptext);
    free(_ctext);
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
    char *ctext;
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
            dst->longmsg = strndup(ctext, csize);
            assert(dst->longmsg);
            if (dst->longmsg == NULL)
                goto enomem;
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
            dst->longmsg = strndup(ctext, csize);
            assert(dst->longmsg);
            if (dst->longmsg == NULL)
                goto enomem;
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
            char *_ctext = malloc(csize);
            assert(_ctext);
            if (_ctext == NULL)
                goto enomem;
            memcpy(_ctext, ctext, csize);

            bloblist_t *_a = bloblist_add(dst->attachments, _ctext, csize,
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

        for (int n = 0; _s && _s->value; _s = _s->next) {
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

                    strcpy(filename, _s->filename);
                    strcpy(filename + len, ".pgp");
                }
                else {
                    filename = calloc(1, 20);
                    if (filename == NULL)
                        goto enomem;

                    ++n;
                    n &= 0xffff;
                    snprintf(filename, 20, "Attachment%d.pgp", n);
                }

                char *_ctext = malloc(csize);
                assert(_ctext);
                if (_ctext == NULL)
                    goto enomem;
                memcpy(_ctext, ctext, csize);

                _d = bloblist_add(_d, _ctext, csize, "application/octet-stream",
                    filename);
                if (_d == NULL)
                    goto enomem;
            }
            else {
                goto pep_error;
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

    add_opt_field(msg, "X-pEp-Version", "1.0");
    
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

    if (blob->filename == NULL)
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

void import_attached_keys(PEP_SESSION session, const message *msg)
{
    assert(session);
    assert(msg);

    bloblist_t *bl;
    for (bl = msg->attachments; bl && bl->value; bl = bl->next) {
        assert(bl && bl->value && bl->size);

        // workaround for Apple Mail bugs
        if (is_mime_type(bl, "application/x-apple-msg-attachment")) {
            if (is_fileending(bl, ".asc")) {
                if (strlen(bl->filename) == 14 &&
                        bl->filename[0] == '0' && bl->filename[1] == 'x')
                    import_key(session, bl->value, bl->size);
                else if (strlen(bl->filename) == 12)
                    import_key(session, bl->value, bl->size);
            }
        }
        else if (bl->mime_type == NULL ||
                    is_mime_type(bl, "application/octet-stream")) {
            if (is_fileending(bl, ".pgp") || is_fileending(bl, ".gpg") ||
                    is_fileending(bl, ".key") || is_fileending(bl, ".asc"))
                import_key(session, bl->value, bl->size);
        }
        else if (is_mime_type(bl, "application/pgp-keys")) {
            import_key(session, bl->value, bl->size);
        }
        else if (is_mime_type(bl, "text/plain")) {
            if (is_fileending(bl, ".pgp") || is_fileending(bl, ".gpg") ||
                    is_fileending(bl, ".key") || is_fileending(bl, ".asc"))
                import_key(session, bl->value, bl->size);
        }
    }
    if(msg->from && msg->from->user_id && msg->from->address)
        update_identity(session, msg->from);
}

void attach_own_key(PEP_SESSION session, message *msg)
{
    char *keydata;
    size_t size;
    bloblist_t *bl;

    assert(session);
    assert(msg);

    assert(msg->from && msg->from->fpr);
    if (msg->from == NULL || msg->from->fpr == NULL)
        return;

    PEP_STATUS status = export_key(session, msg->from->fpr, &keydata, &size);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        return;
    assert(size);

    bl = bloblist_add(msg->attachments, keydata, size, "application/pgp-keys",
            "pEpkey.asc");
    if (msg->attachments == NULL && bl)
        msg->attachments = bl;
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

    if (!(session && src && dst))
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
    
    if (enc_format == PEP_enc_none)
    {
        attach_own_key(session, src);
        return PEP_UNENCRYPTED;
    }
    
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
        
        if(_il->next || src->to || src->cc)
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

DYNAMIC_API PEP_STATUS decrypt_message(
        PEP_SESSION session,
        message *src,
        message **dst,
        stringlist_t **keylist,
        PEP_color *color
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

    if (!(session && src && dst && keylist && color))
        return PEP_ILLEGAL_VALUE;

    import_attached_keys(session, src);
    PEP_cryptotech crypto = determine_encryption_format(src);

    *dst = NULL;
    *keylist = NULL;
    *color = PEP_rating_undefined;
 
    switch (src->enc_format) {
        case PEP_enc_none:
            *color = PEP_rating_unencrypted;
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

                msg->longmsg = strdup(ptext);
                assert(msg->longmsg);
                if (msg->longmsg == NULL)
                    goto enomem;

                bloblist_t *_m = msg->attachments;
                if (_m == NULL && src->attachments && src->attachments->value) {
                    msg->attachments = new_bloblist(NULL, 0, NULL, NULL);
                    _m = msg->attachments;
                }

                bloblist_t *_s;
                for (_s = src->attachments; _s && _s->value; _s = _s->next) {
                    if (is_encrypted_attachment(_s)) {
                        stringlist_t *_keylist = NULL;
                        char *attctext;
                        size_t attcsize;

                        attctext = _s->value;
                        attcsize = _s->size;

                        status = decrypt_and_verify(session, attctext, attcsize,
                                &ptext, &psize, &_keylist);
                        free_stringlist(_keylist);

                        if (ptext) {
                            if (is_encrypted_html_attachment(_s)) {
                                msg->longmsg_formatted = strdup(ptext);
                                assert(msg->longmsg_formatted);
                                if (msg->longmsg_formatted == NULL)
                                    goto pep_error;
                            }
                            else {
                                char * mime_type = "application/octet-stream";
                                char * filename =
                                    without_double_ending(_s->filename);
                                if (filename == NULL)
                                    goto enomem;

                                char *_ptext = malloc(psize);
                                assert(_ptext);
                                if (_ptext == NULL)
                                    goto enomem;
                                memcpy(_ptext, ptext, psize);

                                _m = bloblist_add(_m, _ptext, psize, mime_type,
                                    filename);
                                if (_m == NULL)
                                    goto enomem;

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
                    assert(msg->shortmsg);
                    if (msg->shortmsg == NULL)
                        goto enomem;
                }
                break;

            default:
                // BUG: must implement more
                NOT_IMPLEMENTED
        }
        
        import_attached_keys(session, msg);
        
        if(decrypt_status == PEP_DECRYPTED){
            
            // In case message did decrypt, but no valid signature could be found
            // then retry decrypt+verify after importing key.
            // TODO optimize if import_attached_keys didn't import any key
            
            char *re_ptext = NULL;
            size_t re_psize;
            
            free_stringlist(_keylist);
            _keylist = NULL;

            status = cryptotech[crypto].decrypt_and_verify(session, ctext,
                csize, &re_ptext, &re_psize, &_keylist);
            
            if(re_ptext)
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

    if (msg)
        decorate_message(msg, *color, _keylist);

    *dst = msg;
    *keylist = _keylist;

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free_message(msg);
    free_stringlist(_keylist);

    return status;
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
    identity_list * il;

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

    for (il = msg->to; il != NULL; il = il->next)
    {
        if (il->ident)
        {
            update_identity(session, il->ident);
            max_comm_type = _get_comm_type(session, max_comm_type,
                    il->ident);
            comm_type_determined = true;
        }
    }

    for (il = msg->cc; il != NULL; il = il->next)
    {
        if (il->ident)
        {
            update_identity(session, il->ident);
            max_comm_type = _get_comm_type(session, max_comm_type,
                    il->ident);
            comm_type_determined = true;
        }
    }
        
    for (il = msg->bcc; il != NULL; il = il->next)
    {
        if (il->ident)
        {
            update_identity(session, il->ident);
            max_comm_type = _get_comm_type(session, max_comm_type,
                                           il->ident);
            comm_type_determined = true;
        }
    }

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

