// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "message_api.h"

#include "platform.h"
#include "mime.h"
#include "sync_fsm.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>


#ifndef _MIN
#define _MIN(A, B) ((B) > (A) ? (A) : (B))
#endif
#ifndef _MAX
#define _MAX(A, B) ((B) > (A) ? (B) : (A))
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

void add_opt_field(message *msg, const char *name, const char *value)
{
    assert(msg && name && value);

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

    const size_t bufsize = SUBJ_LEN + strlen(shortmsg) + NL_LEN + strlen(longmsg) + 1;
    char * ptext = calloc(1, bufsize);
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

    free_stringpair_list(dst->opt_fields);
    dst->opt_fields = NULL;
    if (src->opt_fields) {
        dst->opt_fields = stringpair_list_dup(src->opt_fields);
        if (dst->opt_fields == NULL)
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
    message *dst,
    PEP_encrypt_flags_t flags
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

    if (flags & PEP_encrypt_flag_force_unsigned)
        status = encrypt_only(session, keys, mimetext, strlen(mimetext),
            &ctext, &csize);
    else
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
    message *dst,
    PEP_encrypt_flags_t flags
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

    bool nosign = (flags & PEP_encrypt_flag_force_unsigned);

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

        if (nosign)
            status = encrypt_only(session, keys, ptext, strlen(ptext), &ctext,
                &csize);
        else 
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
        if (nosign)
            status = encrypt_only(session, keys, ptext, strlen(ptext), &ctext,
                &csize);
        else 
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
        if (nosign)
            status = encrypt_only(session, keys, ptext, strlen(ptext), &ctext,
                &csize);
        else 
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
                if (nosign)
                    status = encrypt_only(session, keys, ptext, psize, &ctext,
                        &csize);
                else 
                    status = encrypt_and_sign(session, keys, ptext, psize, &ctext,
                        &csize);
                if (ctext) {
                    char *filename = NULL;

                    if (_s->filename) {
                        size_t len = strlen(_s->filename);
                        size_t bufsize = len + 5; // length of .pgp extension + NUL
                        filename = calloc(1, bufsize);
                        if (filename == NULL)
                            goto enomem;

                        strlcpy(filename, _s->filename, bufsize);
                        strlcat(filename, ".pgp", bufsize);
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

static const char * rating_to_string(PEP_rating rating)
{
    switch (rating) {
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
        return "under_attack";
    default:
        return "undefined";
    }
}

static void decorate_message(
    message *msg,
    PEP_rating rating,
    stringlist_t *keylist
    )
{
    assert(msg);

    add_opt_field(msg, "X-pEp-Version", PEP_VERSION);

    if (rating != PEP_rating_undefined)
        add_opt_field(msg, "X-EncStatus", rating_to_string(rating));

    if (keylist) {
        char *_keylist = keylist_to_string(keylist);
        add_opt_field(msg, "X-KeyList", _keylist);
        free(_keylist);
    }
}

static PEP_rating _rating(PEP_comm_type ct, PEP_rating rating)
{
    if (ct == PEP_ct_unknown)
        return PEP_rating_undefined;

    else if (ct == PEP_ct_key_not_found)
        return PEP_rating_have_no_key;

    else if (ct == PEP_ct_compromized)
        return PEP_rating_under_attack;

    else if (ct == PEP_ct_mistrusted)
        return PEP_rating_mistrust;

    if (rating == PEP_rating_unencrypted_for_some)
        return PEP_rating_unencrypted_for_some;

    if (ct == PEP_ct_no_encryption || ct == PEP_ct_no_encrypted_channel ||
            ct == PEP_ct_my_key_not_included) {
        if (rating > PEP_rating_unencrypted_for_some)
            return PEP_rating_unencrypted_for_some;
        else
            return PEP_rating_unencrypted;
    }

    if (rating == PEP_rating_unencrypted)
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
    assert(blob);

    if (blob == NULL || blob->filename == NULL)
        return false;

    char *ext = strrchr(blob->filename, '.');
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

static PEP_rating decrypt_rating(PEP_STATUS status)
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

static PEP_rating key_rating(PEP_SESSION session, const char *fpr)
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

static PEP_rating worst_rating(PEP_rating rating1, PEP_rating rating2) {
    return ((rating1 < rating2) ? rating1 : rating2);
}

static PEP_rating keylist_rating(PEP_SESSION session, stringlist_t *keylist)
{
    PEP_rating rating = PEP_rating_reliable;

    assert(keylist && keylist->value);
    if (keylist == NULL || keylist->value == NULL)
        return PEP_rating_undefined;

    stringlist_t *_kl;
    for (_kl = keylist; _kl && _kl->value; _kl = _kl->next) {
        PEP_comm_type ct;
        PEP_STATUS status;

        PEP_rating _rating_ = key_rating(session, _kl->value);
         
        if (_rating_ <= PEP_rating_mistrust)
            return _rating_;

        if (rating == PEP_rating_undefined)
            rating = worst_rating(rating, _rating_);

        if (_rating_ >= PEP_rating_reliable) {
            status = least_trust(session, _kl->value, &ct);
            if (status != PEP_STATUS_OK)
                return PEP_rating_undefined;
            if (ct == PEP_ct_unknown){
                if (rating >= PEP_rating_reliable){
                    rating = worst_rating(rating, PEP_rating_reliable);
                }
            }
            else{
                rating = worst_rating(rating, _rating(ct, rating));
            }
        }
        else if (_rating_ == PEP_rating_unencrypted) {
            if (rating > PEP_rating_unencrypted_for_some)
                rating = worst_rating(rating, PEP_rating_unencrypted_for_some);
        }
    }

    return rating;
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
            return _MIN(max_comm_type, ident->comm_type);
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

    int i = 0;
    for (bloblist_t *bl = msg->attachments; i < MAX_KEYS_TO_IMPORT && bl && bl->value;
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
    char *keydata = NULL;
    size_t size;

    PEP_STATUS status = export_key(session, fpr, &keydata, &size);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        return status;
    assert(size);

     bloblist_t *bl = bloblist_add(msg->attachments, keydata, size, "application/pgp-keys",
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
    else if (msg->attachments && msg->attachments->next &&
            is_mime_type(msg->attachments->next, "application/pgp-encrypted") &&
            is_PGP_message_text(msg->attachments->value)
        ) {
        msg->enc_format = PEP_enc_PGP_MIME_Outlook1;
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
        PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags
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
            status = encrypt_PGP_MIME(session, src, keys, msg, flags);
            break;

        case PEP_enc_pieces:
            status = encrypt_PGP_in_pieces(session, src, keys, msg, flags);
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

    if (msg) {
        decorate_message(msg, PEP_rating_undefined, NULL);
        if (src->id) {
            msg->id = strdup(src->id);
            assert(msg->id);
            if (msg->id == NULL)
                goto enomem;
        }
    }

    *dst = msg;
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free_stringlist(keys);
    free_message(msg);

    return status;
}

DYNAMIC_API PEP_STATUS encrypt_message_for_self(
        PEP_SESSION session,
        pEp_identity* target_id,
        message *src,
        message **dst,
        PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags
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

    status = myself(session, target_id);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    *dst = NULL;


    PEP_STATUS _status = update_identity(session, target_id);
    if (_status != PEP_STATUS_OK) {
        status = _status;
        goto pep_error;
    }

    char* target_fpr = target_id->fpr;
    if (!target_fpr)
        return PEP_KEY_NOT_FOUND; // FIXME: Error condition

    keys = new_stringlist(target_fpr);


    msg = clone_to_empty_message(src);
    if (msg == NULL)
        goto enomem;

    switch (enc_format) {
        case PEP_enc_PGP_MIME:
        case PEP_enc_PEP: // BUG: should be implemented extra
            status = encrypt_PGP_MIME(session, src, keys, msg, flags);
            break;

        case PEP_enc_pieces:
            status = encrypt_PGP_in_pieces(session, src, keys, msg, flags);
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

     if (msg && msg->shortmsg == NULL) {
         msg->shortmsg = strdup("pEp");
         assert(msg->shortmsg);
         if (msg->shortmsg == NULL)
             goto enomem;
     }

     if (msg) {
         if (src->id) {
             msg->id = strdup(src->id);
             assert(msg->id);
             if (msg->id == NULL)
                 goto enomem;
         }
     }

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


PEP_STATUS _get_detached_signature(message* msg, bloblist_t** signature_blob) {
    bloblist_t* attach_curr = msg->attachments;

    *signature_blob = NULL;

    while (attach_curr) {
        if (strcasecmp(attach_curr->mime_type, "application/pgp-signature") == 0) {
            *signature_blob = attach_curr;
            break;
        }
        attach_curr = attach_curr->next;
    }

    return PEP_STATUS_OK;
}

PEP_STATUS _get_signed_text(const char* ptext, const size_t psize,
                            char** stext, size_t* ssize) {

    char* signed_boundary = NULL;
    char* signpost = strstr(ptext, "Content-Type: multipart/signed");

    *ssize = 0;
    *stext = NULL;

    if (!signpost)
        return PEP_UNKNOWN_ERROR;

    char* curr_line = signpost;
//    const char* end_text = ptext + psize;
    const char* boundary_key = "boundary=\"";
    const size_t BOUNDARY_KEY_SIZE = 10;

    char* start_boundary = strstr(curr_line, boundary_key);
    if (!start_boundary)
        return PEP_UNKNOWN_ERROR;

    start_boundary += BOUNDARY_KEY_SIZE;

    char* end_boundary = strstr(start_boundary, "\"");

    if (!end_boundary)
        return PEP_UNKNOWN_ERROR;

    size_t boundary_strlen = (end_boundary - start_boundary) + 2;

    signed_boundary = calloc(1, boundary_strlen + 1);
    strlcpy(signed_boundary, "--", boundary_strlen + 1);
    strlcat(signed_boundary, start_boundary, boundary_strlen + 1);

    start_boundary = strstr(end_boundary, signed_boundary);

    if (!start_boundary)
        return PEP_UNKNOWN_ERROR;

    start_boundary += boundary_strlen;

    while (*start_boundary == '\n')
        start_boundary++;

    end_boundary = strstr(start_boundary + boundary_strlen, signed_boundary);

    if (!end_boundary)
        return PEP_UNKNOWN_ERROR;

    end_boundary--; // See RFC3156 section 5...

    *ssize = end_boundary - start_boundary;
    *stext = start_boundary;
    free(signed_boundary);

    return PEP_STATUS_OK;
}

PEP_STATUS combine_keylists(PEP_SESSION session, stringlist_t** verify_in, 
                            stringlist_t** keylist_in_out, 
                            pEp_identity* from) {
    
    if (!verify_in || !(*verify_in)) // this isn't really a problem.
        return PEP_STATUS_OK;
    
    stringlist_t* orig_verify = *verify_in;
    
    stringlist_t* verify_curr = NULL;
    stringlist_t* from_keys = NULL;
    
    /* FIXME: what to do if head needs to be null */
    PEP_STATUS status = find_keys(session, from->address, &from_keys);
    
    stringlist_t* from_fpr_node = NULL;
    stringlist_t* from_curr;
    
    for (from_curr = from_keys; from_curr; from_curr = from_curr->next) {
        for (verify_curr = orig_verify; verify_curr; verify_curr = verify_curr->next) {
            if (from_curr->value && verify_curr->value &&
                _same_fpr(from_curr->value, strlen(from_curr->value),
                          verify_curr->value, strlen(verify_curr->value))) {
                from_fpr_node = from_curr;
                break;
            }
        }
    }
    
    if (!from_fpr_node) {
        status = PEP_KEY_NOT_FOUND;
        goto free;
    }

    verify_curr = orig_verify;
    
    /* put "from" signer at the beginning of the list */
    if (!_same_fpr(orig_verify->value, strlen(orig_verify->value),
                   from_fpr_node->value, strlen(from_fpr_node->value))) {
        orig_verify = stringlist_delete(orig_verify, from_fpr_node->value);
        verify_curr = new_stringlist(from_fpr_node->value);
        verify_curr->next = orig_verify;
    }

    /* append keylist to signers */
    if (keylist_in_out && *keylist_in_out && (*keylist_in_out)->value) {
        stringlist_t** tail_pp = &verify_curr->next;
        
        while (*tail_pp) {
            tail_pp = &((*tail_pp)->next);
        }
        *tail_pp = *keylist_in_out;
    }
    
    *keylist_in_out = verify_curr;
    
    status = PEP_STATUS_OK;
    
free:
    free_stringlist(from_keys);
    return status;
}


DYNAMIC_API PEP_STATUS _decrypt_message(
        PEP_SESSION session,
        message *src,
        message **dst,
        stringlist_t **keylist,
        PEP_rating *rating,
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
    assert(rating);
    assert(flags);

    if (!(session && src && dst && keylist && rating && flags))
        return PEP_ILLEGAL_VALUE;

    *flags = 0;

    // Private key in unencrypted mail are ignored -> NULL
    bool imported_keys = import_attached_keys(session, src, NULL);

    // Update src->from in case we just imported a key
    // we would need to check signature
    status = _update_identity_for_incoming_message(session, src);
    if(status != PEP_STATUS_OK)
        return status;

    // Get detached signature, if any
    bloblist_t* detached_sig = NULL;
    char* dsig_text = NULL;
    size_t dsig_size = 0;
    status = _get_detached_signature(src, &detached_sig);
    if (detached_sig) {
        dsig_text = detached_sig->value;
        dsig_size = detached_sig->size;
    }

    PEP_cryptotech crypto = determine_encryption_format(src);

    *dst = NULL;
    *keylist = NULL;
    *rating = PEP_rating_undefined;

    switch (src->enc_format) {
        case PEP_enc_none:
            *rating = PEP_rating_unencrypted;
            if (imported_keys)
                remove_attached_keys(src);
            if(session->sync_session->inject_sync_msg){
                status = receive_DeviceState_msg(session, src, *rating, *keylist);
                if (status == PEP_MESSAGE_CONSUME ||
                    status == PEP_MESSAGE_IGNORE) {
                    free_message(msg);
                    msg = NULL;
                    *flags |= (status == PEP_MESSAGE_IGNORE) ?
                                PEP_decrypt_flag_ignore :
                                PEP_decrypt_flag_consume;
                }
                else if (status != PEP_STATUS_OK) {
                    return status;
                }
            }
            
            char* slong = src->longmsg;
            char* sform = src->longmsg_formatted;
            bloblist_t* satt = src->attachments;
            
            if ((!slong || slong[0] == '\0')
                 && (!sform || sform[0] == '\0')) {
                if (satt) {
                    const char* inner_mime_type = satt->mime_type;
                    if (strcasecmp(inner_mime_type, "text/plain") == 0) {
                        free(slong); /* in case of "" */
                        src->longmsg = strndup(satt->value, satt->size); // N.B.: longmsg might be shorter, if attachment contains NUL bytes which are not allowed in text/plain!
                        
                        bloblist_t* next_node = satt->next;
                        if (next_node) {
                            inner_mime_type = next_node->mime_type;
                            if (strcasecmp(inner_mime_type, "text/html") == 0) {
                                free(sform);
                                src->longmsg_formatted = strndup(next_node->value, next_node->size);  // N.B.: longmsg might be shorter, if attachment contains NUL bytes which are not allowed in text/plain!
                            }
                        }
                    }
                    else if (strcasecmp(inner_mime_type, "text/html") == 0) {
                        free(sform);
                        src->longmsg_formatted = strndup(satt->value, satt->size);  // N.B.: longmsg might be shorter, if attachment contains NUL bytes which are not allowed in text/plain!
                    }
                }
            }
            
            return PEP_UNENCRYPTED;

        case PEP_enc_PGP_MIME:
            ctext = src->attachments->next->value;
            csize = src->attachments->next->size;
            break;

        case PEP_enc_PGP_MIME_Outlook1:
            ctext = src->attachments->value;
            csize = src->attachments->size;
            break;

        case PEP_enc_pieces:
            ctext = src->longmsg;
            csize = strlen(ctext);
            break;

        default:
            NOT_IMPLEMENTED
    }
    status = cryptotech[crypto].decrypt_and_verify(session, ctext,
                                                   csize, dsig_text, dsig_size,
                                                   &ptext, &psize, &_keylist);
    if (status > PEP_CANNOT_DECRYPT_UNKNOWN){
        goto pep_error;
    }

    decrypt_status = status;

    if (status == PEP_DECRYPT_NO_KEY){
        PEP_STATUS sync_status = inject_DeviceState_event(session, CannotDecrypt, NULL, NULL);
        if (sync_status == PEP_OUT_OF_MEMORY){
            status = PEP_OUT_OF_MEMORY;
            goto pep_error;
        }
    }

    bool imported_private_key_address = false;

    if (ptext) {
        switch (src->enc_format) {
            case PEP_enc_PGP_MIME:
            case PEP_enc_PGP_MIME_Outlook1:
                status = mime_decode_message(ptext, psize, &msg);
                if (status != PEP_STATUS_OK)
                    goto pep_error;
                
                char* mlong = msg->longmsg;
                char* mform = msg->longmsg_formatted;
                bloblist_t* matt = msg->attachments;
                
                if ((!mlong || mlong[0] == '\0')
                     && (!mform || mform[0] == '\0')) {
                    if (matt) {
                        const char* inner_mime_type = matt->mime_type;
                        if (strcasecmp(inner_mime_type, "text/plain") == 0) {
                            free(mlong); /* in case of "" */
                            msg->longmsg = strndup(matt->value, matt->size);
                            
                            bloblist_t* next_node = matt->next;
                            if (next_node) {
                                inner_mime_type = next_node->mime_type;
                                if (strcasecmp(inner_mime_type, "text/html") == 0) {
                                    free(mform);
                                    msg->longmsg_formatted = strndup(next_node->value, next_node->size);
                                }
                            }
                        }
                        else if (strcasecmp(inner_mime_type, "text/html") == 0) {
                            free(mform);
                            msg->longmsg_formatted = strndup(matt->value, matt->size);
                        }
                    }
                    if (msg->shortmsg) {
                        free(src->shortmsg);
                        src->shortmsg = strdup(msg->shortmsg);
                    }
                }

                if (decrypt_status != PEP_DECRYPTED_AND_VERIFIED) {
                    status = _get_detached_signature(msg, &detached_sig);
                    if (decrypt_status == PEP_DECRYPTED && detached_sig) {
                        dsig_text = detached_sig->value;
                        dsig_size = detached_sig->size;
                        size_t ssize = 0;
                        char* stext = NULL;

                        status = _get_signed_text(ptext, psize, &stext, &ssize);
                        stringlist_t *_verify_keylist = NULL;

                        if (ssize > 0 && stext) {
                            status = cryptotech[crypto].verify_text(session, stext,
                                                                    ssize, dsig_text, dsig_size,
                                                                    &_verify_keylist);

                            if (status == PEP_VERIFIED || status == PEP_VERIFIED_AND_TRUSTED)
                                decrypt_status = PEP_DECRYPTED_AND_VERIFIED;
                            
                                status = combine_keylists(session, &_verify_keylist, &_keylist, src->from);
                        }
                    }
                }
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

                        // FIXME: What about attachments with separate sigs???
                        status = decrypt_and_verify(session, attctext, attcsize,
                                                    NULL, 0,
                                                    &ptext, &psize, &_keylist);
                        free_stringlist(_keylist); // FIXME: Why do we do this?

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
            case PEP_enc_PGP_MIME_Outlook1:
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
                csize, dsig_text, dsig_size, &re_ptext, &re_psize, &_keylist);

            free(re_ptext);

            if (status > PEP_CANNOT_DECRYPT_UNKNOWN)
                goto pep_error;

            decrypt_status = status;
        }

        *rating = decrypt_rating(decrypt_status);

        if (*rating > PEP_rating_mistrust) {
            PEP_rating kl_rating = PEP_rating_undefined;

            if (_keylist)
                kl_rating = keylist_rating(session, _keylist);

            if (kl_rating <= PEP_rating_mistrust) {
                *rating = kl_rating;
            }
            else if (*rating >= PEP_rating_reliable &&
                     kl_rating < PEP_rating_reliable) {
                *rating = PEP_rating_unreliable;
            }
            else if (*rating >= PEP_rating_reliable &&
                     kl_rating >= PEP_rating_reliable) {
                if (!(src->from && src->from->user_id && src->from->user_id[0])) {
                    *rating = PEP_rating_unreliable;
                }
                else {
                    char *fpr = _keylist->value;
                    pEp_identity *_from = new_identity(src->from->address, fpr,
                                                       src->from->user_id, src->from->username);
                    if (_from == NULL)
                        goto enomem;
                    status = get_trust(session, _from);
                    if (_from->comm_type != PEP_ct_unknown)
                        *rating = _rating(_from->comm_type, PEP_rating_undefined);
                    free_identity(_from);
                    if (status == PEP_CANNOT_FIND_IDENTITY)
                       status = PEP_STATUS_OK;
                    if (status != PEP_STATUS_OK)
                        goto pep_error;
                }
            }
        }
    }
    else
    {
        *rating = decrypt_rating(decrypt_status);
        goto pep_error;
    }

    // Case of own key imported from own trusted message
    if (// Message have been reliably decrypted
        msg &&
        *rating >= PEP_rating_trusted &&
        imported_private_key_address &&
        // to is [own]
        msg->to->ident->user_id &&
        strcmp(msg->to->ident->user_id, PEP_OWN_USERID) == 0
        )
    {
        *flags |= PEP_decrypt_flag_own_private_key;
    }

    if (msg) {
        decorate_message(msg, *rating, _keylist);
        if (imported_keys)
            remove_attached_keys(msg);
        if (*rating >= PEP_rating_reliable &&
            session->sync_session->inject_sync_msg) {
            status = receive_DeviceState_msg(session, msg, *rating, _keylist);
            if (status == PEP_MESSAGE_CONSUME ||
                status == PEP_MESSAGE_IGNORE) {
                free_message(msg);
                msg = NULL;
                *flags |= (status == PEP_MESSAGE_IGNORE) ?
                            PEP_decrypt_flag_ignore :
                            PEP_decrypt_flag_consume;

                status = decrypt_status;
            }
            else if (status != PEP_STATUS_OK){
                goto pep_error;
            }
        }
    }
    if (msg) {
        if (src->id) {
            msg->id = strdup(src->id);
            assert(msg->id);
            if (msg->id == NULL)
                goto enomem;
        }
    }

    *dst = msg;
    *keylist = _keylist;

    return status;

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
        PEP_rating *rating,
        PEP_decrypt_flags_t *flags
    )
{
    return _decrypt_message( session, src, dst, keylist, rating, flags, NULL );
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

    message *dst = NULL;
    stringlist_t *keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;

    *ident = NULL;

    identity_list *private_il = NULL;
    PEP_STATUS status = _decrypt_message(session, msg,  &dst, &keylist, &rating, &flags, &private_il);
    free_message(dst);
    free_stringlist(keylist);

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

DYNAMIC_API PEP_STATUS outgoing_message_rating(
        PEP_SESSION session,
        message *msg,
        PEP_rating *rating
    )
{
    PEP_comm_type max_comm_type = PEP_ct_pEp;
    bool comm_type_determined = false;

    assert(session);
    assert(msg);
    assert(msg->dir == PEP_dir_outgoing);
    assert(rating);

    if (!(session && msg && rating))
        return PEP_ILLEGAL_VALUE;

    if (msg->dir != PEP_dir_outgoing)
        return PEP_ILLEGAL_VALUE;

    *rating = PEP_rating_undefined;

    _max_comm_type_from_identity_list(msg->to, session,
                                      &max_comm_type, &comm_type_determined);

    _max_comm_type_from_identity_list(msg->cc, session,
                                      &max_comm_type, &comm_type_determined);

    _max_comm_type_from_identity_list(msg->bcc, session,
                                      &max_comm_type, &comm_type_determined);

    if (comm_type_determined == false)
        *rating = PEP_rating_undefined;
    else
        *rating = _MAX(_rating(max_comm_type, PEP_rating_undefined),
                PEP_rating_unencrypted);

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS identity_rating(
        PEP_SESSION session,
        pEp_identity *ident,
        PEP_rating *rating
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(ident);
    assert(rating);

    if (!(session && ident && rating))
        return PEP_ILLEGAL_VALUE;

    if (ident->me)
        status = _myself(session, ident, false, true);
    else
        status = update_identity(session, ident);

    if (status == PEP_STATUS_OK)
        *rating = _rating(ident->comm_type, PEP_rating_undefined);

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


DYNAMIC_API PEP_color color_from_rating(PEP_rating rating)
{
    if (rating == PEP_rating_b0rken || rating == PEP_rating_have_no_key)
        return PEP_color_no_color;

    if (rating < PEP_rating_undefined)
        return PEP_color_red;

    if (rating < PEP_rating_reliable)
        return PEP_color_no_color;

    if (rating < PEP_rating_trusted)
        return PEP_color_yellow;

    if (rating >= PEP_rating_trusted)
        return PEP_color_green;

    // this should never happen
    assert(false);
	return PEP_color_no_color;
}

static bool _is_valid_hex(const char* hexstr) {
    if (!hexstr)
        return false;

    const char* curr = hexstr;
    char currchar;

    for (currchar = *curr; currchar != '\0'; currchar = *(++curr)) {
        if ((currchar >= '0' && currchar <= '9') ||
            (currchar >= 'a' && currchar <= 'f') ||
            (currchar >= 'A' && currchar <= 'F'))
        {
            continue;
        }
        return false;
    }
    return true;
}

// Returns, in comparison: 1 if fpr1 > fpr2, 0 if equal, -1 if fpr1 < fpr2
static PEP_STATUS _compare_fprs(const char* fpr1, const char* fpr2, int* comparison) {

    const int _FULL_FINGERPRINT_LENGTH = 40;
    const int _ASCII_LOWERCASE_OFFSET = 32;

    size_t fpr1_len = strlen(fpr1);
    size_t fpr2_len = strlen(fpr2);

    if (fpr1_len != _FULL_FINGERPRINT_LENGTH || fpr2_len != _FULL_FINGERPRINT_LENGTH)
        return PEP_TRUSTWORDS_FPR_WRONG_LENGTH;

    if (!_is_valid_hex(fpr1) || !_is_valid_hex(fpr2))
        return PEP_ILLEGAL_VALUE;

    const char* fpr1_curr = fpr1;
    const char* fpr2_curr = fpr2;

    char current;

    // Advance past leading zeros.
    for (current = *fpr1_curr; current != '0' && current != '\0'; current = *(++fpr1_curr), fpr1_len--);
    for (current = *fpr2_curr; current != '0' && current != '\0'; current = *(++fpr2_curr), fpr2_len--);

    if (fpr1_len == fpr2_len) {
        char digit1;
        char digit2;

        while (fpr1_curr && *fpr1_curr != '\0') {
            digit1 = *fpr1_curr++;
            digit2 = *fpr2_curr++;

            // Adjust for case-insensitive compare
            if (digit1 >= 'a' && digit1 <= 'f')
                digit1 -= _ASCII_LOWERCASE_OFFSET;
            if (digit2 >= 'a' && digit2 <= 'f')
                digit2 -= _ASCII_LOWERCASE_OFFSET;

            // We take advantage of the fact that 'a'-'f' are larger
            // integer values in the ASCII table than '0'-'9'.
            // This allows us to compare digits directly.
            if (digit1 > digit2) {
                *comparison = 1;
                return PEP_STATUS_OK;
            } else if (digit1 < digit2) {
                *comparison = -1;
                return PEP_STATUS_OK;
            }

            // pointers already advanced above. Keep going.
        }
        *comparison = 0;
        return PEP_STATUS_OK;
    }
    else if (fpr1_len > fpr2_len) {
        *comparison = 1;
        return PEP_STATUS_OK;
    }
    // Otherwise, fpr1_len < fpr2_len
    *comparison = -1;
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS get_trustwords(
    PEP_SESSION session, const pEp_identity* id1, const pEp_identity* id2,
    const char* lang, char **words, size_t *wsize, bool full
)
{
    assert(session);
    assert(id1);
    assert(id2);
    assert(id1->fpr);
    assert(id2->fpr);
    assert(words);
    assert(wsize);

    if (!(session && id1 && id2 && words && wsize) ||
        !(id1->fpr) || (!id2->fpr))
        return PEP_ILLEGAL_VALUE;

    const char *source1 = id1->fpr;
    const char *source2 = id2->fpr;

    *words = NULL;
    *wsize = 0;

    const size_t SHORT_NUM_TWORDS = 5;

    // N.B. THIS will have to be changed once we start checking trustword entropy.
    // For now, full is ALL, and otherwise it's 5-per-id.
    size_t max_words_per_id = (full ? 0 : SHORT_NUM_TWORDS);

    char* first_set = NULL;
    char* second_set = NULL;
    size_t first_wsize = 0;
    size_t second_wsize = 0;

    int fpr_comparison = -255;
    PEP_STATUS status = _compare_fprs(source1, source2, &fpr_comparison);
    if (status != PEP_STATUS_OK)
        return status;

    char* _retstr = NULL;

    switch (fpr_comparison) {
        case 1: // source1 > source2
            status = trustwords(session, source2, lang, &first_set, &first_wsize, max_words_per_id);
            if (status != PEP_STATUS_OK)
                goto error_release;
            status = trustwords(session, source1, lang, &second_set, &second_wsize, max_words_per_id);
            if (status != PEP_STATUS_OK)
                goto error_release;
            break;
        case 0:
        case -1: // source1 <= source2
            status = trustwords(session, source1, lang, &first_set, &first_wsize, max_words_per_id);
            if (status != PEP_STATUS_OK)
                goto error_release;
            status = trustwords(session, source2, lang, &second_set, &second_wsize, max_words_per_id);
            if (status != PEP_STATUS_OK)
                goto error_release;
            break;
        default:
            return PEP_UNKNOWN_ERROR; // shouldn't be possible
    }

    size_t _wsize = first_wsize + second_wsize;

    bool needs_space = (first_set[first_wsize - 1] != ' ');

    if (needs_space)
        _wsize++;

    _retstr = calloc(1, _wsize + 1);

    size_t len = strlcpy(_retstr, first_set, _wsize);
    if (len >= _wsize) {
        status = PEP_UNKNOWN_ERROR;
        goto error_release;
    }
    if (needs_space) {
        strlcat(_retstr, " ", _wsize);
        if (len >= _wsize) {
            status = PEP_UNKNOWN_ERROR;
            goto error_release;
        }
    }
    strlcat(_retstr, second_set, _wsize);
    if (len >= _wsize){
        status = PEP_UNKNOWN_ERROR;
        goto error_release;
    }

    *words = _retstr;
    *wsize = _wsize;
    status = PEP_STATUS_OK;

    goto the_end;

    error_release:
    free(_retstr);

    the_end:
    free(first_set);
    free(second_set);
    return status;
}

DYNAMIC_API PEP_STATUS get_message_trustwords(
    PEP_SESSION session, 
    message *msg,
    stringlist_t *keylist,
    pEp_identity* received_by,
    const char* lang, char **words, bool full
)
{
    assert(session);
    assert(msg);
    assert(received_by);
    assert(received_by->address);
    assert(lang);
    assert(words);

    if (!(session && 
          msg &&
          received_by && 
          received_by->address && 
          lang && 
          words))
        return PEP_ILLEGAL_VALUE;
    
    pEp_identity* partner = NULL;
     
    PEP_STATUS status = PEP_STATUS_OK;
    
    *words = NULL;

    // We want fingerprint of key that did sign the message

    if (keylist == NULL) {

        // Message is to be decrypted
        message *dst = NULL;
        stringlist_t *_keylist = keylist;
        PEP_rating rating;
        PEP_decrypt_flags_t flags;
        status = decrypt_message( session, msg, &dst, &_keylist, &rating, &flags);

        if (status != PEP_STATUS_OK) {
            free_message(dst);
            free_stringlist(_keylist);
            return status;
        }

        if (dst && dst->from && _keylist) {
            partner = identity_dup(dst->from); 
            if(partner){
                free(partner->fpr);
                partner->fpr = strdup(_keylist->value);
                if (partner->fpr == NULL)
                    status = PEP_OUT_OF_MEMORY;
            } else {
                status = PEP_OUT_OF_MEMORY;
            }
        } else {
            status = PEP_UNKNOWN_ERROR;
        }

        free_message(dst);
        free_stringlist(_keylist);

    } else {

        // Message already decrypted
        if (keylist->value) {
            partner = identity_dup(msg->from); 
            if(partner){
                free(partner->fpr);
                partner->fpr = strdup(keylist->value);
                if (partner->fpr == NULL)
                    status = PEP_OUT_OF_MEMORY;
            } else {
                status = PEP_OUT_OF_MEMORY;
            }
        } else {
            status = PEP_ILLEGAL_VALUE;
        }
    }

    if (status != PEP_STATUS_OK) {
        free_identity(partner);
        return status;
    }
   
    // Find own identity corresponding to given account address.
    // In that case we want default key attached to own identity
    pEp_identity *stored_identity = NULL;
    status = get_identity(session,
                          received_by->address,
                          PEP_OWN_USERID,
                          &stored_identity);

    if (status != PEP_STATUS_OK) {
        free_identity(stored_identity);
        return status;
    }

    // get the trustwords
    size_t wsize;
    status = get_trustwords(session, 
                            partner, received_by, 
                            lang, words, &wsize, full);

    return status;
}

DYNAMIC_API PEP_STATUS MIME_decrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    char** mime_plaintext,
    stringlist_t **keylist,
    PEP_rating *rating,
    PEP_decrypt_flags_t *flags
)
{
    PEP_STATUS status = PEP_STATUS_OK;
    message* tmp_msg = NULL;
    message* dec_msg = NULL;

    status = mime_decode_message(mimetext, size, &tmp_msg);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    status = decrypt_message(session,
                             tmp_msg,
                             &dec_msg,
                             keylist,
                             rating,
                             flags);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    status = mime_encode_message(dec_msg, false, mime_plaintext);

pep_error:
    free_message(tmp_msg);
    free_message(dec_msg);

    return status;
}

DYNAMIC_API PEP_STATUS MIME_encrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    stringlist_t* extra,
    char** mime_ciphertext,
    PEP_enc_format enc_format,
    PEP_encrypt_flags_t flags
)
{
    PEP_STATUS status = PEP_STATUS_OK;
    message* tmp_msg = NULL;
    message* enc_msg = NULL;

    status = mime_decode_message(mimetext, size, &tmp_msg);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    // This isn't incoming, though... so we need to reverse the direction
    tmp_msg->dir = PEP_dir_outgoing;
    status = encrypt_message(session,
                             tmp_msg,
                             extra,
                             &enc_msg,
                             enc_format,
                             flags);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    status = mime_encode_message(enc_msg, false, mime_ciphertext);

pep_error:
    free_message(tmp_msg);
    free_message(enc_msg);

    return status;

}
