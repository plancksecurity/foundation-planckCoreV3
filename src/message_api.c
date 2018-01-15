// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "message_api.h"

#include "platform.h"
#include "mime.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>


#ifndef _MIN
#define _MIN(A, B) ((B) > (A) ? (A) : (B))
#endif
#ifndef _MAX
#define _MAX(A, B) ((B) > (A) ? (B) : (A))
#endif

static bool is_a_pEpmessage(const message *msg)
{
    for (stringpair_list_t *i = msg->opt_fields; i && i->value ; i=i->next) {
        if (strcasecmp(i->value->key, "X-pEp-Version") == 0)
            return true;
    }
    return false;
}

static bool is_wrapper(message* src)
{
    bool retval = false;
    
    if (src) {
        unsigned char pepstr[] = PEP_SUBJ_STRING;
        if (is_a_pEpmessage(src) || (src->shortmsg == NULL || strcmp(src->shortmsg, "pEp") == 0 ||
            _unsigned_signed_strcmp(pepstr, src->shortmsg, PEP_SUBJ_BYTELEN) == 0) ||
            (strcmp(src->shortmsg, "p=p") == 0)) {
            char* plaintext = src->longmsg;
            if (plaintext) {
                const char *line_end = strchr(plaintext, '\n');

                if (line_end != NULL) {
                    size_t n = line_end - plaintext;
                    
                    char* copycat = calloc(n + 1, 1);
                    
                    if (copycat) {
                        strlcpy(copycat, plaintext, n+1);
                        
                        if (strstr(copycat, PEP_MSG_WRAP_KEY) && strstr(copycat, "OUTER"))
                            retval = true;
                        
                        free(copycat);
                    }
                }
            }
        }
    }
    return retval;
}


/*
 * static stringpair_t* search_optfields(const message* msg, const char* key) {
 *     if (msg && key) {
 *         stringpair_list_t* opt_fields = msg->opt_fields;
 *         
 *         const stringpair_list_t* curr;
 *         
 *         for (curr = opt_fields; curr && curr->value; curr = curr->next) {
 *             if (curr->value->key) {
 *                 if (strcasecmp(curr->value->key, key) == 0)
 *                     return curr->value;
 *             }
 *         } 
 *     }
 *     return NULL;
 * }
 */

static char * keylist_to_string(const stringlist_t *keylist)
{
    if (keylist) {
        size_t size = stringlist_length(keylist);

        const stringlist_t *_kl;
        for (_kl = keylist; _kl && _kl->value; _kl = _kl->next) {
            size += strlen(_kl->value);
        }

        char *result = calloc(size, 1);
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

void replace_opt_field(message *msg, const char *name, const char *value)
{
    assert(msg && name && value);
    
    if (msg && name && value) {
        stringpair_list_t* opt_fields = msg->opt_fields;
        stringpair_t* pair = NULL;
        if (opt_fields) {
            while (opt_fields) {
                pair = opt_fields->value;
                if (pair && (strcmp(name, pair->key) == 0))
                    break;
                    
                pair = NULL;
                opt_fields = opt_fields->next;
            }
        }
        
        if (pair) {
            free(pair->value);
            pair->value = strdup(value);
        }
        else {
            add_opt_field(msg, name, value);
        }
    }
}


static void decorate_message(
    message *msg,
    PEP_rating rating,
    stringlist_t *keylist,
    bool add_version
    )
{
    assert(msg);

    if (add_version)
        replace_opt_field(msg, "X-pEp-Version", PEP_VERSION);

    if (rating != PEP_rating_undefined)
        replace_opt_field(msg, "X-EncStatus", rating_to_string(rating));

    if (keylist) {
        char *_keylist = keylist_to_string(keylist);
        replace_opt_field(msg, "X-KeyList", _keylist);
        free(_keylist);
    }
}

static char* _get_resource_ptr_noown(char* uri) {
    char* uri_delim = strstr(uri, "://");
    if (!uri_delim)
        return uri;
    else
        return uri + 3;
}

// static bool is_file_uri(char* str) {
//     return(strncmp(str, "file://", 7) == 0);
// }

static bool is_cid_uri(const char* str) {
    return(strncmp(str, "cid://", 6) == 0);
}

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

    if (bl == NULL || bl->filename == NULL || fe == NULL || is_cid_uri(bl->filename))
        return false;

    assert(bl && bl->filename);

    size_t fe_len = strlen(fe);
    size_t fn_len = strlen(bl->filename);

    if (fn_len <= fe_len)
        return false;

    assert(fn_len > fe_len);

    return strcmp(bl->filename + (fn_len - fe_len), fe) == 0;
}


static char * encapsulate_message_wrap_info(const char *msg_wrap_info, const char *longmsg)
{
    assert(msg_wrap_info);
    
    if (!msg_wrap_info) {
        if (!longmsg)
            return NULL;
        else {
            char *result = strdup(longmsg);
            assert(result);
            return result;            
        }    
    }
    
    if (longmsg == NULL)
        longmsg = "";
        
    const char * const newlines = "\n\n";
    const size_t NL_LEN = 2;
        
    const size_t bufsize = PEP_MSG_WRAP_KEY_LEN + strlen(msg_wrap_info) + NL_LEN + strlen(longmsg) + 1;
    char * ptext = calloc(bufsize, 1);
    assert(ptext);
    if (ptext == NULL)
        return NULL;

    strlcpy(ptext, PEP_MSG_WRAP_KEY, bufsize);
    strlcat(ptext, msg_wrap_info, bufsize);
    strlcat(ptext, newlines, bufsize);
    strlcat(ptext, longmsg, bufsize);

    return ptext;
}

static char * combine_short_and_long(const char *shortmsg, const char *longmsg)
{
    assert(shortmsg);
    
    unsigned char pepstr[] = PEP_SUBJ_STRING;
    assert(strcmp(shortmsg, "pEp") != 0 && _unsigned_signed_strcmp(pepstr, shortmsg, PEP_SUBJ_BYTELEN) != 0); 
    
    if (!shortmsg || strcmp(shortmsg, "pEp") == 0 || 
                     _unsigned_signed_strcmp(pepstr, shortmsg, PEP_SUBJ_BYTELEN) == 0) {
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

    const char * const newlines = "\n\n";
    const size_t NL_LEN = 2;

    const size_t bufsize = PEP_SUBJ_KEY_LEN + strlen(shortmsg) + NL_LEN + strlen(longmsg) + 1;
    char * ptext = calloc(bufsize, 1);
    assert(ptext);
    if (ptext == NULL)
        return NULL;

    strlcpy(ptext, PEP_SUBJ_KEY, bufsize);
    strlcat(ptext, shortmsg, bufsize);
    strlcat(ptext, newlines, bufsize);
    strlcat(ptext, longmsg, bufsize);

    return ptext;
}

static PEP_STATUS replace_subject(message* msg) {
    unsigned char pepstr[] = PEP_SUBJ_STRING;
    if (msg->shortmsg && *(msg->shortmsg) != '\0') {
        char* longmsg = combine_short_and_long(msg->shortmsg, msg->longmsg);
        if (!longmsg)
            return PEP_OUT_OF_MEMORY;
        else {
            free(msg->longmsg);
            msg->longmsg = longmsg;
        }
    }
    free(msg->shortmsg);
#ifdef WIN32
    msg->shortmsg = strdup("pEp");
#else
    msg->shortmsg = strdup((char*)pepstr);
#endif    
    
    if (!msg->shortmsg)
        return PEP_OUT_OF_MEMORY;
    
    return PEP_STATUS_OK;
}

unsigned long long get_bitmask(int num_bits) {
    if (num_bits <= 0)
        return 0;
        
    unsigned long long bitmask = 0;
    int i;
    for (i = 1; i < num_bits; i++) {
        bitmask = bitmask << 1;
        bitmask |= 1;
    }
    return bitmask;
}

static char* get_base_36_rep(unsigned long long value, int num_sig_bits) {
        
    int bufsize = ceil(num_sig_bits / _pEp_log2_36) + 1;
    
    // based on
    // https://en.wikipedia.org/wiki/Base36#C_implementation
    // ok, we supposedly have a 64-bit kinda sorta random blob
    const char base_36_symbols[36] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    char* retbuf = calloc(bufsize, 1); 

    int i = bufsize - 1; // (end index)

    while (i > 0) {
        retbuf[--i] = base_36_symbols[value % 36];
        value /= 36;
    }

    return retbuf;
}


static char* message_id_prand_part(void) {
    // RAND modulus
    int num_bits = _pEp_rand_max_bits;

    if (num_bits < 0)
        return NULL;
        
    const int DESIRED_BITS = 64;

    num_bits = _MIN(num_bits, DESIRED_BITS);
    
    int i;
    
    // at least 64 bits
    unsigned long long bitmask = get_bitmask(num_bits);
    
    unsigned long long output_value = 0;
    
    i = DESIRED_BITS;
    
    int bitshift = 0;
    
    while (i > 0) {
        int randval = rand();
        unsigned long long temp_val = randval & bitmask;

        output_value |= temp_val;

        i -= num_bits; 
        
        bitshift = _MIN(num_bits, i);
        output_value <<= bitshift;        
        bitmask = get_bitmask(bitshift);
    }

    return get_base_36_rep(output_value, DESIRED_BITS);
}

static PEP_STATUS generate_message_id(message* msg) {

    if (!msg || !msg->from || !msg->from->address)
        return PEP_ILLEGAL_VALUE;

    char* time_prefix = NULL;
    char* random_id = NULL;
    char* retval = NULL;
    
    size_t buf_len = 2; // NUL + @
    
    char* from_addr = msg->from->address;
    char* domain_ptr = strstr(from_addr, "@");
    if (!domain_ptr || *(domain_ptr + 1) == '\0')
        domain_ptr = "localhost";
    else
        domain_ptr++;

    buf_len += strlen(domain_ptr);
    
    if (msg->id)
        free(msg->id);

    msg->id = NULL;
    
    time_t curr_time = time(NULL);
    
    time_prefix = get_base_36_rep(curr_time, ceil(log2(curr_time)));

    if (!time_prefix)
        goto enomem;
    
    buf_len += strlen(time_prefix);

    random_id = message_id_prand_part();

    if (!random_id)
        goto enomem;
    
        
    buf_len += strlen(random_id);
    
    // make a new uuid - depending on rand() impl, time precision, etc,
    // we may still not be unique. We'd better make sure. So. 
    char new_uuid[37];
    pEpUUID uuid;
    uuid_generate_random(uuid);
    uuid_unparse_upper(uuid, new_uuid);

    buf_len += strlen(new_uuid);

    buf_len += 6; // "pEp" and 3 '.' chars

    retval = calloc(buf_len, 1);
    
    if (!retval)
        goto enomem;
    
    strlcpy(retval, "pEp.", buf_len);
    strlcat(retval, time_prefix, buf_len);
    strlcat(retval, ".", buf_len);
    strlcat(retval, random_id, buf_len);
    strlcat(retval, ".", buf_len);
    strlcat(retval, new_uuid, buf_len);        
    strlcat(retval, "@", buf_len);    
    strlcat(retval, domain_ptr, buf_len);    

    msg->id = retval;
    
    free(time_prefix);
    free(random_id);
    
    return PEP_STATUS_OK;
        
enomem:
    free(time_prefix);
    free(random_id);
    return PEP_OUT_OF_MEMORY;
}

/* 
   WARNING: For the moment, this only works for the first line of decrypted
   plaintext because we don't need more. IF WE DO, THIS MUST BE EXPANDED, or
   we need a delineated section to parse separately
   
   Does case-insensitive compare of keys, so sending in a lower-cased
   string constant saves a bit of computation
 */
static PEP_STATUS get_data_from_encapsulated_line(const char* plaintext, const char* key, 
                                                  const size_t keylen, char** data, 
                                                  char** modified_msg) {
    char* _data = NULL;
    char* _modified = NULL;
    
    if (strncasecmp(plaintext, key, keylen) == 0) {
        const char *line_end = strchr(plaintext, '\n');

        if (line_end == NULL) {
            _data = strdup(plaintext + keylen);
            assert(_data);
            if (_data == NULL)
                return PEP_OUT_OF_MEMORY;
        }
        else {
            size_t n = line_end - plaintext;

            if (*(line_end - 1) == '\r')
                _data = strndup(plaintext + keylen, n - (keylen + 1));
            else
                _data = strndup(plaintext + keylen, n - keylen);
            assert(_data);
            if (_data == NULL)
                return PEP_OUT_OF_MEMORY;

            while (*(plaintext + n) && (*(plaintext + n) == '\n' || *(plaintext + n) == '\r'))
                ++n;

            if (*(plaintext + n)) {
                _modified = strdup(plaintext + n);
                assert(_modified);
                if (_modified == NULL)
                    return PEP_OUT_OF_MEMORY;
            }
        }
    }
    *data = _data;
    *modified_msg = _modified;
    return PEP_STATUS_OK;
}


static int separate_short_and_long(const char *src, char **shortmsg, char** msg_wrap_info, char **longmsg)
{
    char *_shortmsg = NULL;
    char *_msg_wrap_info = NULL;
    char *_longmsg = NULL;

    assert(src);
    assert(shortmsg);
    assert(msg_wrap_info);
    assert(longmsg);

    if (src == NULL || shortmsg == NULL || msg_wrap_info == NULL || longmsg == NULL)
        return -1;

    *shortmsg = NULL;
    *longmsg = NULL;
    *msg_wrap_info = NULL;

    // We generated the input here. If we ever need more than one header value to be
    // encapsulated and hidden in the encrypted text, we will have to modify this.
    // As is, we're either doing this with a version 1.0 client, in which case
    // the only encapsulated header value is subject, or 2.0+, in which the
    // message wrap info is the only encapsulated header value. If we need this
    // to be more complex, we're going to have to do something more elegant
    // and efficient.    
    PEP_STATUS status = get_data_from_encapsulated_line(src, PEP_SUBJ_KEY_LC, 
                                                        PEP_SUBJ_KEY_LEN, 
                                                        &_shortmsg, &_longmsg);
                                                        
    if (_shortmsg) {
        if (status == PEP_STATUS_OK)
            *shortmsg = _shortmsg;
        else
            goto enomem;
    }
    else {
        status = get_data_from_encapsulated_line(src, PEP_MSG_WRAP_KEY_LC, 
                                                 PEP_MSG_WRAP_KEY_LEN, 
                                                 &_msg_wrap_info, &_longmsg);
        if (_msg_wrap_info) {
            if (status == PEP_STATUS_OK)
                *msg_wrap_info = _msg_wrap_info;
            else
                goto enomem;
        }
    }
    
    // If there was no secret data hiding in the first line...
    if (!_shortmsg && !_msg_wrap_info) {
        _longmsg = strdup(src);
        assert(_longmsg);
        if (_longmsg == NULL)
            goto enomem;
    }
    
    *longmsg = _longmsg;

    return 0;

enomem:
    free(_shortmsg);
    free(_msg_wrap_info);
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

// FIXME: error mem leakage
static message* extract_minimal_envelope(const message* src, 
                                         PEP_msg_direction direct) {
                                                 
    message* envelope = new_message(direct);
    if (!envelope)
        return NULL;
        
    envelope->shortmsg = _pep_subj_copy();
    if (!envelope->shortmsg)
        goto enomem;

    if (src->from) {
        envelope->from = identity_dup(src->from);
        if (!envelope->from)
            goto enomem;
    }

    if (src->to) {
        envelope->to = identity_list_dup(src->to);
        if (!envelope->to)
            goto enomem;
    }

    if (src->cc) {
        envelope->cc = identity_list_dup(src->cc);
        if (!envelope->cc)
            goto enomem;
    }

    if (src->bcc) {
        envelope->bcc = identity_list_dup(src->bcc);
        if (!envelope->bcc)
            goto enomem;
    }

    // For Outlook Force-Encryption
    // const char* pull_keys[] = {"pEp-auto-consume",
    //                            "pEp-force-protection",
    //                            "X-pEp-Never-Unsecure"};
    // int pull_keys_len = 3; // UPDATE WHEN MORE ADDED ABOVE
    // 
    // int i = 0;
    // stringpair_t* opt_add = NULL;    
    // for( ; i < pull_keys_len; i++) {        
    //     opt_add = search_optfields(src, pull_keys[i]);
    //     stringpair_list_t* add_ptr = NULL;
    //     if (opt_add) {
    //         add_ptr = stringpair_list_add(src->opt_fields, stringpair_dup(opt_add));
    //         if (!add_ptr)
    //             goto enomem;
    //     }
    //     opt_add = NULL;
    //     add_ptr = NULL;
    // }
        
    envelope->enc_format = src->enc_format;        
    
    return envelope;
    
enomem:
    free(envelope);
    return NULL;
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

static message* wrap_message_as_attachment(message* envelope, 
    message* attachment, bool keep_orig_subject) {
    
    if (!attachment)
        return NULL;
    
    message* _envelope = envelope;

    PEP_STATUS status = PEP_STATUS_OK;

    replace_opt_field(attachment, "X-pEp-Version", PEP_VERSION);
        
    if (!_envelope) {
        _envelope = extract_minimal_envelope(attachment, PEP_dir_outgoing);
        status = generate_message_id(_envelope);
        
        if (status != PEP_STATUS_OK)
            goto enomem;
        
        attachment->longmsg = encapsulate_message_wrap_info("INNER", attachment->longmsg);
        _envelope->longmsg = encapsulate_message_wrap_info("OUTER", _envelope->longmsg);
    }
    else {
        _envelope->longmsg = encapsulate_message_wrap_info("TRANSPORT", _envelope->longmsg);
    }
    
    if (!attachment->id || attachment->id[0] == '\0') {
        free(attachment->id);
        if (!_envelope->id) {
            status = generate_message_id(_envelope);
        
            if (status != PEP_STATUS_OK)
                goto enomem;
        }
            
        attachment->id = strdup(_envelope->id);
    }
    
    char* message_text = NULL;

    /* prevent introduction of pEp in inner message */

    if (!attachment->shortmsg) {
        attachment->shortmsg = strdup("");
        if (!attachment->shortmsg)
            goto enomem;
    }
            
    /* Turn message into a MIME-blob */
    status = _mime_encode_message_internal(attachment, false, &message_text, true);
        
    if (status != PEP_STATUS_OK)
        goto enomem;
    
    size_t message_len = strlen(message_text);
    
    bloblist_t* message_blob = new_bloblist(message_text, message_len,
                                            "message/rfc822", NULL);
    
    _envelope->attachments = message_blob;
    if (keep_orig_subject && attachment->shortmsg)
        _envelope->shortmsg = strdup(attachment->shortmsg);
    return _envelope;
    
enomem:
    if (!envelope) {
        free_message(_envelope);
    }
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

    if (src->shortmsg)
        dst->shortmsg = strdup(src->shortmsg);
        
    message *_src = calloc(1, sizeof(message));
    assert(_src);
    if (_src == NULL)
        goto enomem;
//    _src->longmsg = ptext;
    _src->longmsg = src->longmsg;
    _src->longmsg_formatted = src->longmsg_formatted;
    _src->attachments = src->attachments;
    _src->enc_format = PEP_enc_none;
    bool mime_encode = !is_wrapper(_src);
    status = _mime_encode_message_internal(_src, true, &mimetext, mime_encode);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    if (free_ptext){
        free(ptext);
        free_ptext=0;
    }
    free(_src);
    _src = NULL;
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
        "file://msg.asc");
    if (_a == NULL)
        goto enomem;

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    if (free_ptext)
        free(ptext);
    free(_src);
    free(ctext);
    return status;
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

    if (blob == NULL || blob->filename == NULL || is_cid_uri(blob->filename))
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
    if (blob == NULL || blob->filename == NULL || is_cid_uri(blob->filename))
        return false;

    const char* bare_filename_ptr = _get_resource_ptr_noown(blob->filename);
    if (strncmp(bare_filename_ptr, "PGPexch.htm.", 12) == 0) {
        if (strcmp(bare_filename_ptr + 11, ".pgp") == 0 ||
            strcmp(bare_filename_ptr + 11, ".asc") == 0)
            return true;
    }

    return false;
}

static char * without_double_ending(const char *filename)
{
    assert(filename);
    if (filename == NULL || is_cid_uri(filename))
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
    case PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH:
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

    assert(session);
    assert(fpr);

    if (session == NULL || fpr == NULL)
        return PEP_rating_undefined;


    PEP_comm_type bare_comm_type = PEP_ct_unknown;
    PEP_comm_type resulting_comm_type = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, fpr, &bare_comm_type);
    if (status != PEP_STATUS_OK)
        return PEP_rating_undefined;

    PEP_comm_type least_comm_type = PEP_ct_unknown;
    least_trust(session, fpr, &least_comm_type);

    if (least_comm_type == PEP_ct_unknown) {
        resulting_comm_type = bare_comm_type;
    } else if (least_comm_type < PEP_ct_strong_but_unconfirmed ||
               bare_comm_type < PEP_ct_strong_but_unconfirmed) {
        // take minimum if anything bad
        resulting_comm_type = least_comm_type < bare_comm_type ? 
                              least_comm_type : 
                              bare_comm_type;
    } else {
        resulting_comm_type = least_comm_type;
    }
    return _rating(resulting_comm_type, PEP_rating_undefined);
}

static PEP_rating worst_rating(PEP_rating rating1, PEP_rating rating2) {
    return ((rating1 < rating2) ? rating1 : rating2);
}

static PEP_rating keylist_rating(PEP_SESSION session, stringlist_t *keylist, char* sender_fpr, PEP_rating sender_rating)
{
    PEP_rating rating = sender_rating;

    assert(keylist && keylist->value);
    if (keylist == NULL || keylist->value == NULL)
        return PEP_rating_undefined;

    stringlist_t *_kl;
    for (_kl = keylist; _kl && _kl->value; _kl = _kl->next) {

        // Ignore own fpr
        if(_same_fpr(sender_fpr, strlen(sender_fpr), _kl->value, strlen(_kl->value)))
            continue;

        PEP_rating _rating_ = key_rating(session, _kl->value);
         
        if (_rating_ <= PEP_rating_mistrust)
            return _rating_;
            
        if (_rating_ == PEP_rating_unencrypted)
        {
            if (rating > PEP_rating_unencrypted_for_some)
                rating = worst_rating(rating, PEP_rating_unencrypted_for_some);
        }
        else
        {
            rating = worst_rating(rating, _rating_);
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
            identity_list *local_private_idents = NULL;
            import_key(session, bl->value, bl->size, &local_private_idents);
            remove = true;
            if (private_idents && *private_idents == NULL && local_private_idents != NULL)
                *private_idents = local_private_idents;
            else
                free_identity_list(local_private_idents);
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
                      "file://pEpkey.asc");

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
    message* _src = src;
    
    assert(session);
    assert(src);
    assert(dst);

    if (!(session && src && dst))
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);

    if (src->dir == PEP_dir_incoming)
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);

    determine_encryption_format(src);
    // TODO: change this for multi-encryption in message format 2.0
    if (src->enc_format != PEP_enc_none)
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);

    *dst = NULL;

    status = myself(session, src->from);
    if (status != PEP_STATUS_OK)
        GOTO(pep_error);

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

    if (enc_format != PEP_enc_none && (_il = src->bcc) && _il->ident)
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
            GOTO(pep_error);
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
                GOTO(pep_error);
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
                GOTO(pep_error);
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

    if (enc_format == PEP_enc_none || !dest_keys_found ||
        stringlist_length(keys)  == 0 ||
        _rating(max_comm_type,
                PEP_rating_undefined) < PEP_rating_reliable)
    {
        free_stringlist(keys);
        if (!session->passive_mode && 
            !(flags & PEP_encrypt_flag_force_no_attached_key)) {
            attach_own_key(session, src);
            decorate_message(src, PEP_rating_undefined, NULL, true);
        }
        return ADD_TO_LOG(PEP_UNENCRYPTED);
    }
    else {
        // FIXME - we need to deal with transport types (via flag)
        if ((max_comm_type | PEP_ct_confirmed) == PEP_ct_pEp) {
            _src = wrap_message_as_attachment(NULL, src, session->unencrypted_subject);
            if (!_src)
                goto pep_error;
        }
        else {
            // hide subject
            if (!session->unencrypted_subject) {
                status = replace_subject(_src);
                if (status == PEP_OUT_OF_MEMORY)
                    goto enomem;
            }
        }
        if (!(flags & PEP_encrypt_flag_force_no_attached_key))
            attach_own_key(session, _src);

        msg = clone_to_empty_message(_src);
        if (msg == NULL)
            goto enomem;

        switch (enc_format) {
            case PEP_enc_PGP_MIME:
            case PEP_enc_PEP: // BUG: should be implemented extra
                status = encrypt_PGP_MIME(session, _src, keys, msg, flags);
                break;

            // case PEP_enc_pieces:
            //     status = encrypt_PGP_in_pieces(session, src, keys, msg, flags);
            //     break;

            /* case PEP_enc_PEP:
                // TODO: implement
                NOT_IMPLEMENTED */

            default:
                assert(0);
                status = PEP_ILLEGAL_VALUE;
                GOTO(pep_error);
        }

        if (status == PEP_OUT_OF_MEMORY)
            goto enomem;

        if (status != PEP_STATUS_OK)
            GOTO(pep_error);
    }

    free_stringlist(keys);

    if (msg && msg->shortmsg == NULL) {
        msg->shortmsg = strdup("");
        assert(msg->shortmsg);
        if (msg->shortmsg == NULL)
            goto enomem;
    }

    if (msg) {
        decorate_message(msg, PEP_rating_undefined, NULL, true);
        if (_src->id) {
            msg->id = strdup(_src->id);
            assert(msg->id);
            if (msg->id == NULL)
                goto enomem;
        }
    }

    *dst = msg;
    
    // ??? FIXME: Check to be sure we don't have references btw _src and msg. 
    // I don't think we do.
    if (_src && _src != src)
        free_message(_src);
        
    return ADD_TO_LOG(status);

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free_stringlist(keys);
    free_message(msg);
    if (_src && _src != src)
        free_message(_src);

    return ADD_TO_LOG(status);
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
    message* _src = src;

    assert(session);
    assert(src);
    assert(dst);
    assert(enc_format != PEP_enc_none);

    if (!(session && src && dst && enc_format != PEP_enc_none))
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);

    if (src->dir == PEP_dir_incoming)
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);

    determine_encryption_format(src);
    if (src->enc_format != PEP_enc_none)
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);

    status = myself(session, target_id);
    if (status != PEP_STATUS_OK)
        GOTO(pep_error);

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
    
    /* KG: did we ever do this??? */
    if (!(flags & PEP_encrypt_flag_force_no_attached_key))
        _attach_key(session, target_fpr, src);

    _src = wrap_message_as_attachment(NULL, src, session->unencrypted_subject);
    if (!_src)
        goto pep_error;

    msg = clone_to_empty_message(_src);
    if (msg == NULL)
        goto enomem;

    switch (enc_format) {
        case PEP_enc_PGP_MIME:
        case PEP_enc_PEP: // BUG: should be implemented extra
            status = encrypt_PGP_MIME(session, _src, keys, msg, flags);
            break;

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
         msg->shortmsg = _pep_subj_copy();
         assert(msg->shortmsg);
         if (msg->shortmsg == NULL)
             goto enomem;
     }

     if (msg) {
         if (_src->id) {
             msg->id = strdup(_src->id);
             assert(msg->id);
             if (msg->id == NULL)
                 goto enomem;
         }
     }

    *dst = msg;
    
    if (src != _src)
        free_message(_src);

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free_stringlist(keys);
    free_message(msg);
    if (src != _src)
        free_message(_src);

    return ADD_TO_LOG(status);
}

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
            status = set_identity(session, src->from);
        }
        return status;
    }
    return PEP_ILLEGAL_VALUE;
}


static PEP_STATUS _get_detached_signature(message* msg, 
                                          bloblist_t** signature_blob) {
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

static PEP_STATUS _get_signed_text(const char* ptext, const size_t psize,
                                   char** stext, size_t* ssize) {

    char* signed_boundary = NULL;
    char* signpost = strstr(ptext, "Content-Type: multipart/signed");

    *ssize = 0;
    *stext = NULL;

    if (!signpost)
        return PEP_UNKNOWN_ERROR;

    char* curr_line = signpost;
//    const char* end_text = ptext + psize;
    const char* boundary_key = "boundary=";
    const size_t BOUNDARY_KEY_SIZE = 9;

    char* start_boundary = strstr(curr_line, boundary_key);
    if (!start_boundary)
        return PEP_UNKNOWN_ERROR;

    start_boundary += BOUNDARY_KEY_SIZE;

    bool quoted = (*start_boundary == '"');

    if (quoted)
        start_boundary++;
        
    char* end_boundary = (quoted ? strstr(start_boundary, "\"") : strstr(start_boundary, ";")); // FIXME: third possiblity is CRLF, or?

    if (!end_boundary)
        return PEP_UNKNOWN_ERROR;

    // Add space for the "--"
    size_t boundary_strlen = (end_boundary - start_boundary) + 2;

    signed_boundary = calloc(boundary_strlen + 1, 1);
    strlcpy(signed_boundary, "--", boundary_strlen + 1);
    strlcat(signed_boundary, start_boundary, boundary_strlen + 1);

    start_boundary = strstr(end_boundary, signed_boundary);

    if (!start_boundary)
        return PEP_UNKNOWN_ERROR;

    start_boundary += boundary_strlen;

    if (*start_boundary == '\r') {
        if (*(start_boundary + 1) == '\n')
            start_boundary += 2;
    }
    else if (*start_boundary == '\n')
        start_boundary++;

    end_boundary = strstr(start_boundary + boundary_strlen, signed_boundary);

    if (!end_boundary)
        return PEP_UNKNOWN_ERROR;

    // See RFC3156 section 5...
    end_boundary--; 
    if (*(end_boundary - 1) == '\r')
        end_boundary--; 

    *ssize = end_boundary - start_boundary;
    *stext = start_boundary;
    free(signed_boundary);

    return PEP_STATUS_OK;
}

static PEP_STATUS combine_keylists(PEP_SESSION session, stringlist_t** verify_in, 
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
        stringlist_t* second_list = *keylist_in_out;
        if (second_list) {
            char* listhead_val = second_list->value;
            if (!listhead_val || listhead_val[0] == '\0') {
                /* remove head, basically. This can happen when,
                   for example, the signature is detached and
                   verification is not seen directly after
                   decryption, so no signer is presumed in
                   the first construction of the keylist */
                *keylist_in_out = (*keylist_in_out)->next;
                second_list->next = NULL;
                free_stringlist(second_list);
            }
        }
        *tail_pp = *keylist_in_out;
    }
    
    *keylist_in_out = verify_curr;
    
    status = PEP_STATUS_OK;
    
free:
    free_stringlist(from_keys);
    return status;
}

static PEP_STATUS amend_rating_according_to_sender_and_recipients(
       PEP_SESSION session,
       PEP_rating *rating,
       pEp_identity *sender,
       stringlist_t *recipients) {
    
    PEP_STATUS status = PEP_STATUS_OK;

    if (*rating > PEP_rating_mistrust) {

        if (recipients == NULL) {
            *rating = PEP_rating_undefined;
            return PEP_STATUS_OK;
        }

        char *fpr = recipients->value;

        if (!(sender && sender->user_id && sender->user_id[0] && fpr && fpr[0])) {
            *rating = PEP_rating_unreliable;
        }
        else {
            pEp_identity *_sender = new_identity(sender->address, fpr,
                                               sender->user_id, sender->username);
            if (_sender == NULL)
                return PEP_OUT_OF_MEMORY;

            status = get_trust(session, _sender);
            if (_sender->comm_type == PEP_ct_unknown) {
                get_key_rating(session, fpr, &_sender->comm_type);
                
            }
            if (_sender->comm_type != PEP_ct_unknown) {
                *rating = keylist_rating(session, recipients, 
                            fpr, _rating(_sender->comm_type, 
                                          PEP_rating_undefined));
            }
            
            free_identity(_sender);
            if (status == PEP_CANNOT_FIND_IDENTITY)
               status = PEP_STATUS_OK;
        }
    }
    return status;
}

// FIXME: Do we need to remove the attachment? I think we do...
static bool pull_up_attached_main_msg(message* src) {
    char* slong = src->longmsg;
    char* sform = src->longmsg_formatted;
    bloblist_t* satt = src->attachments;
    
    if ((!slong || slong[0] == '\0')
         && (!sform || sform[0] == '\0')) {
        if (satt) {
            const char* inner_mime_type = satt->mime_type;
            if (strcasecmp(inner_mime_type, "text/plain") == 0) {
                free(slong); /* in case of "" */
                src->longmsg = strndup(satt->value, satt->size); 
                
                bloblist_t* next_node = satt->next;
                if (next_node) {
                    inner_mime_type = next_node->mime_type;
                    if (strcasecmp(inner_mime_type, "text/html") == 0) {
                        free(sform);
                        src->longmsg_formatted = strndup(next_node->value, next_node->size);
                    }
                }
            }
            else if (strcasecmp(inner_mime_type, "text/html") == 0) {
                free(sform);
                src->longmsg_formatted = strndup(satt->value, satt->size);
            }
        }
        return true;
    }
    return false;
}



static PEP_STATUS unencapsulate_hidden_fields(message* src, message* msg,
                                              char** msg_wrap_info) {
    if (!src)
        return PEP_ILLEGAL_VALUE;
    unsigned char pepstr[] = PEP_SUBJ_STRING;
    PEP_STATUS status = PEP_STATUS_OK;

    bool change_source_in_place = (msg ? false : true);
    
    if (change_source_in_place)
        msg = src;
        
    
    switch (src->enc_format) {
        case PEP_enc_PGP_MIME:
        case PEP_enc_pieces:
        case PEP_enc_PGP_MIME_Outlook1:
//        case PEP_enc_none: // FIXME - this is wrong

            if (!change_source_in_place)
                status = copy_fields(msg, src);
                
            if (status != PEP_STATUS_OK)
                return status;
                
            // FIXME: This is a mess. Talk with VB about how far we go to identify
            if (is_a_pEpmessage(src) || (src->shortmsg == NULL || strcmp(src->shortmsg, "pEp") == 0 ||
                _unsigned_signed_strcmp(pepstr, src->shortmsg, PEP_SUBJ_BYTELEN) == 0) ||
                (strcmp(src->shortmsg, "p=p") == 0))
            {
                char * shortmsg = NULL;
                char * longmsg = NULL;
        
                if (msg->longmsg) {
                    int r = separate_short_and_long(msg->longmsg, 
                                                    &shortmsg, 
                                                    msg_wrap_info,
                                                    &longmsg);
                
                    if (r == -1)
                        return PEP_OUT_OF_MEMORY;
                }

                // We only use the shortmsg in version 1.0 messages; if it occurs where we
                // didn't replace the subject, we ignore this all
                if (!(*msg_wrap_info || change_source_in_place)) {
                    if (!shortmsg || 
                        (src->shortmsg != NULL && strcmp(src->shortmsg, "pEp") != 0 &&
                         _unsigned_signed_strcmp(pepstr, src->shortmsg, PEP_SUBJ_BYTELEN) != 0 &&
                        strcmp(src->shortmsg, "p=p") != 0)) {
                             
                        if (shortmsg != NULL)
                            free(shortmsg);                        
                            
                        if (src->shortmsg == NULL) {
                            shortmsg = strdup("");
                        }
                        else {
                            // FIXME: is msg->shortmsg always a copy of
                            // src->shortmsg already?
                            // if so, we need to change the logic so
                            // that in this case, we don't free msg->shortmsg
                            // and do this strdup, etc
                            shortmsg = strdup(src->shortmsg);
                        }        
                    }
                    free(msg->shortmsg);
                    msg->shortmsg = shortmsg;
                }
                
                free(msg->longmsg);

                msg->longmsg = longmsg;
            }
            else {
                if (!change_source_in_place) {
                    msg->shortmsg = strdup(src->shortmsg);
                    assert(msg->shortmsg);
                    if (msg->shortmsg == NULL)
                        return PEP_OUT_OF_MEMORY;
                }
            }
            break;
        default:
                // BUG: must implement more
                NOT_IMPLEMENTED
    }
    return PEP_STATUS_OK;

}

static PEP_STATUS get_crypto_text(message* src, char** crypto_text, size_t* text_size) {
                
    // this is only here because of how NOT_IMPLEMENTED works            
    PEP_STATUS status = PEP_STATUS_OK;
                    
    switch (src->enc_format) {
        case PEP_enc_PGP_MIME:
            *crypto_text = src->attachments->next->value;
            *text_size = src->attachments->next->size;
            break;

        case PEP_enc_PGP_MIME_Outlook1:
            *crypto_text = src->attachments->value;
            *text_size = src->attachments->size;
            break;

        case PEP_enc_pieces:
            *crypto_text = src->longmsg;
            *text_size = strlen(*crypto_text);
            break;

        default:
            NOT_IMPLEMENTED
    }
    
    return status;
}


static PEP_STATUS verify_decrypted(PEP_SESSION session,
                                   message* src,
                                   message* msg, 
                                   char* plaintext, 
                                   size_t plaintext_size,
                                   stringlist_t** keylist,
                                   PEP_STATUS* decrypt_status,
                                   PEP_cryptotech crypto) {

    assert(src && src->from);
    
    if (!src && !src->from)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS _cached_decrypt_status = *decrypt_status;
        
    pEp_identity* sender = src->from;

    bloblist_t* detached_sig = NULL;
    PEP_STATUS status = _get_detached_signature(msg, &detached_sig);
    stringlist_t *verify_keylist = NULL;
    
    
    if (detached_sig) {
        char* dsig_text = detached_sig->value;
        size_t dsig_size = detached_sig->size;
        size_t ssize = 0;
        char* stext = NULL;

        status = _get_signed_text(plaintext, plaintext_size, &stext, &ssize);

        if (ssize > 0 && stext) {
            status = cryptotech[crypto].verify_text(session, stext,
                                                    ssize, dsig_text, dsig_size,
                                                    &verify_keylist);
        }
        
        if (status == PEP_VERIFIED || status == PEP_VERIFIED_AND_TRUSTED)
        {
            *decrypt_status = PEP_DECRYPTED_AND_VERIFIED;
        
            status = combine_keylists(session, &verify_keylist, keylist, sender);
        }
    }
    else {
        size_t csize, psize;
        char* ctext;
        char* ptext;
        get_crypto_text(src, &ctext, &csize);
        // reverify - we may have imported a key in the meantime
        // status = cryptotech[crypto].verify_text(session, ctext,
        //                                         csize, NULL, 0,
        //                                         &verify_keylist);
        free_stringlist(*keylist);
        *decrypt_status = decrypt_and_verify(session, ctext, csize,
                                            NULL, 0,
                                            &ptext, &psize, keylist);
        
    }

    if (*decrypt_status != PEP_DECRYPTED_AND_VERIFIED)
        *decrypt_status = _cached_decrypt_status;                                

    return PEP_STATUS_OK;
}

static PEP_STATUS _decrypt_in_pieces(PEP_SESSION session, 
                                     message* src, 
                                     message** msg_ptr, 
                                     char* ptext,
                                     size_t psize) {
                            
    PEP_STATUS status = PEP_STATUS_OK;
    
    *msg_ptr = clone_to_empty_message(src);

    if (*msg_ptr == NULL)
        return PEP_OUT_OF_MEMORY;

    message* msg = *msg_ptr;

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
                return PEP_OUT_OF_MEMORY;

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
                        return PEP_OUT_OF_MEMORY;

                    _m = bloblist_add(_m, ptext, psize, mime_type,
                        filename);
                    free(filename);
                    if (_m == NULL)
                        return PEP_OUT_OF_MEMORY;

                    ptext = NULL;

                    if (msg->attachments == NULL)
                        msg->attachments = _m;
                }
            }
            else {
                char *copy = malloc(_s->size);
                assert(copy);
                if (copy == NULL)
                    return PEP_OUT_OF_MEMORY;
                memcpy(copy, _s->value, _s->size);
                _m = bloblist_add(_m, copy, _s->size, _s->mime_type, _s->filename);
                if (_m == NULL)
                    return PEP_OUT_OF_MEMORY;
            }
        }
        else {
            char *copy = malloc(_s->size);
            assert(copy);
            if (copy == NULL)
                return PEP_OUT_OF_MEMORY;
            memcpy(copy, _s->value, _s->size);
            _m = bloblist_add(_m, copy, _s->size, _s->mime_type, _s->filename);
            if (_m == NULL)
                return PEP_OUT_OF_MEMORY;
        }
    }
    return status;
}

static PEP_STATUS import_priv_keys_from_decrypted_msg(PEP_SESSION session,
                                                      message* src, 
                                                      message* msg,
                                                      bool* imported_keys,
                                                      bool* imported_private,
                                                      identity_list** private_il) {
                                                          
    PEP_STATUS status = PEP_STATUS_OK;
    
    // check for private key in decrypted message attachment while importing
    identity_list *_private_il = NULL;
    *imported_keys = import_attached_keys(session, msg, &_private_il);
    
    if (_private_il && identity_list_length(_private_il) == 1 &&
        _private_il->ident->address)
        *imported_private = true;

    if (private_il && imported_private) {
        // the private identity list should NOT be subject to myself() or
        // update_identity() at this point.
        // If the receiving app wants them to be in the trust DB, it
        // should call myself() on them upon return.
        // We do, however, prepare these so the app can use them
        // directly in a myself() call by putting the own_id on it.
        char* own_id = NULL;
        status = get_default_own_userid(session, &own_id);
        
        if (status != PEP_STATUS_OK) {
            free(own_id);
            own_id = NULL;
        }
        
        identity_list* il = _private_il;
        for ( ; il; il = il->next) {
            if (own_id) {
                free(il->ident->user_id);
                il->ident->user_id = strdup(own_id);
            }
            il->ident->me = true;
        }
        *private_il = _private_il;
        
        free(own_id);
    }
    else
        free_identity_list(_private_il);
 
    
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
    
    assert(session);
    assert(src);
    assert(dst);
    assert(keylist);
    assert(rating);
    assert(flags);

    if (!(session && src && dst && keylist && rating && flags))
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);

    /*** Begin init ***/
    PEP_STATUS status = PEP_STATUS_OK;
    PEP_STATUS decrypt_status = PEP_CANNOT_DECRYPT_UNKNOWN;
    message *msg = NULL;
    char *ctext;
    size_t csize;
    char *ptext = NULL;
    size_t psize;
    stringlist_t *_keylist = NULL;

    *dst = NULL;
    *keylist = NULL;
    *rating = PEP_rating_undefined;

    *flags = 0;
    /*** End init ***/

    /*** Begin Import any attached public keys and update identities accordingly ***/

    // Private key in unencrypted mail are ignored -> NULL
    bool imported_keys = import_attached_keys(session, src, NULL);

    // Update src->from in case we just imported a key
    // we would need to check signature
    status = _update_identity_for_incoming_message(session, src);
    
    if (status == PEP_ILLEGAL_VALUE && src->from && is_me(session, src->from)) {
        // the above function should fail if it's us.
        // We don't need to update, as any revocations or expirations
        // of our own key imported above, which are all that we 
        // would care about for anything imported,
        // SHOULD get caught when they matter later.
        // (Private keys imported above are not stored in the trust DB)
        status = PEP_STATUS_OK;
    }
        
    if (status != PEP_STATUS_OK)
        return ADD_TO_LOG(status);

    /*** End Import any attached public keys and update identities accordingly ***/
    
    /*** Begin get detached signatures that are attached to the encrypted message ***/
    // Get detached signature, if any
    bloblist_t* detached_sig = NULL;
    char* dsig_text = NULL;
    size_t dsig_size = 0;
    status = _get_detached_signature(src, &detached_sig);
    if (detached_sig) {
        dsig_text = detached_sig->value;
        dsig_size = detached_sig->size;
    }
    /*** End get detached signatures that are attached to the encrypted message ***/

    /*** Determine encryption format ***/
    PEP_cryptotech crypto = determine_encryption_format(src);

    // Check for and deal with unencrypted messages
    if (src->enc_format == PEP_enc_none) {

        *rating = PEP_rating_unencrypted;

        if (imported_keys)
            remove_attached_keys(src);
                                    
        pull_up_attached_main_msg(src);
        
        return ADD_TO_LOG(PEP_UNENCRYPTED);
    }

    status = get_crypto_text(src, &ctext, &csize);
    if (status != PEP_STATUS_OK)
        return status;
    
    /** Ok, we should be ready to decrypt. Try decrypt and verify first! **/
    status = cryptotech[crypto].decrypt_and_verify(session, ctext,
                                                   csize, dsig_text, dsig_size,
                                                   &ptext, &psize, &_keylist);

    if (status > PEP_CANNOT_DECRYPT_UNKNOWN)
        GOTO(pep_error);

    decrypt_status = status;
    
    bool imported_private_key_address = false;

    if (ptext) { 
        /* we got a plaintext from decryption */
        switch (src->enc_format) {
            
            case PEP_enc_PGP_MIME:
            case PEP_enc_PGP_MIME_Outlook1:
            
                status = mime_decode_message(ptext, psize, &msg);
                if (status != PEP_STATUS_OK)
                    goto pep_error;
                
                /* Ensure messages whose maintext is in the attachments
                   move main text into message struct longmsg et al */
                if (pull_up_attached_main_msg(msg) && msg->shortmsg) {
                    free(src->shortmsg);
                    src->shortmsg = strdup(msg->shortmsg);
                }

                // check for private key in decrypted message attachment while importing
                // N.B. Apparently, we always import private keys into the keyring; however,
                // we do NOT always allow those to be used for encryption. THAT is controlled
                // by setting it as an own identity associated with the key in the DB.
                status = import_priv_keys_from_decrypted_msg(session, src, msg,
                                                             &imported_keys,
                                                             &imported_private_key_address,
                                                             private_il);
                if (status != PEP_STATUS_OK)
                    GOTO(pep_error);            

                /* if decrypted, but not verified... */
                if (decrypt_status == PEP_DECRYPTED) {
                                                                                     
                    status = verify_decrypted(session,
                                              src, msg,
                                              ptext, psize,
                                              &_keylist,
                                              &decrypt_status,
                                              crypto);
                }
                break;

            case PEP_enc_pieces:
                status = _decrypt_in_pieces(session, src, &msg, ptext, psize);
            
                if (status == PEP_OUT_OF_MEMORY)
                    goto enomem;

                break;

            default:
                // BUG: must implement more
                NOT_IMPLEMENTED
        }

        if (status == PEP_OUT_OF_MEMORY)
            goto enomem;
            
        if (status != PEP_STATUS_OK)
            goto pep_error;

        if (decrypt_status == PEP_DECRYPTED || decrypt_status == PEP_DECRYPTED_AND_VERIFIED) {
            char* wrap_info = NULL;
            
            status = unencapsulate_hidden_fields(src, msg, &wrap_info);

//            bool is_transport_wrapper = false;
            
            // FIXME: replace with enums, check status
            if (wrap_info) {
                if (strcmp(wrap_info, "OUTER") == 0) {
                    // this only occurs in with a direct outer wrapper
                    // where the actual content is in the inner wrapper
                    message* inner_message = NULL;                    
                    bloblist_t* actual_message = msg->attachments;
                    
                    while (actual_message) {
                        char* mime_type = actual_message->mime_type;
                        if (mime_type) {
                            
                            // libetpan appears to change the mime_type on this one.
                            // *growl*
                            if (strcmp("message/rfc822", mime_type) == 0 ||
                                strcmp("text/rfc822", mime_type) == 0) {
                                    
                                status = mime_decode_message(actual_message->value, 
                                                             actual_message->size, 
                                                             &inner_message);
                                if (status != PEP_STATUS_OK)
                                    GOTO(pep_error);
                                
                                if (inner_message) {
                                    // Though this will strip any message info on the
                                    // attachment, this is safe, as we do not
                                    // produce more than one attachment-as-message,
                                    // and those are the only ones with such info.
                                    // Since we capture the information, this is ok.
                                    wrap_info = NULL;
                                    inner_message->enc_format = src->enc_format;
                                    // FIXME
                                    status = unencapsulate_hidden_fields(inner_message, NULL, &wrap_info);
                                    if (wrap_info) {
                                        // useless check, but just in case we screw up?
                                        if (strcmp(wrap_info, "INNER") == 0) {
                                            if (status != PEP_STATUS_OK) {
                                                free_message(inner_message);
                                                GOTO(pep_error);
                                            }
                                                
                                            // THIS is our message
                                            // FIXME: free msg, but check references
                                            src = msg = inner_message;
                                            
                                            if (src->from)
                                                update_identity(session, src->from);
                                            break;        
                                        }
                                        else { // should never happen
                                            status = PEP_UNKNOWN_ERROR;
                                            free_message(inner_message);
                                            GOTO(pep_error);
                                        }
                                    }
                                    inner_message->enc_format = PEP_enc_none;
                                }
                                else { // forwarded message, leave it alone
                                    free_message(inner_message);
                                }
                            }
                        }
                        actual_message = actual_message->next;
                    }                    
                }
                else if (strcmp(wrap_info, "TRANSPORT") == 0) {
                    // FIXME: this gets even messier.
                    // (TBI in ENGINE-278)
                }
                else {} // shouldn't be anything to be done here
            }
        }
        
        *rating = decrypt_rating(decrypt_status);

        /* Ok, now we have a keylist used for decryption/verification.
           now we need to update the message rating with the 
           sender and recipients in mind */
        status = amend_rating_according_to_sender_and_recipients(session,
                rating, src->from, _keylist);

        if (status != PEP_STATUS_OK)
            GOTO(pep_error);
        
        /* We decrypted ok, hallelujah. */
        msg->enc_format = PEP_enc_none;    
    } 
    else {
        // We did not get a plaintext out of the decryption process.
        // Abort and return error.
        *rating = decrypt_rating(decrypt_status);
        goto pep_error;
    }

    /* 
       Ok, at this point, we know we have a reliably decrypted message.
       Prepare the output message for return.
    */
    
    // 1. Check to see if this message is to us and contains an own key imported 
    // from own trusted message 
    if (msg && *rating >= PEP_rating_trusted && imported_private_key_address &&
        msg->to && msg->to->ident && msg->to->ident->me) {

        // flag it as such
        *flags |= PEP_decrypt_flag_own_private_key;
    }

    // 2. Clean up message and prepare for return 
    if (msg) {
        
        /* add pEp-related status flags to header */
        decorate_message(msg, *rating, _keylist, false);
        
        if (imported_keys)
            remove_attached_keys(msg);
                    
        if (src->id && src != msg) {
            msg->id = strdup(src->id);
            assert(msg->id);
            if (msg->id == NULL)
                goto enomem;
        }
    } // End prepare output message for return

    *dst = msg;
    *keylist = _keylist;

    if(decrypt_status == PEP_DECRYPTED_AND_VERIFIED)
        return ADD_TO_LOG(PEP_STATUS_OK);
    else
        return ADD_TO_LOG(decrypt_status);

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    free(ptext);
    free_message(msg);
    free_stringlist(_keylist);

    return ADD_TO_LOG(status);
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

    return ADD_TO_LOG(status);
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
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);

    if (msg->dir != PEP_dir_outgoing)
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);

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

/* [0-9]: 0x30 - 0x39; [A-F] = 0x41 - 0x46; [a-f] = 0x61 - 0x66 */
static short asciihex_to_num(char a) {
    short conv_num = -1;
    if (a >= 0x30 && a <= 0x39)
        conv_num = a - 0x30;
    else {
        // convert case, subtract offset, get number
        conv_num = ((a | 0x20) - 0x61) + 10;
        if (conv_num < 0xa || conv_num > 0xf)
            conv_num = -1;
    }
    return conv_num;
}

static char num_to_asciihex(short h) {
    if (h < 0 || h > 16)
        return '\0';
    if (h < 10)
        return (char)(h + 0x30);
    return (char)((h - 10) + 0x41); // for readability
}

static char xor_hex_chars(char a, char b) {
    short a_num = asciihex_to_num(a);
    short b_num = asciihex_to_num(b);
    if (a_num < 0 || b_num < 0)
        return '\0';
    short xor_num = a_num^b_num;
    return num_to_asciihex(xor_num);
}

static char* skip_separators(char* current, char* begin) {
    while (current >= begin) {
        /* .:,;-_ ' ' - [2c-2e] [3a-3b] [20] [5f] */
        char check_char = *current;
        switch (check_char) {
            case '.':
            case ':':
            case ',':
            case ';':
            case '-':
            case '_':
            case ' ':
                current--;
                continue;
            default:
                break;
        }
        break;
    }
    return current;
}

PEP_STATUS check_for_zero_fpr(char* fpr) {
    PEP_STATUS status = PEP_TRUSTWORDS_DUPLICATE_FPR;
    
    while (*fpr) {
        if (*fpr != '0') {
            status = PEP_STATUS_OK;
            break;
        }
        fpr++;    
    }
    
    return status;
    
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

    int SHORT_NUM_TWORDS = 5; 
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    if (!(session && id1 && id2 && words && wsize) ||
        !(id1->fpr) || (!id2->fpr))
        return PEP_ILLEGAL_VALUE;

    char *source1 = id1->fpr;
    char *source2 = id2->fpr;

    int source1_len = strlen(source1);
    int source2_len = strlen(source2);
    int max_len;
        
    *words = NULL;    
    *wsize = 0;

    max_len = (source1_len > source2_len ? source1_len : source2_len);
    
    char* XORed_fpr = (char*)(calloc(max_len + 1, 1));
    *(XORed_fpr + max_len) = '\0';
    char* result_curr = XORed_fpr + max_len - 1;
    char* source1_curr = source1 + source1_len - 1;
    char* source2_curr = source2 + source2_len - 1;

    while (source1 <= source1_curr && source2 <= source2_curr) {
        source1_curr = skip_separators(source1_curr, source1);
        source2_curr = skip_separators(source2_curr, source2);
        
        if (source1_curr < source1 || source2_curr < source2)
            break;
            
        char xor_hex = xor_hex_chars(*source1_curr, *source2_curr);
        if (xor_hex == '\0') {
            status = PEP_ILLEGAL_VALUE;
            goto error_release;
        }
        
        *result_curr = xor_hex;
        result_curr--; source1_curr--; source2_curr--;
    }

    char* remainder_start = NULL;
    char* remainder_curr = NULL;
    
    if (source1 <= source1_curr) {
        remainder_start = source1;
        remainder_curr = source1_curr;
    }
    else if (source2 <= source2_curr) {
        remainder_start = source2;
        remainder_curr = source2_curr;
    }
    if (remainder_curr) {
        while (remainder_start <= remainder_curr) {
            remainder_curr = skip_separators(remainder_curr, remainder_start);
            
            if (remainder_curr < remainder_start)
                break;
            
            char the_char = *remainder_curr;
            
            if (asciihex_to_num(the_char) < 0) {
                status = PEP_ILLEGAL_VALUE;
                goto error_release;
            }
            
            *result_curr = the_char;                
            result_curr--;
            remainder_curr--;
        }
    }
    
    result_curr++;

    if (result_curr > XORed_fpr) {
        char* tempstr = strdup(result_curr);
        free(XORed_fpr);
        XORed_fpr = tempstr;
    }
    
    status = check_for_zero_fpr(XORed_fpr);
    
    if (status != PEP_STATUS_OK)
        goto error_release;
    
    size_t max_words_per_id = (full ? 0 : SHORT_NUM_TWORDS);

    char* the_words = NULL;
    size_t the_size = 0;

    status = trustwords(session, XORed_fpr, lang, &the_words, &the_size, max_words_per_id);
    if (status != PEP_STATUS_OK)
        goto error_release;

    *words = the_words;
    *wsize = the_size;
    
    status = PEP_STATUS_OK;

    goto the_end;

    error_release:
        free (XORed_fpr);
        
    the_end:
    return ADD_TO_LOG(status);
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
        return ADD_TO_LOG(status);
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
        return ADD_TO_LOG(status);
    }

    // get the trustwords
    size_t wsize;
    status = get_trustwords(session, 
                            partner, received_by, 
                            lang, words, &wsize, full);

    return ADD_TO_LOG(status);
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
    assert(mimetext);
    assert(mime_plaintext);
    assert(keylist);
    assert(rating);
    assert(flags);

    PEP_STATUS status = PEP_STATUS_OK;
    message* tmp_msg = NULL;
    message* dec_msg = NULL;
    *mime_plaintext = NULL;

    status = mime_decode_message(mimetext, size, &tmp_msg);
    if (status != PEP_STATUS_OK)
        GOTO(pep_error);

    PEP_STATUS decrypt_status = decrypt_message(session,
                                                tmp_msg,
                                                &dec_msg,
                                                keylist,
                                                rating,
                                                flags);
                                                
    if (!dec_msg && (decrypt_status == PEP_UNENCRYPTED || decrypt_status == PEP_VERIFIED)) {
        dec_msg = message_dup(tmp_msg);
    }
        
    if (decrypt_status > PEP_CANNOT_DECRYPT_UNKNOWN || !dec_msg)
    {
        status = decrypt_status;
        GOTO(pep_error);
    }

    // FIXME: test with att
    status = _mime_encode_message_internal(dec_msg, false, mime_plaintext, false);

    if (status == PEP_STATUS_OK)
    {
        free(tmp_msg);
        free(dec_msg);
        return ADD_TO_LOG(decrypt_status);
    }
    
pep_error:
    free_message(tmp_msg);
    free_message(dec_msg);

    return ADD_TO_LOG(status);
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
        GOTO(pep_error);

    // This isn't incoming, though... so we need to reverse the direction
    tmp_msg->dir = PEP_dir_outgoing;
    status = encrypt_message(session,
                             tmp_msg,
                             extra,
                             &enc_msg,
                             enc_format,
                             flags);
    if (status != PEP_STATUS_OK)
        GOTO(pep_error);


    if (!enc_msg) {
        status = PEP_UNKNOWN_ERROR;
        GOTO(pep_error);
    }

    status = _mime_encode_message_internal(enc_msg, false, mime_ciphertext, false);

pep_error:
    free_message(tmp_msg);
    free_message(enc_msg);

    return ADD_TO_LOG(status);

}

DYNAMIC_API PEP_STATUS MIME_encrypt_message_for_self(
    PEP_SESSION session,
    pEp_identity* target_id,
    const char *mimetext,
    size_t size,
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
    status = encrypt_message_for_self(session,
                                      target_id,
                                      tmp_msg,
                                      &enc_msg,
                                      enc_format,
                                      flags);
    if (status != PEP_STATUS_OK)
        goto pep_error;
 
    if (!enc_msg) {
        status = PEP_UNKNOWN_ERROR;
        goto pep_error;
    }

    status = mime_encode_message(enc_msg, false, mime_ciphertext);

pep_error:
    free_message(tmp_msg);
    free_message(enc_msg);

    return ADD_TO_LOG(status);
}

static PEP_rating string_to_rating(const char * rating)
{
    if (rating == NULL)
        return PEP_rating_undefined;
    if (strcmp(rating, "cannot_decrypt") == 0)
        return PEP_rating_cannot_decrypt;
    if (strcmp(rating, "have_no_key") == 0)
        return PEP_rating_have_no_key;
    if (strcmp(rating, "unencrypted") == 0)
        return PEP_rating_unencrypted;
    if (strcmp(rating, "unencrypted_for_some") == 0)
        return PEP_rating_unencrypted_for_some;
    if (strcmp(rating, "unreliable") == 0)
        return PEP_rating_unreliable;
    if (strcmp(rating, "reliable") == 0)
        return PEP_rating_reliable;
    if (strcmp(rating, "trusted") == 0)
        return PEP_rating_trusted;
    if (strcmp(rating, "trusted_and_anonymized") == 0)
        return PEP_rating_trusted_and_anonymized;
    if (strcmp(rating, "fully_anonymous") == 0)
        return PEP_rating_fully_anonymous;
    if (strcmp(rating, "mistrust") == 0)
        return PEP_rating_mistrust;
    if (strcmp(rating, "b0rken") == 0)
        return PEP_rating_b0rken;
    if (strcmp(rating, "under_attack") == 0)
        return PEP_rating_under_attack;
    return PEP_rating_undefined;
}

static PEP_STATUS string_to_keylist(const char * skeylist, stringlist_t **keylist)
{
    if (skeylist == NULL || keylist == NULL)
        return PEP_ILLEGAL_VALUE;

    stringlist_t *rkeylist = NULL;
    stringlist_t *_kcurr = NULL;
    const char * fpr_begin = skeylist;
    const char * fpr_end = NULL;

    do {
        fpr_end = strstr(fpr_begin, ",");
        
        char * fpr = strndup(
            fpr_begin,
            (fpr_end == NULL) ? strlen(fpr_begin) : fpr_end - fpr_begin);
        
        if (fpr == NULL)
            goto enomem;
        
        _kcurr = stringlist_add(_kcurr, fpr);
        if (_kcurr == NULL) {
            free(fpr);
            goto enomem;
        }
        
        if (rkeylist == NULL)
            rkeylist = _kcurr;
        
        fpr_begin = fpr_end ? fpr_end + 1 : NULL;
        
    } while (fpr_begin);
    
    *keylist = rkeylist;
    return PEP_STATUS_OK;
    
enomem:
    free_stringlist(rkeylist);
    return PEP_OUT_OF_MEMORY;
}

DYNAMIC_API PEP_STATUS re_evaluate_message_rating(
    PEP_SESSION session,
    message *msg,
    stringlist_t *x_keylist,
    PEP_rating x_enc_status,
    PEP_rating *rating
)
{
    PEP_STATUS status = PEP_STATUS_OK;
    stringlist_t *_keylist = x_keylist;
    bool must_free_keylist = false;
    PEP_rating _rating;

    assert(session);
    assert(msg);
    assert(rating);

    if (!(session && msg && rating))
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);

    *rating = PEP_rating_undefined;

    if (x_enc_status == PEP_rating_undefined){
        for (stringpair_list_t *i = msg->opt_fields; i && i->value ; i=i->next) {
            if (strcasecmp(i->value->key, "X-EncStatus") == 0){
                x_enc_status = string_to_rating(i->value->value);
                goto got_rating;
            }
        }
        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);
    }

got_rating:

    _rating = x_enc_status;

    if (_keylist == NULL){
        for (stringpair_list_t *i = msg->opt_fields; i && i->value ; i=i->next) {
            if (strcasecmp(i->value->key, "X-KeyList") == 0){
                status = string_to_keylist(i->value->value, &_keylist);
                if (status != PEP_STATUS_OK)
                    GOTO(pep_error);
                must_free_keylist = true;
                goto got_keylist;
            }
        }

        // there was no rcpt fpr, it could be an unencrypted mail
        if(_rating == PEP_rating_unencrypted) {
            *rating = _rating;
            return ADD_TO_LOG(PEP_STATUS_OK);
        }

        return ADD_TO_LOG(PEP_ILLEGAL_VALUE);
    }
got_keylist:

    status = update_identity(session, msg->from);
    if (status != PEP_STATUS_OK)
        GOTO(pep_error);

    status = amend_rating_according_to_sender_and_recipients(session, &_rating,
            msg->from, _keylist);
    if (status == PEP_STATUS_OK)
        *rating = _rating;
    
pep_error:
    if (must_free_keylist)
        free_stringlist(_keylist);

    return ADD_TO_LOG(status);
}
