/**
 * @file     message_api.c
 * @brief    implementation of pEp engine API for message handling and evaluation and related functions
 * @license  GNU General Public License 3.0 - see LICENSE.txt
 */

#include "pEp_internal.h"
#include "message_api.h"
#include "pEpEngine.h"

#include "platform.h"
#include "mime.h"
#include "baseprotocol.h"
#include "KeySync_fsm.h"
#include "base64.h"
#include "resource_id.h"
#include "internal_format.h"
#include "keymanagement.h"
#include "sync_codec.h"
#include "distribution_codec.h"

#include "keymanagement_internal.h"

#include "group.h"
#include "group_internal.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>


// These are globals used in generating message IDs and should only be
// computed once, as they're either really constants or OS-dependent

int _pEp_rand_max_bits;
double _pEp_log2_36;

/**
 *  @internal
 *
 *  <!--       is_a_pEpmessage()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *msg        constmessage
 *  
 *  @retval     bool
 */
static bool is_a_pEpmessage(const message *msg)
{
    for (stringpair_list_t *i = msg->opt_fields; i && i->value ; i=i->next) {
        if (strcasecmp(i->value->key, "X-pEp-Version") == 0)
            return true;
    }
    return false;
}

/**
 *  @internal
 *
 *  <!--       keylist_to_string()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *keylist        conststringlist_t
 *
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

/**
 *  @internal
 *
 *  <!--       _memnmemn()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *needle        constchar
 *  @param[in]    needle_size        size_t
 *  @param[in]    *haystack        constchar
 *  @param[in]    haystack_size        size_t
 *
 */
bool _memnmemn(const char* needle,
                size_t needle_size,
                const char* haystack, 
                size_t haystack_size) 
{
    if (needle_size > haystack_size) {
        return false;
    }
    else if (needle_size == 0) {
        return true;
    }
                        
    bool found = true;
    const char* haystack_ptr = haystack;
    unsigned int i = 0;
    size_t remaining_hay = haystack_size;
    for (i = 0; i < haystack_size && (remaining_hay >= needle_size); i++, haystack_ptr++) {
        found = false;
        const char* needle_ptr = needle;
        if (*haystack_ptr == *needle) {
            const char* haystack_tmp = haystack_ptr;
            unsigned int j;
            found = true;
            for (j = 0; j < needle_size; j++) {
                if (*needle_ptr++ != *haystack_tmp++) {
                    found = false;
                    break;
                }
            }
            if (found)
                break;
        }
        remaining_hay--;
    }
    return found;
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

/**
 *  @internal
 *
 *  <!--       replace_opt_field()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *msg        message
 *  @param[in]    *name        constchar
 *  @param[in]    *value        constchar
 *  @param[in]    clobber        bool
 *
 */
void replace_opt_field(message *msg,
                       const char *name, 
                       const char *value,
                       bool clobber)
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
            if (clobber) {
                free(pair->value);
                pair->value = strdup(value);
            }
        }
        else {
            add_opt_field(msg, name, value);
        }
    }
}

    // This only decodes the payload - there is no update_identity/myself shenanigans going on here
    // (important for _decrypt_message - if it changes, this MUST be reflected in username caching
    // by the caller)
void decorate_message(
    PEP_SESSION session,
    message *msg,
    PEP_rating rating,
    stringlist_t *keylist,
    bool add_version,
    bool clobber
    )
{
    assert(msg);

    if (add_version)
        replace_opt_field(msg, "X-pEp-Version", PEP_VERSION, clobber);

    if (rating != PEP_rating_undefined) {
        replace_opt_field(msg, "X-EncStatus", rating_to_string(rating), clobber);
        set_receiverRating(session, msg, rating);
    }

    if (keylist) {
        char *_keylist = keylist_to_string(keylist);
        replace_opt_field(msg, "X-KeyList", _keylist, clobber);
        free(_keylist);
    }
}

/**
 *  @internal
 *
 *  <!--       _get_resource_ptr_noown()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *uri        char
 *  
 *  @retval     bool
 */
static char* _get_resource_ptr_noown(char* uri) {
    char* uri_delim = strstr(uri, "://");
    if (!uri_delim)
        return uri;
    else
        return uri + 3;
}

/**
 *  @internal
 *
 *  <!--       string_equality()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *s1        const char
 *  @param[in]    *s2        const char
 *  
 *  @retval     bool
 */
static bool string_equality(const char *s1, const char *s2)
{
    if (s1 == NULL || s2 == NULL)
        return false;

    assert(s1 && s2);

    return strcmp(s1, s2) == 0;
}

/**
 *  @internal
 *
 *  <!--       is_mime_type()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *bl        constbloblist_t
 *  @param[in]    *mt        constchar
 *
 *  @retval     bool
 */
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
/**
 *  @internal
 *
 *  <!--       is_fileending()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *bl        constbloblist_t
 *  @param[in]    *fe        constchar
 *  
 *  @retval
 */
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

/**
 *  @internal
 *
 *  <!--       encapsulate_message_wrap_info()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *msg_wrap_info        constchar
 *  @param[in]    *longmsg        constchar
 *
 */
char * encapsulate_message_wrap_info(const char *msg_wrap_info, const char *longmsg)
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

/**
 *  @internal
 *
 *  <!--       combine_short_and_long()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *shortmsg        constchar
 *  @param[in]    *longmsg        constchar
 *
 */
static char * combine_short_and_long(const char *shortmsg, const char *longmsg)
{
    assert(shortmsg);
    
    unsigned char pEpstr[] = PEP_SUBJ_STRING;

    // assert(strcmp(shortmsg, "pEp") != 0 && _unsigned_signed_strcmp(pEpstr, shortmsg, PEP_SUBJ_BYTELEN) != 0); 
    // in case encrypt_message() is called twice with a different passphrase this was done already
    
    if (strcmp(shortmsg, "pEp") == 0 || _unsigned_signed_strcmp(pEpstr, shortmsg, PEP_SUBJ_BYTELEN) == 0) {
        char *ptext = strdup(longmsg);
        assert(ptext);
        if (!ptext)
            return NULL;
        return ptext;
    }

    if (!shortmsg || strcmp(shortmsg, "pEp") == 0 || 
                     _unsigned_signed_strcmp(pEpstr, shortmsg, PEP_SUBJ_BYTELEN) == 0) {
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

/**
 *  @internal
 *
 *  <!--       replace_subject()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *msg        message
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 */
static PEP_STATUS replace_subject(message* msg) {
    unsigned char pEpstr[] = PEP_SUBJ_STRING;
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
    msg->shortmsg = strdup((char*)pEpstr);
#endif    
    
    if (!msg->shortmsg)
        return PEP_OUT_OF_MEMORY;
    
    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       get_bitmask()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    num_bits        int
 *
 */
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

/**
 *  @internal
 *
 *  <!--       get_base_36_rep()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    value        unsigned long long
 *  @param[in]    num_sig_bits        int
 *
 */
static char* get_base_36_rep(unsigned long long value, int num_sig_bits) {
        
    int bufsize = ((int) ceil((double) num_sig_bits / _pEp_log2_36)) + 1;
    
    // based on
    // https://en.wikipedia.org/wiki/Base36#C_implementation
    // ok, we supposedly have a 64-bit kinda sorta random blob
    const char base_36_symbols[37] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    char* retbuf = calloc(bufsize, 1); 
    assert(retbuf);
    if (!retbuf)
        return NULL;

    int i = bufsize - 1; // (end index)

    while (i > 0) {
        retbuf[--i] = base_36_symbols[value % 36];
        value /= 36;
    }

    return retbuf;
}


/**
 *  @internal
 *
 *  <!--       message_id_prand_part()       -->
 *
 *  @brief            TODO
 *
 *
 */
static char* message_id_prand_part(void) {
    // RAND modulus
    int num_bits = _pEp_rand_max_bits;

    if (num_bits < 0)
        return NULL;
        
    const int DESIRED_BITS = 64;

    num_bits = MIN(num_bits, DESIRED_BITS);
    
    int i;
    
    // at least 64 bits
    unsigned long long bitmask = get_bitmask(num_bits);
    
    unsigned long long output_value = 0;
    
    i = DESIRED_BITS;
    
    while (i > 0) {
        int bitshift = 0;
        int randval = rand();
        unsigned long long temp_val = randval & bitmask;

        output_value |= temp_val;

        i -= MIN(num_bits, i); 
        
        bitshift = MIN(num_bits, i);
        output_value <<= bitshift;        
        bitmask = get_bitmask(bitshift);
    }

    return get_base_36_rep(output_value, DESIRED_BITS);
}

/**
 *  @internal
 *
 *  <!--       generate_message_id()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *msg        message
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 */
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
    
    time_prefix = get_base_36_rep(curr_time, (int) ceil(log2((double) curr_time)));

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
/**
 *  @internal
 *
 *  <!--       get_data_from_encapsulated_line()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *plaintext        constchar
 *  @param[in]    *key        constchar
 *  @param[in]    keylen        constsize_t
 *  @param[in]    **data        char
 *  @param[in]    **modified_msg        char
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
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


/**
 *  @internal
 *
 *  <!--       separate_short_and_long()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *src        constchar
 *  @param[in]    **shortmsg        char
 *  @param[in]    **msg_wrap_info        char
 *  @param[in]    **longmsg        char
 *
 */
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

/**
 *  @internal
 *
 *  <!--       copy_fields()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *dst        message
 *  @param[in]    *src        constmessage
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 */
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
/**
 *  @internal
 *
 *  <!--       extract_minimal_envelope()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *src        constmessage
 *  @param[in]    direct        PEP_msg_direction
 *
 */
static message* extract_minimal_envelope(const message* src,
                                         PEP_msg_direction direct) {
                                                 
    message* envelope = new_message(direct);
    if (!envelope)
        return NULL;
        
    envelope->shortmsg = _pEp_subj_copy();
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

/**
 *  @internal
 *
 *  <!--       clone_to_empty_message()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *src        constmessage
 *
 */
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

/**
 *  @internal
 *
 *  <!--       wrap_message_as_attachment()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *envelope        message
 *  @param[in]    *attachment        message
 *  @param[in]    wrap_type        message_wrap_type
 *  @param[in]    keep_orig_subject        bool
 *  @param[in]    *extra_keys        stringlist_t
 *  @param[in]    max_major        unsignedint
 *  @param[in]    max_minor        unsignedint
 *
 */
static PEP_STATUS wrap_message_as_attachment(message* envelope,
    message* attachment, message** new_message, message_wrap_type wrap_type, 
    bool keep_orig_subject, stringlist_t* extra_keys,
    unsigned int max_major, unsigned int max_minor) {
    
    *new_message = NULL;

    if (!attachment)
        return PEP_ILLEGAL_VALUE;
    
    message* _envelope = envelope;

    PEP_STATUS status = PEP_STATUS_OK;

    replace_opt_field(attachment, "X-pEp-Version", PEP_VERSION, true);

    if (extra_keys) {
        char* ex_keystr = stringlist_to_string(extra_keys);
        if (ex_keystr)
            add_opt_field(attachment, "X-pEp-extra-keys", ex_keystr);
    }

    if (!_envelope && (wrap_type != PEP_message_transport)) {
        _envelope = extract_minimal_envelope(attachment, PEP_dir_outgoing);
        status = generate_message_id(_envelope);
        
        if (status != PEP_STATUS_OK)
            goto pEp_error;
        
        const char* inner_type_string = "";
        switch (wrap_type) {
            case PEP_message_key_reset:
                inner_type_string = "KEY_RESET";
                break;
            default:
                inner_type_string = "INNER";
        }
        if (max_major < 2 || (max_major == 2 && max_minor == 0)) {
            attachment->longmsg = encapsulate_message_wrap_info(inner_type_string, attachment->longmsg);        
            _envelope->longmsg = encapsulate_message_wrap_info("OUTER", _envelope->longmsg);
        }
        else {
            _envelope->longmsg = strdup(
                "This message was encrypted with p≡p (https://pep.software). If you are seeing this message,\n" 
                "your client does not support raising message attachments. Please click on the message attachment\n"
                "to view it, or better yet, consider using p≡p!\n"
            );
        }

        if (max_major <= 0 || max_minor < 0) {
            max_major = 1;
            max_minor = 0;
        }

        // // I hate this. Wish it were extensible.
        // // 2 to cover logs, one for period, one for null termination = + 4
        // int buf_size = floor(log10(max_major)) + (max_minor == 0 ? 0 : floor(log10(max_minor))) + 4;
//        char* msg_ver = (char*)calloc(buf_size, 1);
        int buf_size = 100;
        char msg_ver[100];
        // if (!msg_ver)
        //     goto enomem;
        snprintf(msg_ver, buf_size, "%d%s%d", max_major, ".", max_minor);

        replace_opt_field(attachment, X_PEP_MSG_VER_KEY, msg_ver, true);
//        free(msg_ver);
        
        
        // 2.1, to replace the above
        add_opt_field(attachment, X_PEP_MSG_WRAP_KEY, inner_type_string); 
    }
    else if (_envelope) {
        // 2.1 - how do we peel this particular union when we get there?
        _envelope->longmsg = encapsulate_message_wrap_info("TRANSPORT", _envelope->longmsg);
    }
    else { 
        status = PEP_UNKNOWN_ERROR;
        goto pEp_error;
    }   

    if (!attachment->id || attachment->id[0] == '\0') {
        free(attachment->id);
        if (!_envelope->id) {
            status = generate_message_id(_envelope);
        
            if (status != PEP_STATUS_OK)
                goto pEp_error;
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
    
    /* add sender fpr to inner message */
    add_opt_field(attachment, 
                  "X-pEp-Sender-FPR", 
                  (attachment->_sender_fpr ? attachment->_sender_fpr : "")
              );
            
    /* Turn message into a MIME-blob */
    status = mime_encode_message(attachment, false, &message_text, false);
        
    if (status != PEP_STATUS_OK)
        goto pEp_error;
    
    size_t message_len = strlen(message_text);
    
    bloblist_t* message_blob = new_bloblist(message_text, message_len,
                                            "message/rfc822", NULL);
    
    if (!message_blob)
        goto enomem;

    _envelope->attachments = message_blob;
    if (keep_orig_subject && attachment->shortmsg)
        _envelope->shortmsg = strdup(attachment->shortmsg);
    *new_message = _envelope;
    return status;
    
enomem:
    status = PEP_OUT_OF_MEMORY;  

pEp_error:
    if (!envelope) {
        free_message(_envelope);
    }
    *new_message = NULL;
    return status;
}

/**
 *  @internal
 *
 *  <!--       encrypt_PGP_inline()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        PEP_SESSION
 *  @param[in]    *src        constmessage
 *  @param[in]    *keys        stringlist_t
 *  @param[in]    *dst        message
 *  @param[in]    flags        PEP_encrypt_flags_t
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
static PEP_STATUS encrypt_PGP_inline(
        PEP_SESSION session,
        const message *src,
        stringlist_t *keys,
        message *dst,
        PEP_encrypt_flags_t flags
    )
{
    char *ctext = NULL;
    size_t csize = 0;

    PEP_STATUS status = encrypt_and_sign(session, keys, src->longmsg,
            strlen(src->longmsg), &ctext, &csize);
    if (status)
        return status;

    dst->enc_format = src->enc_format;

    // shortmsg is copied
    if (src->shortmsg) {
        dst->shortmsg = strdup(src->shortmsg);
        assert(dst->shortmsg);
        if (!dst->shortmsg)
            return PEP_OUT_OF_MEMORY;
    }

    // id stays the same
    if (src->id) {
        dst->id = strdup(src->id);
        assert(dst->id);
        if (!dst->id)
            return PEP_OUT_OF_MEMORY;
    }

    char *_ctext = realloc(ctext, csize + 1);
    assert(_ctext);
    if (!_ctext)
        return PEP_OUT_OF_MEMORY;
    _ctext[csize] = 0;

    dst->longmsg = _ctext;

    dst->attachments = new_bloblist(NULL, 0, NULL, NULL);
    if (!dst->attachments)
        return PEP_OUT_OF_MEMORY;

    bloblist_t *ad = dst->attachments;

    if (!EMPTYSTR(src->longmsg_formatted)) {
        status = encrypt_and_sign(session, keys, src->longmsg_formatted,
                strlen(src->longmsg_formatted), &ctext, &csize);
        if (status)
            return status;

        char *_ctext = realloc(ctext, csize + 1);
        assert(_ctext);
        if (!_ctext)
            return PEP_OUT_OF_MEMORY;
        _ctext[csize] = 0;

        ad = bloblist_add(ad, _ctext, csize + 1, "text/html", NULL);
        if (!ad)
            return PEP_OUT_OF_MEMORY;

        ad->disposition = PEP_CONTENT_DISP_INLINE;
    }

    if (src->attachments && src->attachments->value) {
        bloblist_t *as;
        for (as = src->attachments; as && as->value; as = as->next) {
            char *value = NULL;
            size_t size = 0;
            if (src->enc_format == PEP_enc_inline_EA) {
                status = encode_internal(as->value, as->size, as->mime_type,
                        &value, &size);
                if (status)
                    return status;
                if (!value) {
                    value = as->value;
                    size = as->size;
                }
            }
            else {
                value = as->value;
                size = as->size;
            }
            status = encrypt_and_sign(session, keys, value, size, &ctext,
                    &csize);
            if (value != as->value)
                free(value);
            if (status)
                return status;

            char *_ctext = realloc(ctext, csize + 1);
            assert(_ctext);
            if (!_ctext)
                return PEP_OUT_OF_MEMORY;
            _ctext[csize] = 0;

            size_t len = strlen(as->filename);
            char *filename = malloc(len + 5);
            assert(filename);
            if (!filename)
                return PEP_OUT_OF_MEMORY;

            memcpy(filename, as->filename, len);
            memcpy(filename + len, ".pgp", 5);

            ad = bloblist_add(ad, _ctext, csize + 1, "application/octet-stream", filename);
            free(filename);
            filename = NULL;
            if (!ad)
                return PEP_OUT_OF_MEMORY;

            ad->disposition = as->disposition;
        }
    }

    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       encrypt_PGP_MIME()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        PEP_SESSION
 *  @param[in]    *src        constmessage
 *  @param[in]    *keys        stringlist_t
 *  @param[in]    *dst        message
 *  @param[in]    flags        PEP_encrypt_flags_t
 *  @param[in]    wrap_type        message_wrap_type
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
static PEP_STATUS encrypt_PGP_MIME(
    PEP_SESSION session,
    const message *src,
    stringlist_t *keys,
    message *dst,
    PEP_encrypt_flags_t flags,
    message_wrap_type wrap_type
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
    
    bool wrapped = (wrap_type != PEP_message_unwrapped);
    status = mime_encode_message(_src, true, &mimetext, wrapped);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    if (free_ptext){
        free(ptext);
        free_ptext=0;
    }
    free(_src);
    _src = NULL;
    assert(mimetext);
    if (mimetext == NULL)
        goto pEp_error;

    if (flags & PEP_encrypt_flag_force_unsigned)
        status = encrypt_only(session, keys, mimetext, strlen(mimetext),
            &ctext, &csize);
    else
        status = encrypt_and_sign(session, keys, mimetext, strlen(mimetext),
            &ctext, &csize);
    free(mimetext);
    if (ctext == NULL || status)
        goto pEp_error;

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

pEp_error:
    if (free_ptext)
        free(ptext);
    free(_src);
    free(ctext);
    return status;
}

/*
static bool _has_PGP_MIME_format(message* msg) {
    if (!msg || !msg->attachments || !msg->attachments->next)
        return false;
    if (msg->attachments->next->next)
        return false;
    if (!msg->attachments->mime_type)
        return false;        
    if (strcmp(msg->attachments->mime_type, "application/pgp-encrypted") != 0)    
        return false;
    if (!msg->attachments->next->mime_type || 
        strcmp(msg->attachments->next->mime_type, "application/octet-stream") != 0)        
        return false;
    return true;    
}
*/

/**
 *  @internal
 *
 *  <!--       is_encrypted_attachment()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *blob        constbloblist_t
 *
 *  @retval     bool
 */
static bool is_encrypted_attachment(const bloblist_t *blob)
{
    assert(blob);

    if (blob == NULL || blob->filename == NULL || is_cid_uri(blob->filename))
        return false;

    char *ext = strrchr(blob->filename, '.');
    if (ext == NULL)
        return false;

    if (strcmp(blob->mime_type, "application/octet-stream") == 0) {
        if (strcmp(ext, ".pgp") == 0 || strcmp(ext, ".gpg") == 0)
            return true;
    }
    if (strcmp(ext, ".asc") == 0 && blob->size > 0) {            
        const char* pubk_needle = "BEGIN PGP PUBLIC KEY";
        size_t pubk_needle_size = strlen(pubk_needle);
        const char* privk_needle = "BEGIN PGP PRIVATE KEY";
        size_t privk_needle_size = strlen(privk_needle);

        if (!(_memnmemn(pubk_needle, pubk_needle_size, blob->value, blob->size)) &&
            !(_memnmemn(privk_needle, privk_needle_size, blob->value, blob->size)))
            return true;
    }

    return false;
}

/**
 *  @internal
 *
 *  <!--       is_encrypted_html_attachment()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *blob        constbloblist_t
 *
 *  @retval     bool
 */
static bool is_encrypted_html_attachment(const bloblist_t *blob)
{
    assert(blob);
    assert(blob->filename);
    if (blob == NULL || blob->filename == NULL || is_cid_uri(blob->filename))
        return false;

    const char* bare_filename_ptr = _get_resource_ptr_noown(blob->filename);
    bare_filename_ptr += strlen(bare_filename_ptr) - 15;
    if (strncmp(bare_filename_ptr, "PGPexch.htm.", 12) == 0) {
        if (strcmp(bare_filename_ptr + 11, ".pgp") == 0 ||
            strcmp(bare_filename_ptr + 11, ".asc") == 0)
            return true;
    }

    return false;
}

/**
 *  @internal
 *
 *  <!--       without_double_ending()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *filename        constchar
 *
 */
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

/**
 *  @internal
 *
 *  <!--       key_rating()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        PEP_SESSION
 *  @param[in]    *fpr        constchar
 *
 */
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
    return rating_from_comm_type(resulting_comm_type);
}

/**
 *  @internal
 *
 *  <!--       worst_rating()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    rating1        PEP_rating
 *  @param[in]    rating2        PEP_rating
 *
 */
static PEP_rating worst_rating(PEP_rating rating1, PEP_rating rating2) {
    return ((rating1 < rating2) ? rating1 : rating2);
}

/**
 *  @internal
 *
 *  <!--       keylist_rating()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        PEP_SESSION
 *  @param[in]    *keylist        stringlist_t
 *  @param[in]    *sender_fpr        char
 *  @param[in]    sender_rating        PEP_rating
 *
 */
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
            
        rating = worst_rating(rating, _rating_);
    }

    return rating;
}

// KB: Fixme - the first statement below is probably unnecessary now.
// Internal function WARNING:
// Should be called on ident that might have its FPR set from retrieval!
// (or on one without an fpr)
// We do not want myself() setting the fpr here.
//
// Cannot return passphrase statuses. No keygen or renewal allowed here.
/**
 *  @internal
 *
 *  <!--       _get_comm_type()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        PEP_SESSION
 *  @param[in]    max_comm_type        PEP_comm_type
 *  @param[in]    *ident        pEp_identity
 *
 */
static PEP_comm_type _get_comm_type(
    PEP_SESSION session,
    PEP_comm_type max_comm_type,
    pEp_identity *ident
    )
{
    if (!ident)
        return PEP_ILLEGAL_VALUE;
            
    PEP_STATUS status = PEP_STATUS_OK;
            
    if (max_comm_type == PEP_ct_compromised)
        return PEP_ct_compromised;

    if (max_comm_type == PEP_ct_mistrusted)
        return PEP_ct_mistrusted;

    if (!is_me(session, ident)) {
        status = update_identity(session, ident);
    }
    else {
        status = _myself(session, ident, false, false, false, true);
    }

    if (status == PEP_STATUS_OK) {
        if (ident->comm_type == PEP_ct_compromised)
            return PEP_ct_compromised;
        else if (ident->comm_type == PEP_ct_mistrusted)
            return PEP_ct_mistrusted;
        else
            return MIN(max_comm_type, ident->comm_type);
    }
    else {
        return PEP_ct_unknown;
    }                    
}

// static void free_bl_entry(bloblist_t *bl)
// {
//     if (bl) {
//         free(bl->value);
//         free(bl->mime_type);
//         free(bl->filename);
//         free(bl);
//     }
// }

/**
 *  @internal
 *
 *  <!--       is_key()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *bl        constbloblist_t
 *
 *  @retval     bool
 */
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

// static void remove_attached_keys(message *msg)
// {
//     if (msg) {
//         bloblist_t *last = NULL;
//         for (bloblist_t *bl = msg->attachments; bl && bl->value; ) {
//             bloblist_t *next = bl->next;
// 
//             if (is_key(bl)) {
//                 if (last) {
//                     last->next = next;
//                 }
//                 else {
//                     msg->attachments = next;
//                 }
//                 free_bl_entry(bl);
//             }
//             else {
//                 last = bl;
//             }
//             bl = next;
//         }
//     }
// }

/**
 *  @internal
 *
 *  <!--       compare_first_n_bytes()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *first        constchar
 *  @param[in]    *second        constchar
 *  @param[in]    n        size_t
 *
 */
static bool compare_first_n_bytes(const char* first, const char* second, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        char num1 = *first;
        char num2 = *second;

        if (num1 != num2)
            return false;
                    
        if (num1 == '\0') {
            if (num2 == '\0')
                return true;
        }   
        first++;
        second++;                     
    }
    return true;
}

// is_pEp_msg isn't available on the message yet usually when we get it here,
// so we need it as a parameter
/**
 *  @internal
 *
 *  <!--       import_attached_keys()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        session handle    
 *  @param[in]    *msg        message
 *  @param[in]    **private_idents        identity_list
 *  @param[in]    **imported_key_list        stringlist_t
 *  @param[in]    *changed_keys        uint64_t
 *
 *  @retval     bool
 */
bool import_attached_keys(
        PEP_SESSION session,
        message *msg,
        bool is_pEp_msg,
        identity_list **private_idents, 
        stringlist_t** imported_key_list,
        uint64_t* changed_keys,
        char** pEp_sender_key
    )
{
    assert(session);
    assert(msg);

    if (session == NULL || msg == NULL)
        return false;

    char* _sender_key_retval = NULL;
    stringlist_t* _keylist = imported_key_list ? *imported_key_list : NULL;
    
    bool remove = false;

    int i = 0;
    
    bloblist_t* prev = NULL;
    
    bool do_not_advance = false;
    const char* pubkey_header = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    const char* privkey_header = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
    // Hate my magic numbers at your peril, but I don't want a strlen each time
    const size_t PUBKEY_HSIZE = 36;
    const size_t PRIVKEY_HSIZE = 37;

    bool pEp_sender_key_found = false;
    stringlist_t* last_fpr_ptr = _keylist ? stringlist_get_tail(_keylist) : NULL;

    for (bloblist_t *bl = msg->attachments; i < MAX_KEYS_TO_IMPORT && bl && bl->value;
         i++)
    {
        do_not_advance = false;
        if (bl && bl->value && bl->size && bl->size < MAX_KEY_SIZE
                && is_key(bl))
        {
            char* blob_value = bl->value;
            size_t blob_size = bl->size;
            bool free_blobval = false;
            bool single_import = false;
            
            if (is_encrypted_attachment(bl)) {
                    
                char* bl_ptext = NULL;
                size_t bl_psize = 0;
                stringlist_t* bl_keylist = NULL;
                PEP_STATUS _status = decrypt_and_verify(session, 
                                                        blob_value, blob_size,
                                                        NULL, 0,
                                                        &bl_ptext, &bl_psize, 
                                                        &bl_keylist,
                                                        NULL);
                free_stringlist(bl_keylist); // we don't care about key encryption as long as we decrypt
                if (_status == PEP_DECRYPTED || _status == PEP_DECRYPTED_AND_VERIFIED) {
                    free_blobval = true;
                    blob_value = bl_ptext;
                    blob_size = bl_psize;
                }
                else {
                    // This is an encrypted attachment we can do nothing with.
                    // We shouldn't delete it or import it, because we can't
                    // do the latter.
                    free(bl_ptext);
                    prev = bl;
                    bl = bl->next;
                    continue;
                }
            }
            identity_list *local_private_idents = NULL;
            PEP_STATUS import_status = import_key_with_fpr_return(
                                                  session, blob_value, blob_size, 
                                                  &local_private_idents,
                                                  &_keylist,
                                                  changed_keys);
                                                  
            if (_keylist) {
                stringlist_t* added_keys = last_fpr_ptr ? last_fpr_ptr->next : _keylist;
                if (stringlist_length(added_keys) == 1)
                    single_import = true;
                last_fpr_ptr = stringlist_get_tail(last_fpr_ptr ? last_fpr_ptr : _keylist);
            }
            
            //bloblist_t* to_delete = NULL;
            const char* uri = NULL;
            
            switch (import_status) {
                case PEP_NO_KEY_IMPORTED:
                    break;
                case PEP_KEY_IMPORT_STATUS_UNKNOWN:
                    // We'll delete armoured stuff, at least
                    if (blob_size <= PUBKEY_HSIZE)
                        break;
                    if ((!compare_first_n_bytes(pubkey_header, (const char*)blob_value, PUBKEY_HSIZE)) &&
                       (!compare_first_n_bytes(privkey_header, (const char*)blob_value, PRIVKEY_HSIZE)))
                        break;
                    // else fall through and delete    
                case PEP_KEY_IMPORTED:
                case PEP_STATUS_OK:
                    // N.B. Removed, at least, until trustsync is in
                    //
                    // to_delete = bl;
                    // if (prev)
                    //     prev->next = bl->next;
                    // else
                    //     msg->attachments = bl->next;
                    // bl = bl->next;
                    // to_delete->next = NULL;
                    // free_bloblist(to_delete);
                    // do_not_advance = true;
                    uri = bl->filename;
                    if (pEp_sender_key && is_pEp_msg && !EMPTYSTR(uri)) {
                        if (strcmp(uri, "file://sender_key.asc") == 0) {
                            if (!pEp_sender_key_found) {   
                                pEp_sender_key_found = true;
                                if (single_import && last_fpr_ptr && !EMPTYSTR(last_fpr_ptr->value))
                                    _sender_key_retval = strdup(last_fpr_ptr->value);
                            }    
                            else {
                                // BAD. Someone messed up. ONE sender_key.asc. 
                                free(_sender_key_retval);
                                _sender_key_retval = NULL;
                            }    
                        }    
                    }
                        
                    remove = true;
                    break;
                default:  
                    // bad stuff, but ok.
                    break;
            }
            if (private_idents && *private_idents == NULL && local_private_idents != NULL)
                *private_idents = local_private_idents;
            else
                free_identity_list(local_private_idents);
            if (free_blobval)
                free(blob_value);
        }
        if (!do_not_advance) {
            prev = bl;
            bl = bl->next;
        }
    }
    if (pEp_sender_key)
        *pEp_sender_key = _sender_key_retval;
        
    if (imported_key_list) {
        if (!(*imported_key_list))
            *imported_key_list = _keylist;
    }        
    else 
        free_stringlist(_keylist);
        
    return remove;
}


/**
 *  @internal
 *
 *  <!--       _attach_key()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        PEP_SESSION
 *  @param[in]    *fpr        constchar
 *  @param[in]    *msg        message
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_KEY_NOT_FOUND   key not found
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
PEP_STATUS _attach_key(PEP_SESSION session, const char* fpr, message *msg, const char* filename)
{
    char *keydata = NULL;
    size_t size = 0;

    PEP_STATUS status = export_key(session, fpr, &keydata, &size);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        return status;
    assert(size);

    if (EMPTYSTR(filename))
        filename = "file://pEpkey.asc";

    bloblist_t *bl = bloblist_add(msg->attachments, keydata, size, "application/pgp-keys",
                      filename);

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

    if(_attach_key(session, msg->from->fpr, msg, "file://sender_key.asc") != PEP_STATUS_OK)
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
            _attach_key(session, revoked_fpr, msg, "file://revoked_key.asc");
        }
    }
    free(revoked_fpr);
}

PEP_cryptotech determine_encryption_format(message *msg)
{
    assert(msg);

    if (is_PGP_message_text(msg->longmsg)) {
        if (msg->enc_format != PEP_enc_inline_EA)
            msg->enc_format = PEP_enc_inline;
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

/**
 *  @internal
 *
 *  <!--       _cleanup_src()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *src        message
 *  @param[in]    remove_attached_key        bool
 *
 */
static void _cleanup_src(message* src, bool remove_attached_key) {
    assert(src);
    
    if (!src)
        return;
        
    char* longmsg = NULL;
    char* shortmsg = NULL;
    char* msg_wrap_info = NULL;
    if (src->longmsg)
        separate_short_and_long(src->longmsg, &shortmsg, &msg_wrap_info,
                                &longmsg);
    if (longmsg) {                    
        free(src->longmsg);
        free(shortmsg);
        free(msg_wrap_info);
        src->longmsg = longmsg;
    }
    if (remove_attached_key) {
        // End of the attachment list
        if (src->attachments) {
            bloblist_t* tmp = src->attachments;
            while (tmp->next && tmp->next->next) {
                tmp = tmp->next;
            }
            free_bloblist(tmp->next);
            tmp->next = NULL;
        }    
    }                   
}

/**
 *  @internal
 *
 *  <!--       id_list_set_enc_format()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *id_list        identity_list
 *  @param[in]    enc_format        PEP_enc_format
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE        illegal parameter value
 *  @retval     PEP_CANNOT_SET_IDENTITY
 */
static PEP_STATUS id_list_set_enc_format(PEP_SESSION session, identity_list* id_list, PEP_enc_format enc_format) {
    PEP_STATUS status = PEP_STATUS_OK;
    identity_list* id_list_curr = id_list;
    for ( ; id_list_curr && id_list_curr->ident && status == PEP_STATUS_OK; id_list_curr = id_list_curr->next) {
        status = set_ident_enc_format(session, id_list_curr->ident, enc_format);
    }
    return status;
}

// N.B.
// depends on update_identity and friends having already been called on list
/**
 *  @internal
 *
 *  <!--       update_encryption_format()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *id_list        identity_list
 *  @param[in]    *enc_format        PEP_enc_format
 *
 */
static void update_encryption_format(identity_list* id_list, PEP_enc_format* enc_format) {
    identity_list* id_list_curr;
    for (id_list_curr = id_list; id_list_curr && id_list_curr->ident; id_list_curr = id_list_curr->next) {
        PEP_enc_format format = id_list_curr->ident->enc_format;
        if (format != PEP_enc_none) {
            *enc_format = format;
            break;
        }
    }
}

/**
 *  @internal
 *
 *  <!--       failed_test()       -->
 *
 *  @brief      returns true if status indicates failure        
 *
 *  @param[in]    status        PEP_STATUS
 *
 *  @retval     bool
 */
static bool failed_test(PEP_STATUS status)
{
    if (status == PEP_OUT_OF_MEMORY ||
            status == PEP_PASSPHRASE_REQUIRED ||
            status == PEP_WRONG_PASSPHRASE  ||
            status == PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED)
        return true;

    return false;
}

// CANNOT return PASSPHRASE errors, as no gen or renew allowed below
/**
 *  @internal
 *
 *  <!--       _update_state_for_ident_list()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        PEP_SESSION
 *  @param[in]    *from_ident        pEp_identity
 *  @param[in]    *ident_list        identity_list
 *  @param[in]    **keylist        stringlist_t
 *  @param[in]    *max_comm_type        PEP_comm_type
 *  @param[in]    *max_version_major        unsignedint
 *  @param[in]    *max_version_minor        unsignedint
 *  @param[in]    *has_pEp_user        bool
 *  @param[in]    *dest_keys_found        bool
 *  @param[in]    suppress_update_for_bcc        bool
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_UNKNOWN_DB_ERROR;
 *  @retval any other value on error
 */
static PEP_STATUS _update_state_for_ident_list(
        PEP_SESSION session,
        pEp_identity* from_ident,
        identity_list* ident_list,
        stringlist_t** keylist,
        PEP_comm_type* max_comm_type,
        unsigned int* max_version_major,
        unsigned int* max_version_minor,
        bool* has_pEp_user,
        bool* dest_keys_found,
        bool suppress_update_for_bcc
    )
{
    if (!ident_list || !max_version_major || !max_version_minor
                    || !has_pEp_user || !dest_keys_found
                    || !keylist)
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = PEP_STATUS_OK;
    
    identity_list* _il = ident_list;
    
    for ( ; _il && _il->ident; _il = _il->next) {

        PEP_STATUS status = PEP_STATUS_OK;
        
        if (!is_me(session, _il->ident)) {
            status = update_identity(session, _il->ident);
            
            if (status == PEP_CANNOT_FIND_IDENTITY) {
                _il->ident->comm_type = PEP_ct_key_not_found;
                status = PEP_STATUS_OK;
            }
            // 0 unless set, so safe.
            
            if (!suppress_update_for_bcc) {
                set_min_version( _il->ident->major_ver, _il->ident->minor_ver, 
                                 *max_version_major, *max_version_minor,
                                 max_version_major, max_version_minor);
            }
            
            if (!(*has_pEp_user) && !EMPTYSTR(_il->ident->user_id))
                is_pEp_user(session, _il->ident, has_pEp_user);
            
            if (!suppress_update_for_bcc && from_ident) {
                status = bind_own_ident_with_contact_ident(session, from_ident, _il->ident);
                if (status != PEP_STATUS_OK) {
                    status = PEP_UNKNOWN_DB_ERROR;
                    goto pEp_done;
                }
            }        
        }
        else // myself, but don't gen or renew
            status = _myself(session, _il->ident, false, false, false, true);
        
        if (status != PEP_STATUS_OK)
            goto pEp_done;

        if (!EMPTYSTR(_il->ident->fpr)) {
            *keylist = stringlist_add(*keylist, _il->ident->fpr);
            if (*keylist == NULL) {
                status = PEP_OUT_OF_MEMORY;
                goto pEp_done;
            }
            *max_comm_type = _get_comm_type(session, *max_comm_type,
                                            _il->ident);
        }
        else {
            *dest_keys_found = false;
// ?           status = PEP_KEY_NOT_FOUND;
        }
    }

pEp_done:
    return status;
}

static bool message_is_from_Sync(const message *src)
{
    // from must be set
    if (!src->from || EMPTYSTR(src->from->address))
        return false;

    // first to must be set
    if (!src->to || !src->to->ident || EMPTYSTR(src->to->ident->address))
        return false;

    // second to must not be set
    if (src->to->next)
        return false;

    // cc must not be set
    if (src->cc && src->cc->ident)
        return false;

    // bcc must not be set
    if (src->bcc && src->bcc->ident)
        return false;

    // from and to must use the same address
    if (strcmp(src->from->address, src->to->ident->address) != 0)
        return false;

    // this is a message from Sync
    return true;
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

    bool added_key_to_real_src = false;
    
    assert(session);
    assert(src && src->from);
    assert(dst);

    if (!(session && src && src->from && dst))
        return PEP_ILLEGAL_VALUE;

    if (src->dir == PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;

    determine_encryption_format(src);
    // TODO: change this for multi-encryption in message format 2.0
    if (src->enc_format != PEP_enc_none)
        return PEP_ILLEGAL_VALUE;

    bool force_v_1 = flags & PEP_encrypt_flag_force_version_1;
    
    *dst = NULL;

    if (!src->from->user_id || src->from->user_id[0] == '\0') {
        char* own_id = NULL;
        status = get_default_own_userid(session, &own_id);
        if (own_id) {
            free(src->from->user_id);
            src->from->user_id = own_id; // ownership transfer
        }
    }
    
    status = myself(session, src->from);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    // This is only local, the caller will keep the keylist, but we don't want to
    // allow extra keys for non-org (e.g. business) accounts, so we set it to NULL
    // locally so as not to use it if it's a non-org account (cheaper than checks
    // everywhere)
    if (!(src->from->flags & PEP_idf_org_ident)) {
        // if this is not from pEp Sync
        if (!message_is_from_Sync(src))
            extra = NULL;
    }

    // is a passphrase needed?
    status = probe_encrypt(session, src->from->fpr);
    if (failed_test(status))
        return status;

    char* send_fpr = strdup(src->from->fpr ? src->from->fpr : "");
    src->_sender_fpr = send_fpr;
    
    keys = new_stringlist(send_fpr);
    if (keys == NULL)
        goto enomem;

    stringlist_t *_k = keys;

    // Will be NULL if this is a private account
    if (extra) {
        _k = stringlist_append(_k, extra);
        if (_k == NULL)
            goto enomem;
    }

    bool dest_keys_found = true;
    bool has_pEp_user = false;
    
    PEP_comm_type max_comm_type = PEP_ct_pEp;
    unsigned int max_version_major = 0;
    unsigned int max_version_minor = 0;
    pEp_version_major_minor(PEP_VERSION, &max_version_major, &max_version_minor);
    
    identity_list * _il = NULL;

    //
    // Update the identities and gather key and version information 
    // for sending 
    //
    if (enc_format != PEP_enc_none && (_il = src->bcc) && _il->ident)
    // BCC limited support:
    {
        //     - App splits mails with BCC in multiple mails.
        //     - Each email is encrypted separately
        if(_il->next || (src->to && src->to->ident) || (src->cc && src->cc->ident))
        {
            // Only one Bcc with no other recipient allowed for now
            return PEP_ILLEGAL_VALUE;
        }

        // If you think this call is a beast, try the cut-and-pasted code 3 x
        PEP_STATUS _status = _update_state_for_ident_list(
                                session, src->from, _il,
                                &_k,
                                &max_comm_type,
                                &max_version_major,
                                &max_version_minor,
                                &has_pEp_user,
                                &dest_keys_found,
                                true);
                                        
        switch (_status) {
            case PEP_PASSPHRASE_REQUIRED:
            case PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED:
            case PEP_WRONG_PASSPHRASE:
                status = _status;
                goto pEp_error;
            case PEP_STATUS_OK:
                break;
            default:
                status = PEP_UNENCRYPTED;
                goto pEp_error;
        }
    }
    else // Non BCC
    {

        // If you think this call is a beast, try the cut-and-pasted code 3 x
        PEP_STATUS _status = PEP_STATUS_OK;
        
        if (src->to) {
            _status = _update_state_for_ident_list(
                            session, src->from, src->to,
                            &_k,
                            &max_comm_type,
                            &max_version_major,
                            &max_version_minor,
                            &has_pEp_user,
                            &dest_keys_found,
                            false
                        );
            switch (_status) {
                case PEP_PASSPHRASE_REQUIRED:
                case PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED:
                case PEP_WRONG_PASSPHRASE:
                    goto pEp_error;
                case PEP_STATUS_OK:
                    break;
                default:
                    status = PEP_UNENCRYPTED;
                    goto pEp_error;
            }                        
        }
        if (src->cc) {
            _status = _update_state_for_ident_list(
                            session, src->from, src->cc,
                            &_k,
                            &max_comm_type,
                            &max_version_major,
                            &max_version_minor,
                            &has_pEp_user,
                            &dest_keys_found,
                            false
                        );
            switch (_status) {
                case PEP_PASSPHRASE_REQUIRED:
                case PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED:
                case PEP_WRONG_PASSPHRASE:
                    goto pEp_error;
                case PEP_STATUS_OK:
                    break;
                default:
                    status = PEP_UNENCRYPTED;
                    goto pEp_error;
            }                        
        }        
    }
    
    if (max_version_major < 2)
        force_v_1 = true;

    if (enc_format == PEP_enc_auto) {
        update_encryption_format(src->to, &enc_format);
        if (enc_format == PEP_enc_auto && src->cc)
            update_encryption_format(src->cc, &enc_format);
        if (enc_format == PEP_enc_auto && src->bcc)
            update_encryption_format(src->bcc, &enc_format);
        if (enc_format == PEP_enc_auto)
            enc_format = PEP_enc_PEP;
    }    
    else if (enc_format != PEP_enc_none) {
        status = id_list_set_enc_format(session, src->to, enc_format);
        status = ((status != PEP_STATUS_OK || !(src->cc)) ? status : id_list_set_enc_format(session, src->cc, enc_format));
        status = ((status != PEP_STATUS_OK || !(src->bcc)) ? status : id_list_set_enc_format(session, src->bcc, enc_format));
        if (status != PEP_STATUS_OK)
            goto pEp_error;
    }
        
    if (enc_format == PEP_enc_none || !dest_keys_found ||
        stringlist_length(keys)  == 0 ||
        rating_from_comm_type(max_comm_type) < PEP_rating_reliable)
    {
        free_stringlist(keys);
        if ((has_pEp_user || !session->passive_mode) && 
            !(flags & PEP_encrypt_flag_force_no_attached_key)) {
            attach_own_key(session, src);
            added_key_to_real_src = true;
        }
        decorate_message(session, src, PEP_rating_undefined, NULL, true, true);
        return PEP_UNENCRYPTED;
    }
    else {
        // First, dedup the keylist
        if (keys && keys->next)
            dedup_stringlist(keys->next);
            
        // FIXME - we need to deal with transport types (via flag)
        message_wrap_type wrap_type = PEP_message_unwrapped;
        if ((enc_format != PEP_enc_inline) && (enc_format != PEP_enc_inline_EA) && (!force_v_1) && ((max_comm_type | PEP_ct_confirmed) == PEP_ct_pEp)) {
            wrap_type = ((flags & PEP_encrypt_flag_key_reset_only) ? PEP_message_key_reset : PEP_message_default);
            status = wrap_message_as_attachment(NULL, src, &_src, wrap_type, false, extra, max_version_major, max_version_minor);
            if (status != PEP_STATUS_OK)
                goto pEp_error;
            else if (!_src) {
                status = PEP_UNKNOWN_ERROR;
                goto pEp_error;
            }
        }
        else {
            // hide subject
            if (enc_format != PEP_enc_inline && enc_format != PEP_enc_inline_EA) {
                // do not replace subject if message format 1.x and unencrypted
                // subject is enabled
                if (!(wrap_type == PEP_message_unwrapped && session->unencrypted_subject)) {
                    status = replace_subject(_src);
                    if (status == PEP_OUT_OF_MEMORY)
                        goto enomem;
                }
            }
            if (!(flags & PEP_encrypt_flag_force_no_attached_key))
                added_key_to_real_src = true;            
        }
        if (!(flags & PEP_encrypt_flag_force_no_attached_key))
            attach_own_key(session, _src);

        msg = clone_to_empty_message(_src);
        if (msg == NULL)
            goto enomem;

        switch (enc_format) {
            case PEP_enc_PGP_MIME:
            case PEP_enc_PEP: // BUG: should be implemented extra
                status = encrypt_PGP_MIME(session, _src, keys, msg, flags, wrap_type);
                break;

            case PEP_enc_inline:
            case PEP_enc_inline_EA:
                _src->enc_format = enc_format;
                status = encrypt_PGP_inline(session, _src, keys, msg, flags);
                break;

            default:
                assert(0);
                status = PEP_ILLEGAL_VALUE;
                goto pEp_error;
        }

        if (status == PEP_OUT_OF_MEMORY)
            goto enomem;

        if (status != PEP_STATUS_OK)
            goto pEp_error;
    }

    free_stringlist(keys);

    if (msg && msg->shortmsg == NULL) {
        msg->shortmsg = strdup("");
        assert(msg->shortmsg);
        if (msg->shortmsg == NULL)
            goto enomem;
    }

    if (msg) {
        decorate_message(session, msg, PEP_rating_undefined, NULL, true, true);
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
    
    // Do similar for extra key list...
    _cleanup_src(src, added_key_to_real_src);
        
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_error:
    free_stringlist(keys);
    free_message(msg);
    if (_src && _src != src)
        free_message(_src);

    _cleanup_src(src, added_key_to_real_src);

    return status;
}

DYNAMIC_API PEP_STATUS encrypt_message_and_add_priv_key(
        PEP_SESSION session,
        message *src,
        message **dst,
        const char* to_fpr,
        PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags
    )
{
    assert(session);
    assert(src);
    assert(dst);
    assert(to_fpr);
        
    if (!session || !src || !dst || !to_fpr)
        return PEP_ILLEGAL_VALUE;
        
    if (enc_format == PEP_enc_none)
        return PEP_ILLEGAL_VALUE;
    
    if (src->cc || src->bcc)
        return PEP_ILLEGAL_VALUE;
        
    if (!src->to || src->to->next)
        return PEP_ILLEGAL_VALUE;
        
    if (!src->from->address || !src->to->ident || !src->to->ident->address)
        return PEP_ILLEGAL_VALUE;
            
    if (strcasecmp(src->from->address, src->to->ident->address) != 0)
        return PEP_ILLEGAL_VALUE;
    
    stringlist_t* keys = NULL;

    char* own_id = NULL;
    char* default_id = NULL;
    
    pEp_identity* own_identity = NULL;
    char* own_private_fpr = NULL;

    char* priv_key_data = NULL;
    
    PEP_STATUS status = get_default_own_userid(session, &own_id);
    
    if (!own_id)
        return PEP_UNKNOWN_ERROR; // Probably a DB error at this point
        
    if (src->from->user_id) {
        if (strcmp(src->from->user_id, own_id) != 0) {
            status = get_userid_alias_default(session, src->from->user_id, &default_id);
            if (status != PEP_STATUS_OK || !default_id || strcmp(default_id, own_id) != 0) {
                status = PEP_ILLEGAL_VALUE;
                goto pEp_free;
            }
        }        
    }
    
    // Ok, we are at least marginally sure the initial stuff is ok.
        
    // Let's get our own, normal identity
    own_identity = identity_dup(src->from);
    status = myself(session, own_identity);

    if (status != PEP_STATUS_OK)
        goto pEp_free;

    // is a passphrase needed?
    status = probe_encrypt(session, own_identity->fpr);
    if (failed_test(status))
        goto pEp_free;

    // Ok, now we know the address is an own address. All good. Then...
    own_private_fpr = own_identity->fpr;
    own_identity->fpr = strdup(to_fpr);
    
    status = get_trust(session, own_identity);
    
    if (status != PEP_STATUS_OK) {
        if (status == PEP_CANNOT_FIND_IDENTITY)
            status = PEP_ILLEGAL_VALUE;
        goto pEp_free;
    }
        
    if ((own_identity->comm_type & PEP_ct_confirmed) != PEP_ct_confirmed) {
        status = PEP_ILLEGAL_VALUE;
        goto pEp_free;
    }
                
    // Ok, so all the things are now allowed.
    // So let's get our own private key and roll with it.
    size_t priv_key_size = 0;
    
    status = export_secret_key(session, own_private_fpr, &priv_key_data, 
                                &priv_key_size);

    if (status != PEP_STATUS_OK)
        goto pEp_free;
    
    if (!priv_key_data) {
        status = PEP_CANNOT_EXPORT_KEY;
        goto pEp_free;
    }
    
    // Ok, fine... let's encrypt yon blob
    keys = new_stringlist(own_private_fpr);
    if (!keys) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_free;
    }
    
    stringlist_add(keys, to_fpr);
    
    char* encrypted_key_text = NULL;
    size_t encrypted_key_size = 0;
    
    if (flags & PEP_encrypt_flag_force_unsigned)
        status = encrypt_only(session, keys, priv_key_data, priv_key_size,
                              &encrypted_key_text, &encrypted_key_size);
    else
        status = encrypt_and_sign(session, keys, priv_key_data, priv_key_size,
                                  &encrypted_key_text, &encrypted_key_size);
    
    if (status == PEP_PASSPHRASE_REQUIRED || status == PEP_WRONG_PASSPHRASE) {
        free(encrypted_key_text);        
        goto pEp_free;
    }                              
    else if (!encrypted_key_text) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_free;
    }
    else if (status != PEP_STATUS_OK) {
        free(encrypted_key_text);
        goto pEp_free; // FIXME - we need an error return overall
    }

    // We will have to delete this before returning, as we allocated it.
    bloblist_t* created_bl = NULL;
    bloblist_t* created_predecessor = NULL;
    
    bloblist_t* old_head = NULL;
    
    if (!src->attachments || src->attachments->value == NULL) {
        if (src->attachments && src->attachments->value == NULL) {
            old_head = src->attachments;
            src->attachments = NULL;
        }
        src->attachments = new_bloblist(encrypted_key_text, encrypted_key_size,
                                        "application/octet-stream", 
                                        "file://pEpkey.asc.pgp");
        created_bl = src->attachments;
    } 
    else {
        bloblist_t* tmp = src->attachments;
        while (tmp && tmp->next) {
            tmp = tmp->next;
        }
        created_predecessor = tmp;                                    
        created_bl = bloblist_add(tmp, 
                                  encrypted_key_text, encrypted_key_size,
                                  "application/octet-stream", 
                                   "file://pEpkey.asc.pgp");
    }
    
    if (!created_bl) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_free;
    }
            
    // Ok, it's in there. Let's do this.        
    status = encrypt_message(session, src, keys, dst, enc_format, flags);
    
    // Delete what we added to src
    free_bloblist(created_bl);
    if (created_predecessor)
        created_predecessor->next = NULL;
    else {
        if (old_head)
            src->attachments = old_head;
        else
            src->attachments = NULL;    
    }
    
pEp_free:
    free(own_id);
    free(default_id);
    free(own_private_fpr);
    free(priv_key_data);
    free_identity(own_identity);
    free_stringlist(keys);
    return status;
}


DYNAMIC_API PEP_STATUS encrypt_message_for_self(
        PEP_SESSION session,
        pEp_identity* target_id,
        message *src,
        stringlist_t* extra,
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
    assert(target_id);
    assert(src);
    assert(dst);
    assert(enc_format != PEP_enc_none);

    if (!(session && target_id && src && dst && enc_format != PEP_enc_none))
        return PEP_ILLEGAL_VALUE;

    // if (src->dir == PEP_dir_incoming)
    //     return PEP_ILLEGAL_VALUE;

    determine_encryption_format(src);
    if (src->enc_format != PEP_enc_none)
        return PEP_ILLEGAL_VALUE;

    if (!target_id->user_id || target_id->user_id[0] == '\0') {
        char* own_id = NULL;
        status = get_default_own_userid(session, &own_id);
        if (own_id) {
            free(target_id->user_id);
            target_id->user_id = own_id; // ownership transfer
        }
    }

    if (!target_id->user_id || target_id->user_id[0] == '\0')
        return PEP_CANNOT_FIND_IDENTITY;

    if (target_id->address) {
        status = myself(session, target_id);
        if (status != PEP_STATUS_OK)
            goto pEp_error;
    }
    else if (!target_id->fpr) {
        return PEP_ILLEGAL_VALUE;
    }

    // Ensure we don't encrypt to extra keys if this is a non-org account
    if (!(target_id->flags & PEP_idf_org_ident))
        extra = NULL;

    *dst = NULL;

    // PEP_STATUS _status = update_identity(session, target_id);
    // if (_status != PEP_STATUS_OK) {
    //     status = _status;
    //     goto pEp_error;
    // }

    char* target_fpr = target_id->fpr;
    if (!target_fpr)
        return PEP_KEY_NOT_FOUND; // FIXME: Error condition
 
    // is a passphrase needed?
    status = probe_encrypt(session, target_fpr);
    if (failed_test(status))
        return status;

    keys = new_stringlist(target_fpr);
    
    stringlist_t *_k = keys;

    if (extra) {
        _k = stringlist_append(_k, extra);
        if (_k == NULL)
            goto enomem;
    }

    /* KG: did we ever do this??? */
    // if (!(flags & PEP_encrypt_flag_force_no_attached_key))
    //     _attach_key(session, target_fpr, src);

    unsigned int major_ver, minor_ver;
    pEp_version_major_minor(PEP_VERSION, &major_ver, &minor_ver);
    status = wrap_message_as_attachment(NULL, src, &_src, PEP_message_default, false, extra, major_ver, minor_ver);
    if (status != PEP_STATUS_OK)
        goto pEp_error;
    else if (!_src) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_error;
    }

    msg = clone_to_empty_message(_src);
    if (msg == NULL)
        goto enomem;

    switch (enc_format) {
        case PEP_enc_PGP_MIME:
        case PEP_enc_PEP: // BUG: should be implemented extra
            status = encrypt_PGP_MIME(session, _src, keys, msg, flags, PEP_message_default);
            if (status == PEP_STATUS_OK || (src->longmsg && strstr(src->longmsg, "INNER")))
                _cleanup_src(src, false);
            break;

        case PEP_enc_inline:
        case PEP_enc_inline_EA:
            _src->enc_format = enc_format;
            status = encrypt_PGP_inline(session, _src, keys, msg, flags);
            break;

        default:
            assert(0);
            status = PEP_ILLEGAL_VALUE;
            goto pEp_error;
    }

    if (status == PEP_OUT_OF_MEMORY)
        goto enomem;

    if (status != PEP_STATUS_OK)
        goto pEp_error;

    if (msg) {
        if (!src->shortmsg) {
            free(msg->shortmsg);
            msg->shortmsg = _pEp_subj_copy();
            assert(msg->shortmsg);
            if (msg->shortmsg == NULL)
                goto enomem;
        }
        else {
            if (session->unencrypted_subject && (flags & PEP_encrypt_reencrypt)) {
                free(msg->shortmsg);
                msg->shortmsg = strdup(src->shortmsg);
            }    
        }

        if (_src->id) {
            msg->id = strdup(_src->id);
            assert(msg->id);
            if (msg->id == NULL)
                goto enomem;
        }
        decorate_message(session, msg, PEP_rating_undefined, NULL, true, true);
    }

    *dst = msg;
    
    if (src != _src)
        free_message(_src);

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_error:
    free_stringlist(keys);
    free_message(msg);
    if (src != _src)
        free_message(_src);

    return status;
}

// static PEP_STATUS _update_identity_for_incoming_message(
//         PEP_SESSION session,
//         const message *src
//     )
// {
//     PEP_STATUS status;
// 
//     if (src->from && src->from->address) {
//         if (!is_me(session, src->from))
//             status = update_identity(session, src->from);
//         else
//             status = myself(session, src->from);
//         if (status == PEP_STATUS_OK
//                 && is_a_pEpmessage(src)
//                 && src->from->comm_type >= PEP_ct_OpenPGP_unconfirmed
//                 && src->from->comm_type != PEP_ct_pEp_unconfirmed
//                 && src->from->comm_type != PEP_ct_pEp)
//         {
//             src->from->comm_type |= PEP_ct_pEp_unconfirmed;
//             status = set_identity(session, src->from);
//         }
//         return status;
//     }
//     return PEP_ILLEGAL_VALUE;
// }


/**
 *  @internal
 *
 *  <!--       _get_detached_signature()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]        *msg                message
 *  @param[in,out]    **signature_blob    bloblist_t
 *
 *  @retval PEP_STATUS_OK 
 */
static PEP_STATUS _get_detached_signature(message* msg,
                                          bloblist_t** signature_blob) {
    bloblist_t* attach_curr = msg->attachments;

    *signature_blob = NULL;

    while (attach_curr) {
        if (attach_curr->mime_type &&
            (strcasecmp(attach_curr->mime_type, "application/pgp-signature") == 0)) {
            *signature_blob = attach_curr;
            break;
        }
        attach_curr = attach_curr->next;
    }

    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       _get_signed_text()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]        *ptext        constchar
 *  @param[in]        psize        constsize_t
 *  @param[out]     **stext        char
 *  @param[out]        *ssize        size_t
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_UNKNOWN_ERROR 
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 */
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
    assert(signed_boundary);
    if (!signed_boundary)
        return PEP_OUT_OF_MEMORY;

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

/**
 *  @internal
 *
 *  <!--       combine_keylists()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]        session                session handle    
 *  @param[in]        **verify_in            stringlist_t
 *  @param[out]     **keylist_in_out    stringlist_t
 *  @param[in]         *from                pEp_identity
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_KEY_NOT_FOUND
 *  @retval any other value on error
 */
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

    if (keylist_in_out) {
        /* append keylist to signers */
        if (*keylist_in_out && (*keylist_in_out)->value) {
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
    }

    status = PEP_STATUS_OK;
    
free:
    free_stringlist(from_keys);
    return status;
}

/**
 *  @internal
 *
 *  <!--       amend_rating_according_to_sender_and_recipients()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *rating            PEP_rating
 *  @param[in]    *sender            pEp_identity
 *  @param[in]    *recipients        stringlist_t
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval PEP_CANNOT_FIND_IDENTITY
 *  @retval any other value on error
 */
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
                            fpr, rating_from_comm_type(_sender->comm_type));
            }
            
            free_identity(_sender);
            if (status == PEP_CANNOT_FIND_IDENTITY)
               status = PEP_STATUS_OK;
        }
    }
    return status;
}

// FIXME: Do we need to remove the attachment? I think we do...
/**
 *  @internal
 *
 *  <!--       pull_up_attached_main_msg()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *src        message
 *
 *  @retval     bool
 */
static bool pull_up_attached_main_msg(message* src) {
    char* slong = src->longmsg;
    char* sform = src->longmsg_formatted;
    bloblist_t* satt = src->attachments;
    
    if ((!slong || slong[0] == '\0')
         && (!sform || sform[0] == '\0')) {
        const char* inner_mime_type = (satt ? satt->mime_type : NULL);     
        if (inner_mime_type) {
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



/**
 *  @internal
 *
 *  <!--       unencapsulate_hidden_fields()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *src        message
 *  @param[in]    *msg        message
 *  @param[in]    **msg_wrap_info        char
 *
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
static PEP_STATUS unencapsulate_hidden_fields(message* src, message* msg,
                                              char** msg_wrap_info) {
    if (!src)
        return PEP_ILLEGAL_VALUE;
    unsigned char pEpstr[] = PEP_SUBJ_STRING;
    PEP_STATUS status = PEP_STATUS_OK;

    bool change_source_in_place = (msg ? false : true);
    
    if (change_source_in_place)
        msg = src;
        
    
    switch (src->enc_format) {
        case PEP_enc_PGP_MIME:
        case PEP_enc_inline:
        case PEP_enc_inline_EA:
        case PEP_enc_PGP_MIME_Outlook1:
//        case PEP_enc_none: // FIXME - this is wrong

            if (!change_source_in_place)
                status = copy_fields(msg, src);
                
            if (status != PEP_STATUS_OK)
                return status;
                
            // FIXME: This is a mess. Talk with VB about how far we go to identify
            if (is_a_pEpmessage(src) || (src->shortmsg == NULL || strcmp(src->shortmsg, "pEp") == 0 ||
                _unsigned_signed_strcmp(pEpstr, src->shortmsg, PEP_SUBJ_BYTELEN) == 0) ||
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
                         _unsigned_signed_strcmp(pEpstr, src->shortmsg, PEP_SUBJ_BYTELEN) != 0 &&
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

/**
 *  @internal
 *
 *  <!--       get_crypto_text()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *src        message
 *  @param[in]    **crypto_text        char
 *  @param[in]    *text_size        size_t
 *
 *  @retval PEP_STATUS_OK
 */
static PEP_STATUS get_crypto_text(message* src, char** crypto_text, size_t* text_size) {
                
    // this is only here because of how NOT_IMPLEMENTED works            
    PEP_STATUS status = PEP_STATUS_OK;
                    
    switch (src->enc_format) {
    case PEP_enc_PGP_MIME:
        *crypto_text = src->attachments->next->value;
        if (src->attachments->next->value[src->attachments->next->size - 1]) {
            // if the attachment is not ending with a trailing 0
            // then it is containing the crypto text directly
            *text_size = src->attachments->next->size;
        }
        else {
            // if the attachment is ending with trailing 0
            // then it is containting a string
            *text_size = strlen(src->attachments->next->value);
        }
        break;

    case PEP_enc_PGP_MIME_Outlook1:
        *crypto_text = src->attachments->value;
        if (src->attachments->value[src->attachments->size - 1]) {
            // if the attachment is not ending with a trailing 0
            // then it is containing the crypto text directly
            *text_size = src->attachments->size;
        }
        else {
            // if the attachment is ending with trailing 0
            // then it is containting a string
            *text_size = strlen(src->attachments->value);
        }
        break;

        case PEP_enc_inline:
        case PEP_enc_inline_EA:
            *crypto_text = src->longmsg;
            *text_size = strlen(*crypto_text);
            break;

        default:
            NOT_IMPLEMENTED
    }
    
    return status;
}


/**
 *  @internal
 *
 *  <!--       verify_decrypted()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        session handle
 *  @param[in]    *src        message
 *  @param[in]    *msg        message
 *  @param[in]    *plaintext        char
 *  @param[in]    plaintext_size        size_t
 *  @param[in]    **keylist        stringlist_t
 *  @param[in]    *decrypt_status        PEP_STATUS
 *  @param[in]    crypto        PEP_cryptotech
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 */
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
                                             &ptext, &psize, keylist,
                                             NULL);
        
    }

    if (*decrypt_status != PEP_DECRYPTED_AND_VERIFIED)
        *decrypt_status = _cached_decrypt_status;                                

    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       _decrypt_in_pieces()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        session handle
 *  @param[in]    *src        message
 *  @param[in]    **msg_ptr        message
 *  @param[in]    *ptext        char
 *  @param[in]    psize        size_t
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
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

    msg->longmsg = strdup(ptext);
    ptext = NULL;

    bloblist_t *_m = msg->attachments;
    if (_m == NULL && src->attachments && src->attachments->value) {
        msg->attachments = new_bloblist(NULL, 0, NULL, NULL);
        _m = msg->attachments;
    }

    bloblist_t *_s;
    for (_s = src->attachments; _s && _s->value; _s = _s->next) {
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

            char* pgp_filename = NULL;
            status = decrypt_and_verify(session, attctext, attcsize,
                                        NULL, 0,
                                        &ptext, &psize, &_keylist,
                                        &pgp_filename);
                                        
            free_stringlist(_keylist);

            char* filename_uri = NULL;

            bool has_uri_prefix = (pgp_filename ? (is_file_uri(pgp_filename) || is_cid_uri(pgp_filename)) :
                                                  (_s->filename ? (is_file_uri(_s->filename) || is_cid_uri(_s->filename)) :
                                                                  false
                                                  )
                                  );
            

            if (ptext) {
                if (is_encrypted_html_attachment(_s)) {
                    msg->longmsg_formatted = ptext;
                    ptext = NULL;
                }
                else {
                    static const char * const mime_type = "application/octet-stream";                    
                    if (pgp_filename) {
                        if (!has_uri_prefix)
                            filename_uri = build_uri("file", pgp_filename);

                        char *_filename = filename_uri ? filename_uri : pgp_filename;
                        if (strcasecmp(_filename, "file://distribution.pEp") == 0)
                            _m = bloblist_add(_m, ptext, psize, "application/pEp.distribution", _filename);
                        else if (strcasecmp(_filename, "file://sync.pEp") == 0)
                            _m = bloblist_add(_m, ptext, psize, "application/pEp.sync", _filename);
                        else
                            _m = bloblist_add(_m, ptext, psize, mime_type, _filename);

                        free(pgp_filename);
                        free(filename_uri);
                        if (_m == NULL)
                            return PEP_OUT_OF_MEMORY;
                    }
                    else {
                        char * const filename =
                            without_double_ending(_s->filename);
                        if (filename == NULL)
                            return PEP_OUT_OF_MEMORY;

                        if (!has_uri_prefix)
                            filename_uri = build_uri("file", filename);

                        char *_filename = filename_uri ? filename_uri : filename;
                        if (strcasecmp(_filename, "file://distribution.pEp") == 0)
                            _m = bloblist_add(_m, ptext, psize, "application/pEp.distribution", _filename);
                        else if (strcasecmp(_filename, "file://sync.pEp") == 0)
                            _m = bloblist_add(_m, ptext, psize, "application/pEp.sync", _filename);
                        else
                            _m = bloblist_add(_m, ptext, psize, mime_type, _filename);

                        free(filename);
                        free(filename_uri);
                        if (_m == NULL)
                            return PEP_OUT_OF_MEMORY;
                    }
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

                if (!has_uri_prefix && _s->filename)
                    filename_uri = build_uri("file", _s->filename);

                _m = bloblist_add(_m, copy, _s->size, _s->mime_type, 
                        (filename_uri ? filename_uri : _s->filename));
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

            char* filename_uri = NULL;

            _m = bloblist_add(_m, copy, _s->size, _s->mime_type, 
                    ((_s->filename && !(is_file_uri(_s->filename) || is_cid_uri(_s->filename))) ?
                         (filename_uri = build_uri("file", _s->filename)) : _s->filename));
            free(filename_uri);
            if (_m == NULL)
                return PEP_OUT_OF_MEMORY;
        }
    }

    return status;
}

// This is misleading - this imports ALL the keys!
/**
 *  @internal
 *
 *  <!--       import_keys_from_decrypted_msg()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                    session handle    
 *  @param[in]    *msg                    message
 *  @param[in]    *keys_were_imported        bool
 *  @param[in]    *imported_private        bool
 *  @param[in]    **private_il        identity_list
 *  @param[in]    **keylist        stringlist_t
 *  @param[in]    *changed_keys        uint64_t
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
static PEP_STATUS import_keys_from_decrypted_msg(PEP_SESSION session,
                                                      message* msg,
                                                      bool is_pEp_msg,
                                                      bool* keys_were_imported,
                                                      bool* imported_private,
                                                      identity_list** private_il,
                                                      stringlist_t** keylist,
                                                      uint64_t* changed_keys,
                                                      char** pEp_sender_key
    )
{
    assert(msg && keys_were_imported && imported_private);
    if (!(msg && keys_were_imported && imported_private))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    *keys_were_imported = false;
    *imported_private = false;
    if (private_il)
        *private_il = NULL;

    // check for private key in decrypted message attachment while importing
    identity_list *_private_il = NULL;

    bool _keys_were_imported = import_attached_keys(session, msg, is_pEp_msg,
                                                    &_private_il, keylist, 
                                                    changed_keys, pEp_sender_key);
    bool _imported_private = false;
    if (_private_il && _private_il->ident && _private_il->ident->address)
        _imported_private = true;

    if (private_il && _imported_private) {
        // the private identity list should NOT be subject to myself() or
        // update_identity() at this point.
        // If the receiving app wants them to be in the trust DB, it
        // should call set_own_key() on them upon return.
        // We do, however, prepare these so the app can use them
        // directly in a set_own_key() call by putting the own_id on it.
        char* own_id = NULL;
        status = get_default_own_userid(session, &own_id);
        
        for (identity_list* il = _private_il; il; il = il->next) {
            if (own_id) {
                free(il->ident->user_id);
                il->ident->user_id = strdup(own_id);
                assert(il->ident->user_id);
                if (!il->ident->user_id) {
                    status = PEP_OUT_OF_MEMORY;
                    break;
                }
            }
            il->ident->me = true;
        }
        free(own_id);
        if (!status)
            *private_il = _private_il;
    }
    else {
        free_identity_list(_private_il);
    }
 
    if (!status) {
        *keys_were_imported = _keys_were_imported;
        *imported_private = _imported_private;
    }

    return status;
}

// ident is in_only and should have been updated
/**
 *  @internal
 *
 *  <!--       pEp_version_upgrade_or_ignore()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        session handle
 *  @param[in]    *ident        pEp_identity
 *  @param[in]    major        unsignedint
 *  @param[in]    minor        unsignedint
 *
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 */
static PEP_STATUS pEp_version_upgrade_or_ignore(
        PEP_SESSION session,
        pEp_identity* ident,
        unsigned int major,
        unsigned int minor) {
            
    PEP_STATUS status = PEP_STATUS_OK;        
    int ver_compare = compare_versions(major, minor, ident->major_ver, ident->minor_ver);
    if (ver_compare > 0)
        status = set_pEp_version(session, ident, major, minor);        
    
    return status;    
}

/**
 *   @internal
 *
 *   @param msg
 *   @param keylist
 *   @return
 *
 *   @note  Presupposes you've updated the msg->from identity somewhere so it contains the ident default.
 */
static bool sender_fpr_is_signer_fpr(message* msg, stringlist_t* keylist) {
    if (!msg || EMPTYSTR(msg->_sender_fpr) || !keylist || EMPTYSTR(keylist->value))
        return false;

    return (strcmp(msg->_sender_fpr, keylist->value) == 0);
}


/**
 *   @internal
 *
 *   @param msg
 *   @return
 *
 *   @note  Presupposes you've updated the msg->from identity somewhere so it contains the ident default.
 */
static bool sender_fpr_is_from_default(message* msg) {
    if (!msg || !msg->from || EMPTYSTR(msg->from->fpr) || EMPTYSTR(msg->_sender_fpr))
        return false;

    return (strcmp(msg->from->fpr, msg->_sender_fpr) == 0);
}

/**
 *  @internal
 *
 *  <!--       update_sender_to_pEp_trust()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session       session handle
 *  @param[in]    msg           the message we're doing this from
 *  @param[in]    keylist       keylist containing signer during decrypt/verify
 *  @param[in]    major         unsigned int
 *  @param[in]    minor         unsigned int
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval PEP_CANNOT_SET_TRUST
 *  @retval any other value on error
 *
 *  @note   Only use on messages that were decrypted; unencrypted messages have a different path.
 */
static PEP_STATUS update_sender_to_pEp_trust(
        PEP_SESSION session, 
        message* msg,
        stringlist_t* keylist,
        unsigned int major,
        unsigned int minor) 
{
    assert(session);
    assert(msg);
    
    if (!session || !msg || !keylist)
        return PEP_ILLEGAL_VALUE;

    if (!msg->from)
        return PEP_STATUS_OK;

    pEp_identity* sender = msg->from;

    PEP_STATUS status = is_me(session, sender) ? _myself(session, sender, false, false, false, true) : update_identity(session, sender);

    if (PASS_ERROR(status))
        return status;

    // Ok, identity is updated.
    // Now, let's find out if the sender_fpr on this message is the signer and if it is the sender default. If so, we can do this.
    // If not? forget it.
    if (!sender_fpr_is_signer_fpr(msg, keylist) || !sender_fpr_is_from_default(msg))
        return PEP_STATUS_OK; // We don't return an error here because failing to satisfy the conditions isn't an error here, it's just a no-op.

    switch (sender->comm_type) {
        case PEP_ct_OpenPGP_unconfirmed:
        case PEP_ct_OpenPGP:
            sender->comm_type = PEP_ct_pEp_unconfirmed | (sender->comm_type & PEP_ct_confirmed);
            status = set_trust(session, sender);
            if (status != PEP_STATUS_OK)
                break;
            // Fallthrough EXPLICIT here
        case PEP_ct_pEp:
        case PEP_ct_pEp_unconfirmed:
            // set version
            if (major == 0) {
                major = 2;
                minor = 1;
            }
            status = pEp_version_upgrade_or_ignore(session, sender, major, minor);
            break;
        default:
            status = PEP_CANNOT_SET_TRUST;
            break;
    }
    
    return status;
}

/**
 *  @internal
 *
 *  <!--       reconcile_identity()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *srcid        pEp_identity
 *  @param[in]    *resultid        pEp_identity
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 */
static PEP_STATUS reconcile_identity(pEp_identity* srcid,
                                     pEp_identity* resultid) {
    assert(srcid);
    assert(resultid);

    if (!srcid || !resultid)
        return PEP_ILLEGAL_VALUE;
        
    if (!EMPTYSTR(srcid->user_id)) {
        if (EMPTYSTR(resultid->user_id) ||
             strcmp(srcid->user_id, resultid->user_id) != 0) {
            free(resultid->user_id);
            resultid->user_id = strdup(srcid->user_id);
        }
    }
    
    resultid->lang[0] = srcid->lang[0];
    resultid->lang[1] = srcid->lang[1];
    resultid->lang[2] = 0;
    resultid->me = srcid->me;
    resultid->flags = srcid->flags;

    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       reconcile_identity_lists()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *src_ids        identity_list
 *  @param[in]    *result_ids        identity_list
 *
 */
static PEP_STATUS reconcile_identity_lists(identity_list* src_ids,
                                           identity_list* result_ids) {
                                           
    identity_list* curr_id = result_ids;
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    while (curr_id) {
        identity_list* curr_src_id = src_ids;
        pEp_identity* result_identity = curr_id->ident;
        
        while (curr_src_id) {
            pEp_identity* source_identity = curr_src_id->ident;
            
            if (EMPTYSTR(source_identity->address) || EMPTYSTR(result_identity->address))
                return PEP_ILLEGAL_VALUE; // something went badly wrong
            
            if (strcasecmp(source_identity->address, result_identity->address) == 0) {
                status = reconcile_identity(source_identity, result_identity);
                if (status != PEP_STATUS_OK)
                    return status;
            }
            curr_src_id = curr_src_id->next;        
        }
        curr_id = curr_id->next;
    }
    return status;    
}

/**
 *  @internal
 *
 *  <!--       reconcile_sent_and_recv_info()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *src        message
 *  @param[in]    *inner_message        message
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 */
static PEP_STATUS reconcile_sent_and_recv_info(message* src, message* inner_message) {
    if (!src || !inner_message)
        return PEP_ILLEGAL_VALUE;
        
    if (!inner_message->sent)
        inner_message->sent = timestamp_dup(src->sent);
        
    // This will never be set otherwise, since it's a transport header on the outside    
    inner_message->recv = timestamp_dup(src->recv);
    
    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       reconcile_src_and_inner_messages()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *src        message
 *  @param[in]    *inner_message        message
 *
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 */
static PEP_STATUS reconcile_src_and_inner_messages(message* src,
                                             message* inner_message) {

    PEP_STATUS status = PEP_STATUS_OK;
    
    if (src->from && inner_message->from && 
           src->from->address && inner_message->from->address && 
           strcasecmp(src->from->address, inner_message->from->address) == 0) {
        status = reconcile_identity(src->from, inner_message->from);
    }    
    
    if (status == PEP_STATUS_OK && inner_message->to)
        status = reconcile_identity_lists(src->to, inner_message->to);

    if (status == PEP_STATUS_OK && inner_message->cc)
        status = reconcile_identity_lists(src->cc, inner_message->cc);

    if (status == PEP_STATUS_OK && inner_message->bcc)
        status = reconcile_identity_lists(src->bcc, inner_message->bcc);

    if (status == PEP_STATUS_OK)
        status = reconcile_sent_and_recv_info(src, inner_message);
        
    return status;
    // FIXME - are there any flags or anything else we need to be sure are carried?
}

/**
 *  @internal
 *
 *  <!--       import_header_keys()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                    session handle
 *  @param[in]    *src                    message
 *  @param[in]    **imported_key_list        stringlist_t
 *  @param[in]    *changed_keys            uint64_t
 *
 *  @retval     bool
 */
static bool import_header_keys(PEP_SESSION session, message* src, stringlist_t** imported_key_list, uint64_t* changed_keys) {
    stringpair_list_t* header_keys = stringpair_list_find(src->opt_fields, "Autocrypt"); 
    if (!header_keys || !header_keys->value)
        return false;
    const char* value = header_keys->value->value;
    if (!value)
        return false;
    const char* start_key = strstr(value, "keydata=");
    if (!start_key)
        return false;
    start_key += 8; // length of "keydata="
    int length = strlen(start_key);
    bloblist_t* the_key = base64_str_to_binary_blob(start_key, length);
    if (!the_key)
        return false;
    PEP_STATUS status = import_key_with_fpr_return(session, 
                                                    the_key->value, 
                                                    the_key->size, 
                                                    NULL, 
                                                    imported_key_list, 
                                                    changed_keys);
    free_bloblist(the_key);
    if (status == PEP_STATUS_OK || status == PEP_KEY_IMPORTED)
        return true;
    return false;
}

/**
 *  @internal
 *
 *  <!--       check_for_own_revoked_key()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *keylist        stringlist_t
 *  @param[in]    **revoked_fpr_pairs        stringpair_list_t
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval any other value on error
 */
PEP_STATUS check_for_own_revoked_key(
        PEP_SESSION session, 
        stringlist_t* keylist,
        stringpair_list_t** revoked_fpr_pairs
    ) 
{
    if (!session || !revoked_fpr_pairs)
        return PEP_ILLEGAL_VALUE;

    char* default_own_userid = NULL;

    *revoked_fpr_pairs = NULL;

    PEP_STATUS status = PEP_STATUS_OK;
    stringpair_list_t* _the_list = new_stringpair_list(NULL);
        
    stringlist_t* _k = keylist;
    for ( ; _k; _k = _k->next) {

        if (EMPTYSTR(_k->value))
            continue; // Maybe the right thing to do is choke. 
                      // But we can have NULL-valued empty list heads.

        const char* recip_fpr = _k->value;
        char* replace_fpr = NULL;
        uint64_t revoke_date = 0; 
        status = get_replacement_fpr(session, 
                                     recip_fpr, 
                                     &replace_fpr, 
                                     &revoke_date);

        bool own_key = false;

        pEp_identity* placeholder_ident = NULL;

        switch (status) {
            case PEP_CANNOT_FIND_IDENTITY:
                status = PEP_STATUS_OK;
                continue;
            case PEP_STATUS_OK:
                // Ok, we know it's a revoked key. Now see if it was "ours" by checking
                // to see if we have an entry for it with our user id, since we already clearly
                // know its replacement

                status = get_default_own_userid(session, &default_own_userid);

                if (status == PEP_STATUS_OK && !EMPTYSTR(default_own_userid)) {
                    placeholder_ident = new_identity(NULL, recip_fpr, default_own_userid, NULL);
                    if (!placeholder_ident)
                        status = PEP_OUT_OF_MEMORY;
                    else
                        status = get_trust(session, placeholder_ident);

                    if (status == PEP_STATUS_OK) {
                        stringlist_t* keylist = NULL;
                        status = find_private_keys(session, recip_fpr, &keylist);
                        if (status == PEP_STATUS_OK) {
                            if (keylist && !EMPTYSTR(keylist->value))
                                own_key = true;
                        }
                        free_stringlist(keylist);
                    }
                }
                else if (status == PEP_CANNOT_FIND_IDENTITY)
                    status = PEP_STATUS_OK;

                free_identity(placeholder_ident);

                if (status != PEP_STATUS_OK) {
                    free(replace_fpr);
                    free(default_own_userid);
                    return status;
                }
                
                if (own_key)
                    stringpair_list_add(_the_list, new_stringpair(recip_fpr, replace_fpr));

                free(replace_fpr);
                replace_fpr = NULL;
                break;
            default:    
                goto pEp_free;    
        }
    }
    
    if (_the_list && _the_list->value) {
        *revoked_fpr_pairs = _the_list;
        _the_list = NULL;
    }
            
pEp_free:
    free_stringpair_list(_the_list);
    free(default_own_userid);
    return status;

}

/**
 *  @internal
 *
 *  <!--       _have_extrakeys()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *keylist        stringlist_t
 *
 *  @retval     bool
 */
static bool _have_extrakeys(stringlist_t *keylist)
{
    return keylist
        && keylist->value
        && keylist->value[0];
}

// practically speaking, only useful to get user_id/address intersection
// we presume no dups in the first list if you're looking for
// a unique result.
/**
 *  @internal
 *
 *  <!--       ident_list_intersect()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *list_a        identity_list
 *  @param[in]    *list_b        identity_list
 *  @param[in]    **intersection        identity_list
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 */
static PEP_STATUS ident_list_intersect(identity_list* list_a,
                                       identity_list* list_b,
                                       identity_list** intersection) {

    if (!intersection)
        return PEP_ILLEGAL_VALUE;
                                           
    *intersection = NULL;                                       
    if (!list_a || !list_b || !list_a->ident || !list_b->ident)
        return PEP_STATUS_OK;
                
        
    *intersection = NULL;
    
    identity_list* isect = NULL;
    
    identity_list* curr_a = list_a;
    for ( ; curr_a && curr_a->ident; curr_a = curr_a->next) {
        pEp_identity* id_a = curr_a->ident;
        if (EMPTYSTR(id_a->user_id) || EMPTYSTR(id_a->address))
            continue;

        identity_list* curr_b = list_b;
        for ( ; curr_b && curr_b->ident; curr_b = curr_b->next) {
            pEp_identity* id_b = curr_b->ident;
            if (EMPTYSTR(id_b->user_id) || EMPTYSTR(id_b->address))
                continue;
                
            if (strcmp(id_a->user_id, id_b->user_id) == 0 &&
                strcmp(id_a->address, id_b->address) == 0) {
                pEp_identity* result_id = identity_dup(id_b);
                if (!id_b) 
                    goto enomem;
                    
                if (!isect) {
                    isect = new_identity_list(result_id);
                    if (!isect) 
                        goto enomem;
                }    
                else {
                    if (!identity_list_add(isect, result_id))
                        goto enomem;
                }   
                break;  
            }
        }
    }
    *intersection = isect;
    return PEP_STATUS_OK;

enomem:
    free_identity_list(isect);
    return PEP_OUT_OF_MEMORY;
    
}

static PEP_STATUS process_Distribution_message(PEP_SESSION session,
                                               message* msg,
                                               PEP_rating rating,
                                               const char* data, size_t size,
                                               char* sender_fpr) {

    Distribution_t *dist = NULL;
    PEP_STATUS status = decode_Distribution_message(data, size, &dist);
    if (status != PEP_STATUS_OK || !dist)
        return status;

    switch(dist->present) {
        case Distribution_PR_keyreset:
            status = receive_key_reset(session, msg);
            break; // We'll do something later here on refactor!
        case Distribution_PR_managedgroup:
            // Set the group stuff in motion!
            status = receive_managed_group_message(session, msg, rating, dist);
            break;
        default:
            status = PEP_DISTRIBUTION_ILLEGAL_MESSAGE;
    }
    return status;
}

static void get_protocol_version_from_headers(
        stringpair_list_t* field_list,
        unsigned int* major_ver,
        unsigned int* minor_ver
    ) 
{
    *major_ver = 0;
    *minor_ver = 0;
    const stringpair_list_t* pEp_protocol_version = stringpair_list_find(field_list, "X-pEp-Version");
                        
    if (pEp_protocol_version && pEp_protocol_version->value)
        pEp_version_major_minor(pEp_protocol_version->value->value, major_ver, minor_ver);           
}

void get_message_version_from_headers(
        stringpair_list_t* field_list,
        unsigned int* major_ver,
        unsigned int* minor_ver
    ) 
{
    *major_ver = 0;
    *minor_ver = 0;
    const stringpair_list_t* pEp_message_version = stringpair_list_find(field_list, X_PEP_MSG_VER_KEY);
                        
    if (pEp_message_version && pEp_message_version->value)
        pEp_version_major_minor(pEp_message_version->value->value, major_ver, minor_ver);           
}

// CAN return PASS errors
static PEP_STATUS set_default_key_fpr_if_valid(
            PEP_SESSION session,
            pEp_identity* ident,
            const char* new_fpr
   ) 
{
    if (EMPTYSTR(new_fpr))
        return PEP_ILLEGAL_VALUE;
        
    free(ident->fpr);
    ident->fpr = strdup(new_fpr);
    if (!ident->fpr)
        return PEP_OUT_OF_MEMORY;
        
    // this will check to see that the key is usable as well as get its comm_type    
    PEP_STATUS status = validate_fpr(session, ident, true, true);
    if (status == PEP_STATUS_OK)
        status = set_identity(session, ident);            
    else { 
        free(ident->fpr);
        ident->fpr = NULL;                            
    }
    return status;
}

static PEP_STATUS _check_and_set_default_key(
        PEP_SESSION session,
        pEp_identity* src_ident,
        const char* sender_key
    )
{
    if (!session || !src_ident)
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(src_ident->address) || EMPTYSTR(sender_key))
        return PEP_STATUS_OK; // DOH, we're not setting anything here

    char* default_from_fpr = NULL;

    PEP_STATUS status = update_identity(session, src_ident);

    if (status == PEP_STATUS_OK && !is_me(session, src_ident)) {
        // Right now, we just want to know if there's a DB default, NOT 
        // if it matches what update_identity gives us (there are good reasons it might not)
        status = get_default_identity_fpr(session, src_ident->address, src_ident->user_id, &default_from_fpr);
        if (status == PEP_KEY_NOT_FOUND || status == PEP_CANNOT_FIND_IDENTITY) {
            if (!EMPTYSTR(sender_key))
                status = set_default_key_fpr_if_valid(session, src_ident, sender_key);
        }
    }

    if (status == PEP_OUT_OF_MEMORY)    
        return status;

    free(default_from_fpr);
    return PEP_STATUS_OK;  // We don't care about other errors here.    
}

static const char* process_key_claim(message* src,
                                     const char* imported_sender_key_fpr,
                                     const char* signer_fpr,
                                     int msg_major, int msg_minor,
                                     stringlist_t* imported_key_list,
                                     bool pEp_conformant) {

    if (msg_major == 2 && msg_minor == 0)
        return NULL;

    // Senders with pEp versions >= than 2.2 will never send us a 2.0 message or less
    // IF they know we are a pEp user.
    //
    // However, they COULD think we're OpenPGP - maybe imported the key from somewhere.
    //
    // So we have to only take the key IF the from-2.2-message-version is listed as
    // 1.0. Everything else we support would have an inner message. And only then
    // if the sender key has the right name. (FIXME: Have we changed 2.1 to do this?)
    // FIXME: From SENDER >= 2.2, we should be VERY careful here -- check back on this one
    //
    const char *sender_key = NULL;

    if (msg_major == 1) // pEp only: We only import from 2.1.34+ clients, which will use the correct name.
        sender_key = imported_sender_key_fpr;
    else if ((msg_major == 2 && msg_minor >= 1) || msg_major > 2) {
        // We've been sent the inner message
        // we require sender key filename to be correct and material to be present in this case
        if (!EMPTYSTR(imported_sender_key_fpr) && !EMPTYSTR(src->_sender_fpr)) {
            if (strcmp(imported_sender_key_fpr, src->_sender_fpr) == 0)
                sender_key = src->_sender_fpr;
        }
    }
    else if (!pEp_conformant) {
        // For header keys, we will have been sent the head of the list here.
        // For others, we were sent a reference to the last set of keys imported before this and checked to be
        // sure there was only one.
        if (imported_key_list) // not necessarily signer key!
            sender_key = imported_key_list->value;
    }
    if (!EMPTYSTR(sender_key) && !EMPTYSTR(signer_fpr)) {
        if (strcmp(sender_key, signer_fpr) != 0)
            sender_key = NULL;
    }

    return sender_key;
}

// Rule for this function, since it is one of the three most complicated functions in this whole damned
// business:
//
// If you calculate a status from something and expect it NOT to be fatal, once you are done USING that status,
// you MUST set it back to "PEP_STATUS_OK".
//
// There are times when we don't want errors during calls to be fatal. Once any action is taken on that
// status, if we are going to continue processing and not bail from the message, the status needs to be reset
// to PEP_STATUS_OK, or, alternately, we need to be using a temp status variable.

static PEP_STATUS _decrypt_message(
        PEP_SESSION session,
        message *src,
        message **dst,
        stringlist_t **keylist,
        PEP_rating *rating,
        PEP_decrypt_flags_t *flags,
        identity_list **private_il,
        stringlist_t** imported_key_fprs,
        uint64_t* changed_public_keys
    )
{
    assert(session);
    assert(src);
    assert(dst);
    assert(keylist);
    assert(rating);
    assert(flags);

    if (!(session && src && dst && keylist && rating && flags))
        return PEP_ILLEGAL_VALUE;

    /*** Begin init ***/
    PEP_STATUS status = PEP_STATUS_OK;
    PEP_STATUS decrypt_status = PEP_CANNOT_DECRYPT_UNKNOWN;
    PEP_STATUS _decrypt_in_pieces_status = PEP_CANNOT_DECRYPT_UNKNOWN;

    message* msg = NULL;
    message* calculated_src = src;
    message* reset_msg = NULL;
    
    char *ctext;
    size_t csize;
    char *ptext = NULL;
    size_t psize;
    stringlist_t *_keylist = NULL;
    bool is_pEp_msg = is_a_pEpmessage(src);
    bool myself_read_only = (src->dir == PEP_dir_incoming);
    bool breaks_protocol = false;
    unsigned int major_ver = 0;
    unsigned int minor_ver = 0;
    unsigned int msg_major_ver = 0;
    unsigned int msg_minor_ver = 0;

    // We have to capture this early, because sometimes, we will have to
    // force-set identity.username (IN THE DATABASE) from this. See
    // https://dev.pep.foundation/Engine/UserPseudonymity
    // This will get replaced if there is an inner message.
    char* input_from_username = NULL;
    PEP_rating channel_pre_rating = PEP_rating_undefined; // This is NOT the message rating. Will be used to
                                                          // cache the rating of non-me from identities before
                                                          // key import might assign a default key

    if (imported_key_fprs)
        *imported_key_fprs = NULL;
        
    stringlist_t* _imported_key_list = NULL;
    uint64_t _changed_keys = 0;
    
    stringpair_list_t* revoke_replace_pairs = NULL;
    
    char* imported_sender_key_fpr = NULL;
    
    // Grab input flags
    bool reencrypt = ((*flags & PEP_decrypt_flag_untrusted_server) &&
            (_have_extrakeys(*keylist) || session->unencrypted_subject));
    
    // We own this pointer, and we take control of *keylist if reencrypting.
    stringlist_t* extra = NULL;
    if (reencrypt)
        extra = *keylist;
            
    *dst = NULL;
    *keylist = NULL;
    *rating = PEP_rating_undefined;

    /*** End init ***/

    /*** Begin caching and setup information from non-me from identities ***/
    // Cache outer from info before key imports and setting of defaults can take place:
    // 1. Cache the username, if present. Under certain circumstances, we will need
    //    to set this as an *identity* default in the database.
    // 2. If it's a pEp message, regardless of whether it's
    //    encrypted or not, we set the sender as a pEp user. This has NOTHING to do
    //    with the key.
    // 3. Cache the outer channel rating. See below.
    // 4. Profit!!! (???????)
    //
    if (src->from && !(is_me(session, src->from))) {
        if (!EMPTYSTR(src->from->username))
            input_from_username = strdup(src->from->username); // Get it before update_identity changes it

        if (is_pEp_msg) {
            pEp_identity* tmp_from = src->from;
    
            // Ensure there's a user id
            if (EMPTYSTR(tmp_from->user_id) && tmp_from->address) {
                // Safe, because we have stored the input username.
                status = update_identity(session, tmp_from);
                if (status == PEP_CANNOT_FIND_IDENTITY) {
                    tmp_from->user_id = calloc(1, strlen(tmp_from->address) + 6);
                    if (!tmp_from->user_id)
                        return PEP_OUT_OF_MEMORY;
                    snprintf(tmp_from->user_id, strlen(tmp_from->address) + 6,
                             "TOFU_%s", tmp_from->address);        
                    status = PEP_STATUS_OK;
                }
            }
            if (status == PEP_STATUS_OK) {
                // Now set user as PEP (may also create an identity if none existed yet)
                status = set_as_pEp_user(session, tmp_from);
            }
        }
        // Before we go any further, we need to check the rating of the "channel" (described
        // in some fdik video somewhere, apparently - this is usually only described as an
        // app concept, so as far as we're concerned for the moment, it's the "usual" rating
        // we'd get if we were receiving in the best available communication with the "from" partner
        // alone). Since we've cached non-me usernames, this is safe here.
        //
        // Note: this MAY not be the actual channel rating we end up caring about - we'll look
        // at the inner message where appropriate if it's available. But for now, we cache this before
        // we lose it.
        status = identity_rating(session, src->from, &channel_pre_rating);

        // FIXME: we've been ignoring these statuses. Should we? Because I kind of don't think we should.
        // RESET
        status = PEP_STATUS_OK;
    }
    /*** End caching and setup information from non-me from identities ***/

    // NOTE:
    // We really need key used in signing to do anything further on the pEp comm_type.
    // So we can't adjust the *real* rating of the sender just yet.

    /*** Begin importing any keys attached an outer, undecrypted message - update identities accordingly ***/
    // Private key in unencrypted mail are ignored -> NULL
    //
    // This import is from the outermost message.
    // We don't do this for PGP_mime. -- KB: FIXME: I am pretty sure this was 
    // because of our overzealous import/remove process, but What does this do to enigmail messages 
    // if the keys are on the outside?? Are they ever?

    // In case there are header keys, get those - these will be the FIRST keys, and right 
    // now, this will lead to the first header key imported being the default key if the from
    // identity has no default key. This is intentional, as we're only importing one autocrypt 
    // header key here, but if this changes, we MUST change this assumption
    bool header_key_imported = import_header_keys(session, src, 
                                                  &_imported_key_list, 
                                                  &_changed_keys);    
    
    // Does this need to reflect the above?
    bool keys_were_imported = false;
        
    PEP_cryptotech enc_type = determine_encryption_format(src);
    if (enc_type != PEP_crypt_OpenPGP || !(src->enc_format == PEP_enc_PGP_MIME || src->enc_format == PEP_enc_PGP_MIME_Outlook1)) {
        keys_were_imported = import_attached_keys(session, 
                                                  src, is_pEp_msg, NULL, 
                                                  &_imported_key_list, 
                                                  &_changed_keys,
                                                  &imported_sender_key_fpr);
    }
    /*** End Import any attached outer public keys and update identities accordingly ***/
    
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
    status = PEP_STATUS_OK; // again, reset, we don't use the status
    /*** End get detached signatures that are attached to the encrypted message ***/

    /*** Determine encryption format ***/
    PEP_cryptotech crypto = determine_encryption_format(src);

    /*** Get outer protocol information ***/
    // Get protocol information listed on the OUTER message. This will not be used if there 
    // is an inner message and is not relied on for any security-relevant functionality since 
    // it is *fully manipulable on-the-wire*. It'll be recalculated if we have inner headers.
    get_protocol_version_from_headers(src->opt_fields, &major_ver, &minor_ver);

    if (major_ver == 0) {
        msg_major_ver = 1;
        msg_minor_ver = 0;
    }
    /*** End get outer protocol information ***/

    /*** Check for and deal with unencrypted messages ***/
    if (src->enc_format == PEP_enc_none) {
        // if there is a valid receiverRating then return this rating else
        // return unencrypted

        // All this does is try to deal with unencrypted sync messages;
        // Failure means the message wasn't one (or maybe wasn't a valid one)
        // and nothing else, so there should NOT be a fatal failure here
        // if the status comes back differently.
        PEP_rating _rating = PEP_rating_undefined;
        status = get_receiverRating(session, src, &_rating);
        if (status == PEP_STATUS_OK && _rating)
            *rating = _rating;
        else
            *rating = PEP_rating_unencrypted;

        // We are DONE with that status. Not clearing it causes ENGINE-915.
        status = PEP_STATUS_OK;

        // We remove these from the outermost source message
        // if (keys_were_imported)
        //     remove_attached_keys(src);
                                    
        pull_up_attached_main_msg(src);

        // Before we inadvertently update the presence of a key (because this
        // function will not have set one yet if needed, even if it was delivered in the
        // sent message), we check the quality of the "channel" by seeing what
        // rating we would have given the sender BEFORE we might import a new key
        // for them.

        // (N.B. is_me is calculated correctly because of the update_identity check above
        //  if we didn't already know at input)
        if (src->from && !is_me(session, src->from)) {
            if (input_from_username) {
                if (status == PEP_STATUS_OK && channel_pre_rating < PEP_rating_reliable) {
                    // We'll set this as the identity's username in the DB.
                    status = force_set_identity_username(session, src->from, input_from_username);
                    if (status == PEP_STATUS_OK) {
                        free(src->from->username);
                        src->from->username = input_from_username;
                        input_from_username = NULL;
                    }
                }
            }
            // Set default key if there isn't one
            // This is the case ONLY for unencrypted messages and differs from the 1.0 and 2.x cases,
            // in case you are led to think this is pure code duplication.
            if (src->from->address) {
                PEP_STATUS incoming_status = status;
                const char* sender_key = NULL;
                if (imported_sender_key_fpr) { // pEp protocol version 2.2 or greater, or someone knows to use the filename
                    sender_key = imported_sender_key_fpr; // FIXME: free
                }
                else if (!is_pEp_msg && header_key_imported) // autocrypt
                    sender_key = _imported_key_list->value;
                else {
                    // Basically, this is everything else, since we can trust nothing on the wire really.
                    if (_imported_key_list && !(_imported_key_list->next))
                        sender_key = _imported_key_list->value;
                } // Otherwise, too bad.

                status = _check_and_set_default_key(session, src->from, sender_key);
                free(imported_sender_key_fpr);
                imported_sender_key_fpr = NULL;

                if (status == PEP_OUT_OF_MEMORY)
                    goto enomem;
                if (status == PEP_STATUS_OK)
                    status = incoming_status;
            }
        }

        if (imported_key_fprs)
            *imported_key_fprs = _imported_key_list;
        if (changed_public_keys)
            *changed_public_keys = _changed_keys;
        
        if (imported_key_fprs)
            *imported_key_fprs = _imported_key_list;
        if (changed_public_keys)
            *changed_public_keys = _changed_keys;

        // FIXME: double check for mem leaks from beginning of function in the unencrypted case!
        free(input_from_username); // in case we didn't use it (if we did, this is NULL)

        // we return the status value here because it's important to know when 
        // we have a DB error here as soon as we have the info.
        return (status == PEP_STATUS_OK ? PEP_UNENCRYPTED : status);
    }
    /*** End check for and deal with unencrypted messages ***/

    //***************************************************************************
    //* From this point on, we are dealing with an encrypted message of some sort.
    //***************************************************************************

    // FIXME: This comment doesn't make a lot of sense. Ask vb about what
    //        is going on here.
    // if there is an own identity defined via this message is coming in
    // retrieve the details; in case there's no usable own key make it
    // functional
    // (Note: according to fdik, the apps are responsible for setting
    //  recv_by)

    // FIXME, with both here: free memory
    if (src->recv_by && !EMPTYSTR(src->recv_by->address)) {
        status = myself(session, src->recv_by);
        if (status) {
            free_stringlist(_imported_key_list);
            return status;
        }
    }

    // FIXME: see above
    status = get_crypto_text(src, &ctext, &csize);
    if (status) {
        free_stringlist(_imported_key_list);
        return status;
    }
        
    /** Ok, we should be ready to decrypt. Try decrypt and verify first! **/
    status = decrypt_and_verify(session, ctext, csize, dsig_text, dsig_size,
            &ptext, &psize, &_keylist, NULL);

    if (status > PEP_CANNOT_DECRYPT_UNKNOWN)
        goto pEp_error;

    decrypt_status = status;
    
    bool imported_private_key_address = false;
    bool has_inner = false;
    bool is_deprecated_key_reset = false;

    if (ptext) { 
        /* we got a plaintext from decryption */
        switch (src->enc_format) {
            
            case PEP_enc_PGP_MIME:
            case PEP_enc_PGP_MIME_Outlook1:
            
                status = mime_decode_message(ptext, psize, &msg, &has_inner);
                if (status != PEP_STATUS_OK)
                    goto pEp_error;
                                
                /* KG: This IS a src modification of old - we're adding to it
                   w/ memhole subject, but the question is whether or not
                   this is OK overall... */
                pull_up_attached_main_msg(msg);
                if (msg->shortmsg) {
                    free(src->shortmsg);
                    src->shortmsg = strdup(msg->shortmsg);                    
                }

                // check for private key in decrypted message attachment while importing
                // N.B. Apparently, we always import private keys into the keyring; however,
                // we do NOT always allow those to be used for encryption. THAT is controlled
                // by setting it as an own identity associated with the key in the DB.
                //
                // We are importing from the decrypted outermost message now.
                //
                free(imported_sender_key_fpr);
                imported_sender_key_fpr = NULL;
                
                stringlist_t** start = (_imported_key_list ? &(stringlist_get_tail(_imported_key_list)->next) : &_imported_key_list);
                // if this is a non-pEp message or a 1.0 message, we'll need to do some default-setting here. 
                // otherwise, we don't ask for a sender import fpr because for pEp 2.0+ any legit default key attachments should 
                // be INSIDE the message 
                status = import_keys_from_decrypted_msg(session, msg, is_pEp_msg,
                                                        &keys_were_imported,
                                                        &imported_private_key_address,
                                                        private_il,
                                                        &_imported_key_list,
                                                        &_changed_keys,
                                                        &imported_sender_key_fpr);

                if (src->from) {
                    if (!is_me(session, src->from)) {

                        /* if decrypted, but not verified... */
                        if (status == PEP_STATUS_OK && decrypt_status == PEP_DECRYPTED) {
                            if (src->from)
                                status = verify_decrypted(session,
                                                          src, msg,
                                                          ptext, psize,
                                                          &_keylist,
                                                          &decrypt_status,
                                                          crypto);
                        }

                        if (status == PEP_STATUS_OK && !has_inner) {
                            // Senders with pEp versions greater than 2.2 will never send us a 2.0 message or less
                            // IF they know we are a pEp user.
                            //
                            // However, they COULD think we're OpenPGP - maybe imported the key from somewhere.
                            //
                            // So we have to only take the key IF the from-2.2-message-version is listed as
                            // 1.0. Everything else we support would have an inner message. And only then
                            // if the sender key has the right name. (FIXME: Have we changed 2.1 to do this?)
                            // FIXME: From SENDER >= 2.2, we should be VERY careful here -- check back on this one
                            //

                            get_message_version_from_headers(src->opt_fields, &msg_major_ver, &msg_minor_ver);

                            const char* key_claim_fpr = NULL;

                            if (decrypt_status == PEP_DECRYPTED_AND_VERIFIED && _imported_key_list) {
                                // This is correct - we require sender key filename to be correct and material to be present in this case from any non-2.2+ version or OpenPGP, and we'll get 1 from 2.2+. Otherwise,
                                // we call shenanigans and don't trust the key to set defaults from.
                                if (imported_sender_key_fpr) {
                                    key_claim_fpr = process_key_claim(src, imported_sender_key_fpr,
                                                                      _imported_key_list->value, 1, 0,
                                                                      _imported_key_list, true);
                                }
                                else {
                                    bool is_only_key = *start && !EMPTYSTR((*start)->value) && !((*start)->next);
                                    if (header_key_imported || is_only_key) {
                                        stringlist_t *claim_node = header_key_imported ? _imported_key_list : *start;
                                        key_claim_fpr = process_key_claim(src, NULL,
                                                                          claim_node ? claim_node->value : NULL,
                                                                          0, 0,
                                                                          _imported_key_list, false);
                                    }
                                }
                            }
                            if (!EMPTYSTR(key_claim_fpr))
                                status = _check_and_set_default_key(session, src->from, key_claim_fpr);


                            free(imported_sender_key_fpr);
                            imported_sender_key_fpr = NULL;

                            if (status == PEP_OUT_OF_MEMORY)
                                goto enomem;
                        } // else, it needs to get set from INNER keys.
                    }
                }

                if (status != PEP_STATUS_OK)
                    goto pEp_error;            

                break;

            case PEP_enc_inline:
            case PEP_enc_inline_EA:
            {
                status = PEP_STATUS_OK;
                _decrypt_in_pieces_status = _decrypt_in_pieces(session, src, &msg, ptext, psize);
            
                switch (_decrypt_in_pieces_status) {
                    case PEP_DECRYPTED:
                    case PEP_DECRYPTED_AND_VERIFIED:
                        if (decrypt_status <= PEP_DECRYPTED_AND_VERIFIED)
                            decrypt_status = MIN(decrypt_status, _decrypt_in_pieces_status);
                        break;
                    case PEP_STATUS_OK:
                        break;    
                    case PEP_OUT_OF_MEMORY:
                        goto enomem;
                    default:
                        decrypt_status = _decrypt_in_pieces_status;
                }

                if (src->enc_format == PEP_enc_inline_EA && msg->longmsg && msg->longmsg[0] == 0) {
                    char *value;
                    size_t size;
                    char *mime_type;
                    const char *filename = NULL;
                    status = decode_internal(ptext, psize, &value, &size, &mime_type);
                    if (status)
                        goto pEp_error;
                    if (strcasecmp(mime_type, "application/pEp.sync") == 0)
                        filename = "file://sync.pEp";
                    else if (strcasecmp(mime_type, "application/pEp.distribution") == 0)
                        filename = "file://distribution.pEp";
                    else if (strcasecmp(mime_type, "application/pgp-keys") == 0)
                        filename = "file://sender_key.asc";
                    else if (strcasecmp(mime_type, "application/pgp-signature") == 0)
                        filename = "file://electronic_signature.asc";
                    bloblist_t *bl = new_bloblist(value, size, mime_type, filename);
                    free(mime_type);
                    if (bl) {
                        msg->attachments = bl;
                        if (msg->longmsg != ptext)
                            free(msg->longmsg);
                        msg->longmsg = NULL;
                        free(ptext);
                        ptext = NULL;
                        psize = 0;
                    }
                    else {
                        free(value);
                        status = PEP_OUT_OF_MEMORY;
                        goto pEp_error;
                    }
                }
                                                        
                // Duplicate code from above - factor out
                free(imported_sender_key_fpr);
                imported_sender_key_fpr = NULL;
                
                stringlist_t** start = (_imported_key_list ? &(stringlist_get_tail(_imported_key_list)->next) : &_imported_key_list);
                // if this is a non-pEp message or a 1.0 message, we'll need to do some default-setting here. 
                // otherwise, we don't ask for a sender import fpr because for pEp 2.0+ any legit default key attachments should 
                // be INSIDE the message 
                status = import_keys_from_decrypted_msg(session, msg,
                                                        is_pEp_msg, &keys_were_imported, 
                                                        &imported_private_key_address,
                                                        private_il,
                                                        &_imported_key_list, 
                                                        &_changed_keys,
                                                        &imported_sender_key_fpr);

                const char* key_claim_fpr = NULL;

                if (decrypt_status == PEP_DECRYPTED_AND_VERIFIED && _imported_key_list) {
                    bool filename_matched = !EMPTYSTR(imported_sender_key_fpr);
                    key_claim_fpr = process_key_claim(src, imported_sender_key_fpr,
                                                      _imported_key_list->value,
                                                      filename_matched ? 1 : 0, 0, // Not as redundant as you think
                                                      filename_matched ? _imported_key_list : *start,
                                                      filename_matched);
                }

                if (!EMPTYSTR(key_claim_fpr))
                    status = _check_and_set_default_key(session, src->from, key_claim_fpr);

                if (_keylist) {
                    if (!EMPTYSTR(_keylist->value))
                        msg->_sender_fpr = strdup(_keylist->value); // will be checked against sender info later
                }
                break;

            default:
                // BUG: must implement more
                NOT_IMPLEMENTED
            }
        }

        if (status == PEP_OUT_OF_MEMORY)
            goto enomem;
            
        if (status != PEP_STATUS_OK)
            goto pEp_error;

        if (decrypt_status == PEP_DECRYPTED || decrypt_status == PEP_DECRYPTED_AND_VERIFIED || 
            decrypt_status == PEP_VERIFY_SIGNER_KEY_REVOKED) {
            char* wrap_info = NULL;
            
            if (!has_inner) {
                status = unencapsulate_hidden_fields(src, msg, &wrap_info);
                if (status == PEP_OUT_OF_MEMORY)
                    goto enomem;                
                if (status != PEP_STATUS_OK)
                    goto pEp_error;
            }        

//            bool is_transport_wrapper = false;
            
        
            // FIXME: replace with enums, check status
            if (has_inner || wrap_info) { // Given that only wrap_info OUTER happens as of the end of wrap_info use, we don't need to strcmp it
                message* inner_message = NULL;
                    
                // For a wrapped message, this is ALWAYS the second attachment; the 
                // mime tree is:
                // multipart/mixed
                //     |
                //     |----- text/plain 
                //     |----- message/rfc822
                //     |----- ...
                //
                // We leave this in below, but once we're rid of 2.0 format,
                // we can dispense with the loop, as has_inner -> 1st message struct attachment is message/rfc822
                //                   

                bloblist_t* message_blob = msg->attachments;
                                    
                if (msg->attachments) {
                    message_blob = msg->attachments;
                    if (!has_inner && strcmp(message_blob->mime_type, "message/rfc822") != 0
                                   && strcmp(message_blob->mime_type, "text/rfc822") != 0)
                        message_blob = NULL;
                }
                    
                if (!message_blob) {
                    bloblist_t* actual_message = msg->attachments;
                
                    while (actual_message) {
                        char* mime_type = actual_message->mime_type;
                        if (mime_type) {
                        
                            // libetpan appears to change the mime_type on this one.
                            // *growl*
                            if (strcmp("message/rfc822", mime_type) == 0 ||
                                strcmp("text/rfc822", mime_type) == 0) {
                                message_blob = actual_message;
                                break;
                            }
                        }
                        actual_message = actual_message->next;
                    }        
                }    
                if (message_blob) {
                    status = mime_decode_message(message_blob->value, 
                                                 message_blob->size, 
                                                 &inner_message,
                                                 NULL);
                    if (status != PEP_STATUS_OK)
                        goto pEp_error;
                                
                    if (inner_message) {

                        // Ok, so IF there is a src->from->username here, we need to be sure to cache the right one
                        // for later.
                        if (src->from && src->from->username && !is_me(session, src->from)) {
                            free(input_from_username);
                            input_from_username = NULL;
                            if (!EMPTYSTR(src->from->username))
                                input_from_username = strdup(src->from->username);
                        }
                        is_pEp_msg = is_a_pEpmessage(inner_message);
                        
                        // Though this will strip any message info on the
                        // attachment, this is safe, as we do not
                        // produce more than one attachment-as-message,
                        // and those are the only ones with such info.
                        // Since we capture the information, this is ok.
                        wrap_info = NULL;
                        inner_message->enc_format = src->enc_format;

                        // const stringpair_list_t* pEp_protocol_version = NULL;
                        // pEp_protocol_version = stringpair_list_find(inner_message->opt_fields, "X-pEp-Version");
                        
                        // if (pEp_protocol_version && pEp_protocol_version->value)
                        //     pEp_version_major_minor(pEp_protocol_version->value->value, &major_ver, &minor_ver);
                        get_protocol_version_from_headers(inner_message->opt_fields, &major_ver, &minor_ver);   
                        if (major_ver > 2 || (major_ver == 2 && minor_ver > 1)) 
                            get_message_version_from_headers(inner_message->opt_fields, &msg_major_ver, &msg_minor_ver);
                            
                        // Sort out pEp user status and version number based on INNER message.
                        
                        bool is_inner = false;

                        // Deal with plaintext modification in 2.0 messages
                        status = unencapsulate_hidden_fields(inner_message, NULL, &wrap_info);   
                        
                        if (status == PEP_OUT_OF_MEMORY)
                            goto enomem;                
                        if (status != PEP_STATUS_OK)
                            goto pEp_error;                                         
                            
                        // Crap - this is broken. Ok. Work this through.
                        // Any client 2.1 or above could send a 2.0 or 2.1 message.
                        // A 2.0 client can only send a 2.0 message here.
                        // So first off: if not 2.2 or greater, infer version:
                        if (major_ver == 2 && minor_ver < 2) {
                            stringpair_list_t* searched = stringpair_list_find(inner_message->opt_fields, X_PEP_MSG_WRAP_KEY);
                            if (searched) {
                                // 2.1 message
                                msg_major_ver = 2;
                                msg_minor_ver = 1;
                            }
                            else if (wrap_info) {
                                msg_major_ver = 2;
                                msg_minor_ver = 0;
                            }
                            else {
                                breaks_protocol = true;
                            }
                        } // else msg_major/minor_ver must have been set.
                        
                        // Ok, this is actually tricky. Normally, we want to look at the message version. But because
                        // We are here, allegedly, on a 2.0+ message, if it was issued by a 2.1+ partner, it will still have 
                        // X-pEp-Sender-FPR on it and we should take that! So we need to do this carefully and distinguish between 
                        // things that vary here based on the SENDER'S client information (with the caveat that the format they are
                        // producing is 2.0 or greater because we're in this logical branch) and the things that vary based upon 
                        // what version of the client the sender thinks we have here.

                        // So first, let's grab a sender fpr if we have one. That depends on the sender'd CLIENT version.
                        if (major_ver > 2 || (major_ver == 2 && minor_ver > 0)) {
                            stringpair_list_t* searched = stringpair_list_find(inner_message->opt_fields, "X-pEp-Sender-FPR");                             
                            inner_message->_sender_fpr = ((searched && searched->value && searched->value->value) ? strdup(searched->value->value) : NULL);
                        }

                        // Ok, now get the message wrapping info
                        if (msg_major_ver > 2 || (msg_major_ver == 2 && msg_minor_ver > 0)) {
                            stringpair_list_t* searched = stringpair_list_find(inner_message->opt_fields, X_PEP_MSG_WRAP_KEY);
                            if (searched && searched->value && searched->value->value) {
                                is_inner = (strcmp(searched->value->value, "INNER") == 0);
                                // FIXME: This is a mess, but we need to keep backwards compat before refactor
                                is_deprecated_key_reset = (strcmp(searched->value->value, "KEY_RESET") == 0);
                                if (is_inner || (is_deprecated_key_reset && (major_ver != 2 || minor_ver != 1))) {
                                    is_deprecated_key_reset = false;
                                    is_inner = true; // I know this is messy, just trust me... this goes out in the refactor
                                }
                                if (is_inner || is_deprecated_key_reset)
                                    inner_message->opt_fields = stringpair_list_delete_by_key(inner_message->opt_fields, X_PEP_MSG_WRAP_KEY);
                            }
                        }
                        else if (wrap_info && msg_major_ver == 2 && msg_minor_ver == 0) {
                            is_inner = (strcmp(wrap_info, "INNER") == 0);
                            if (!is_inner)
                                is_deprecated_key_reset = (strcmp(wrap_info, "KEY_RESET") == 0);
                        }                      

                        // check for private key in decrypted message attachment while importing
                        // N.B. Apparently, we always import private keys into the keyring; however,
                        // we do NOT always allow those to be used for encryption. THAT is controlled
                        // by setting it as an own identity associated with the key in the DB.
                        
                        // If we have a message 2.x message, we are ONLY going to act on keys
                        // we imported from THIS part of the message.
                                                        
                        bool ignore_msg = false;
                            
                        if (is_deprecated_key_reset) {
                            if (decrypt_status == PEP_VERIFY_SIGNER_KEY_REVOKED)
                                ignore_msg = true;
                            else if (inner_message->_sender_fpr) {
                                bool sender_key_is_me = false;
                                status = is_own_key(session, inner_message->_sender_fpr, &sender_key_is_me);
                                if (status != PEP_STATUS_OK && status != PEP_KEY_NOT_FOUND)
                                    goto pEp_error;
                                
                                if (sender_key_is_me) {    
                                    bool grouped = false;
                                    status = deviceGrouped(session, &grouped);
                                    
                                    if (status != PEP_STATUS_OK)
                                        goto pEp_error;
                                    
                                    if (!grouped)
                                        ignore_msg = true;    
                                }
                            }
                            else
                                ignore_msg = true;    
                        }

                        if (!ignore_msg) {
                            imported_private_key_address = false;
                            free(private_il); 
                            private_il = NULL;

                            // Generally imported from the outer decryption - inner messages lie along side it in the message.
                            // So should we always pass NULL here? Probably. FIXME.
                            // import keys from decrypted INNER source
                            status = import_keys_from_decrypted_msg(session, inner_message, is_pEp_msg,
                                                                    &keys_were_imported,
                                                                    &imported_private_key_address,
                                                                    private_il,
                                                                    &_imported_key_list, 
                                                                    &_changed_keys,
                                                                    EMPTYSTR(imported_sender_key_fpr) ? &imported_sender_key_fpr : NULL);

                            if (status != PEP_STATUS_OK)
                                goto pEp_error;            

                            // Set default?
                            if (!breaks_protocol && inner_message->from && !is_me(session, inner_message->from) && _imported_key_list) {
                                // We don't consider the pEp 2.0 case anymore, so no special processing
                                const char* key_claim_fpr = process_key_claim(inner_message, imported_sender_key_fpr,
                                                                              _imported_key_list->value, msg_major_ver, msg_minor_ver,
                                                                              NULL, true);


                                status = _check_and_set_default_key(session, inner_message->from, key_claim_fpr);
                                if (status == PEP_OUT_OF_MEMORY)
                                    goto enomem;
                            }   
                        }
                        if (is_deprecated_key_reset) {
                            if (decrypt_status == PEP_DECRYPTED || decrypt_status == PEP_DECRYPTED_AND_VERIFIED) {
                                if (!ignore_msg) {  
                                    status = receive_key_reset(session,
                                                            inner_message);
                                    if (status != PEP_STATUS_OK) {
                                        free_message(inner_message);
                                        goto pEp_error;
                                    }
                                }    
                                *flags |= PEP_decrypt_flag_consume;
                                calculated_src = msg = inner_message;                                    
                            }
                        }
                        else if (is_inner || breaks_protocol) {

                            // THIS is our message
                            // Now, let's make sure we've copied in 
                            // any information sent in by the app if
                            // needed...
                            reconcile_src_and_inner_messages(src, inner_message);
                            
                            // FIXME: free msg, but check references
                            //src = msg = inner_message;
                            calculated_src = msg = inner_message;
                            
                        }
                        else { // should never happen
                            status = PEP_UNKNOWN_ERROR;
                            free_message(inner_message);
                            goto pEp_error;
                        }
                        inner_message->enc_format = PEP_enc_none;
                    }
                    else { // forwarded message, leave it alone
                        free_message(inner_message);
                    }
                } // end if (message_blob)
            } // end if (has_inner || wrap_info)
            else {
                // this we do if this isn't an inner message
                if (_keylist && !EMPTYSTR(_keylist->value)) {
                    msg->_sender_fpr = strdup(_keylist->value);
                }
            }

            pEp_identity* msg_from = msg->from;
            if (msg_from && !EMPTYSTR(msg_from->address)) {
                if (!is_me(session, msg_from)) {
                    status = update_identity(session, msg_from);
                    if (status == PEP_CANNOT_FIND_IDENTITY) {
                        msg_from->user_id = calloc(1, strlen(msg_from->address) + 6);
                        if (!msg_from->user_id)
                            return PEP_OUT_OF_MEMORY;
                        snprintf(msg_from->user_id, strlen(msg_from->address) + 6,
                                 "TOFU_%s", msg_from->address);        
                        status = PEP_STATUS_OK;
                    }
                }
                else {
                    // update the own from identity, read_only, but preserve username 
                    // for returned message.
                    char* cached_ownname = msg_from->username;
                    // Shouldn't be possible, but just in case.
                    if (!cached_ownname)
                        cached_ownname = strdup(msg_from->address);
                    msg_from->username = NULL;
                    
                    // Don't renew for now: FIXME, SWIFT ticket coming with one To: etc...
                    status = _myself(session, msg_from, false, false, false, myself_read_only);
                    if (PASS_ERROR(status))
                        goto pEp_error;
                        
                    free(msg_from->username);
                    msg_from->username = cached_ownname;
                }    
            }                                                                        
        } // end if (decrypt_status == PEP_DECRYPTED || decrypt_status == PEP_DECRYPTED_AND_VERIFIED)
        
        *rating = decrypt_rating(decrypt_status);

        // Now, if:
        // 1. Message was signed and verified,
        // 2. Message was signed with from user's *default* key (which may
        //    have been set above, and
        // 3. This is a pEp message,
        // We can upgrade the user to being a pEp user. But we should actually check if this is necessary to begin
        // with.
        // Checks on fpr viability are done in the update_sender_to_pEp_trust function now.
        if (msg && decrypt_status == PEP_DECRYPTED_AND_VERIFIED && !is_deprecated_key_reset && !EMPTYSTR(msg->_sender_fpr)) {
            if (is_pEp_msg && msg->from && !EMPTYSTR(msg->from->user_id)) {
                bool pEp_peep = false;
                status = is_pEp_user(session, msg->from, &pEp_peep);
                if (status == PEP_STATUS_OK && !pEp_peep)
                    status = update_sender_to_pEp_trust(session, msg, _keylist, major_ver, minor_ver);
            }
        }


        /* Ok, now we have a keylist used for decryption/verification.
           now we need to update the message rating with the 
           sender and recipients in mind */
        if (!is_deprecated_key_reset) { // key reset messages invalidate some of the ratings in the DB by now.
            status = amend_rating_according_to_sender_and_recipients(session,
                     rating, msg->from, _keylist);
            if (status != PEP_STATUS_OK)
                goto pEp_error;
         
        }

        // Ok, one last thing - if the message didn't follow the protocol, amend rating again.  
        if (breaks_protocol) {
            if (*rating > PEP_rating_b0rken)
                *rating = PEP_rating_b0rken;
        }           
        
        /* We decrypted ok, hallelujah. */
        msg->enc_format = PEP_enc_none;    
    } 
    else {
        // We did not get a plaintext out of the decryption process.
        // Abort and return error.
        *rating = decrypt_rating(decrypt_status);
        goto pEp_error;
    }

    /* 
       Ok, at this point, we know we have a reliably decrypted message.
       Prepare the output message for return.
    */

    // 1. Check to see if this message is to us and contains an own key imported 
    // from own trusted message
    if (*rating >= PEP_rating_trusted && imported_private_key_address) {

        if (msg && msg->to && msg->to->ident) {            
            // This will only happen rarely, so we can do this.
            PEP_STATUS _tmp_status = PEP_STATUS_OK;
            
            if (!is_me(session, msg->to->ident))
                _tmp_status = update_identity(session, msg->to->ident);
            
            if (_tmp_status == PEP_STATUS_OK && is_me(session, msg->to->ident)) {
                // flag it as such
                *flags |= PEP_decrypt_flag_own_private_key;
            }
        }
    }

    // 2. Clean up message and prepare for return 
    if (msg) {
        if (_keylist && _keylist->next)
            dedup_stringlist(_keylist->next);
            
        /* add pEp-related status flags to header */
        if (src->recv_by) {
            free_identity(msg->recv_by);
            msg->recv_by = identity_dup(src->recv_by);
            if (!msg->recv_by)
                goto enomem;
        }

        // Maybe unnecessary
        // if (keys_were_imported)
        //     remove_attached_keys(msg);
                    
        if (calculated_src->id && calculated_src != msg) {
            msg->id = strdup(calculated_src->id);
            assert(msg->id);
            if (msg->id == NULL)
                goto enomem;
        }
    } // End prepare output message for return

    // 3. Check to see if the sender is a pEp user who used any of our revoked keys
    //
    if (msg && msg->from && !is_me(session, msg->from)) {
        bool pEp_peep = false;

        if (!EMPTYSTR(msg->from->user_id)) {
            status = is_pEp_user(session, msg->from, &pEp_peep);
            
            // If it's a pEp user, check if there was a revoked key used so we can notify
            if (pEp_peep) {
                status = check_for_own_revoked_key(session, _keylist, &revoke_replace_pairs);

                if (status != PEP_STATUS_OK) {
                    // This should really never choke unless the DB is broken.
                    status = PEP_UNKNOWN_DB_ERROR;
                    goto pEp_error;
                }
                
                if (msg) {
                    stringpair_list_t* curr_pair_node;
                    stringpair_t* curr_pair;

                    for (curr_pair_node = revoke_replace_pairs; curr_pair_node; curr_pair_node = curr_pair_node->next) {
                        curr_pair = curr_pair_node->value;

                        if (!curr_pair)
                            continue; // Again, shouldn't occur

                        if (curr_pair->key && curr_pair->value) {
                            /* Figure out which address(es) this came to so we know who to reply from */                    

                            identity_list* my_rev_ids = NULL;
                            
                            /* check by replacement ID for identities which used this key? */
                            status = get_identities_by_main_key_id(session, curr_pair->value,
                                                                   &my_rev_ids);
                                                                                                                              
                            if (status == PEP_STATUS_OK && my_rev_ids) {
                                // get identities in this list the message was to/cc'd to (not for bcc)
                                identity_list* used_ids_for_key = NULL;
                                status = ident_list_intersect(my_rev_ids, msg->to, &used_ids_for_key);
                                if (status != PEP_STATUS_OK)
                                    goto pEp_error; // out of memory

                                identity_list* used_cc_ids = NULL;    
                                status = ident_list_intersect(my_rev_ids, msg->cc, &used_cc_ids);
                                if (status != PEP_STATUS_OK)
                                    goto pEp_error;

                                used_ids_for_key = identity_list_join(used_ids_for_key, used_cc_ids);
                                
                                identity_list* curr_recip = used_ids_for_key;

                                // We have all possible recips that use our revoked key.
                                for ( ; curr_recip && curr_recip->ident; curr_recip = curr_recip->next) {
                                    if (!is_me(session, curr_recip->ident))
                                        continue;

                                    // If this is a group identity, we'd better be the manager - otherwise,
                                    // ignore this.
                                    if (curr_recip->ident->flags & PEP_idf_group_ident) {
                                        bool is_my_group = false;
                                        status = is_group_mine(session, curr_recip->ident, &is_my_group);
                                        if (status == PEP_OUT_OF_MEMORY)
                                            goto pEp_error;
                                        else if (status != PEP_STATUS_OK || !is_my_group)
                                            continue;

                                        // Ok, it's my group. Is this from a member, or an outsider?
                                        bool active_member = false;
                                        status = is_active_group_member(session, curr_recip->ident, msg->from, &active_member);
                                        if (active_member) {
                                            pEp_identity* group_ident = curr_recip->ident;

                                            // FIXME: Factor out of send_key_reset_to_active_group_members
                                            message* outmsg = NULL;
                                            identity_list* reset_ident_list = new_identity_list(group_ident);
                                            if (!group_ident)
                                                return PEP_OUT_OF_MEMORY;

                                            pEp_identity* manager = NULL;
                                            status = get_group_manager(session, group_ident, &manager);
                                            // FIXME: what kind of error behaviour do we want here?
                                            // It really is an error - we've identified the group as ours,
                                            // so if we can't get the manager, something internal broke.
                                            if (status != PEP_STATUS_OK)
                                                goto pEp_error;
                                            if (!manager) {
                                                status = PEP_UNKNOWN_ERROR;
                                                goto pEp_error;
                                            }

                                            status = generate_own_commandlist_msg(session,
                                                                                  reset_ident_list,
                                                                                  false,
                                                                                  manager,
                                                                                  msg->from,
                                                                                  curr_pair->value,
                                                                                  &outmsg);

                                            if (status != PEP_STATUS_OK) // FIXME: mem
                                                goto pEp_error;

                                            if (outmsg) {

                                                message* enc_group_reset_msg = NULL;

                                                // encrypt this baby and get out
                                                // extra keys???
                                                status = encrypt_message(session, outmsg, NULL, &enc_group_reset_msg, PEP_enc_auto, PEP_encrypt_flag_key_reset_only);

                                                if (status != PEP_STATUS_OK)
                                                    return status;

                                                _add_auto_consume(enc_group_reset_msg);

                                                // insert into queue
                                                if (session->messageToSend)
                                                    status = session->messageToSend(enc_group_reset_msg);
                                                else
                                                    status = PEP_SYNC_NO_MESSAGE_SEND_CALLBACK;
                                            }
                                            continue;
                                        }
                                        else if (status != PEP_STATUS_OK && status != PEP_NO_MEMBERSHIP_STATUS_FOUND)
                                            goto pEp_error;

                                        // Otherwise, normal reset...
                                    }

                                    status = create_standalone_key_reset_message(session,
                                        &reset_msg,
                                        curr_recip->ident,
                                        msg->from,
                                        curr_pair->key,
                                        curr_pair->value);

                                    // If we can't find the identity, this is someone we've never mailed, so we just
                                    // go on letting them use the wrong key until we mail them ourselves. (Spammers, etc)
                                    if (status != PEP_CANNOT_FIND_IDENTITY) {
                                        if (status != PEP_STATUS_OK)
                                            goto pEp_error;

                                        if (!reset_msg) {
                                            status = PEP_OUT_OF_MEMORY;
                                            goto pEp_error;
                                        }
                                        // insert into queue
                                        if (session->messageToSend)
                                            status = session->messageToSend(reset_msg);
                                        else
                                            status = PEP_SYNC_NO_MESSAGE_SEND_CALLBACK;


                                        if (status == PEP_STATUS_OK) {
                                            // Put into notified DB
                                            status = set_reset_contact_notified(session, curr_recip->ident->address, curr_pair->key, msg->from->user_id);
                                            if (status != PEP_STATUS_OK) // It's ok to barf because it's a DB problem??
                                                goto pEp_error;
                                        }
                                        else {
                                            // According to Volker, this would only be a fatal error, so...
                                            free_message(reset_msg); // ??
                                            reset_msg = NULL; // ??
                                            goto pEp_error;
                                        }
                                    }
                                }    
                            } // else we couldn't find an ident for replacement key    
                        }
                    }        
                }
            }
        }    
        free_stringpair_list(revoke_replace_pairs);
        revoke_replace_pairs = NULL;
    } // end !is_me(msg->from)    

    // 4. Reencrypt if necessary
    bool reenc_signer_key_is_own_key = false; // only matters for reencrypted messages

    bool has_extra_keys = _have_extrakeys(extra);

    bool subjects_match = false;
    if (src->shortmsg && msg->shortmsg) {
        if (strcmp(src->shortmsg, msg->shortmsg) == 0)
            subjects_match = true;
    }
    else if (src->shortmsg == msg->shortmsg) {
        if (!src->shortmsg) 
            subjects_match = true;    
    }
    
    if (reencrypt && session->unencrypted_subject && !has_extra_keys && subjects_match) 
        reencrypt = false;


    if (reencrypt) {
        if (decrypt_status == PEP_DECRYPTED || decrypt_status == PEP_DECRYPTED_AND_VERIFIED
            || decrypt_status == PEP_VERIFY_SIGNER_KEY_REVOKED) {
            const char* sfpr = NULL;
            if (has_extra_keys)
                sfpr = _keylist->value;

            // We only actually reencrypt if the message is 100% safe.
            if (sfpr && decrypt_status == PEP_DECRYPTED_AND_VERIFIED) {
                own_key_is_listed(session, sfpr, &reenc_signer_key_is_own_key);

                bool key_missing = false;

                // Also, see if extra keys are all in the encrypted-to keys; otherwise, we do it again
                if (extra) {
                    stringlist_t* curr_key = NULL;
                    for (curr_key = extra; curr_key && curr_key->value; curr_key = curr_key->next) {
                        const stringlist_t* found = stringlist_search(_keylist, curr_key->value);
                        if (!found) {
                            key_missing = true;
                            break;
                        }
                    }
                }

                // Reencrypt if not signed by us, or there was a key missing from us/extra keys or if we keep subjects
                // unencrypted and they don't match on inner/outer (?)
                if (key_missing || (!reenc_signer_key_is_own_key) || ((!subjects_match) && session->unencrypted_subject)) {
                    message* reencrypt_msg = NULL;
                    PEP_STATUS reencrypt_status = PEP_CANNOT_REENCRYPT;

                    if (src->recv_by && !EMPTYSTR(src->recv_by->address)) {
                        // we've already called myself() on this, so we have a key.
                        if (!EMPTYSTR(src->recv_by->fpr)) {
                            reencrypt_status = encrypt_message_for_self(session, src->recv_by, msg,
                                                                        extra, &reencrypt_msg, PEP_enc_PGP_MIME,
                                                                        PEP_encrypt_reencrypt);
                            if (reencrypt_status != PEP_STATUS_OK)
                                reencrypt_status = PEP_CANNOT_REENCRYPT;
                        }
                    }

                    // This was the initial contents of the keylist**, which we now own.
                    // Keylist is overwritten as an output variable above.
                    free_stringlist(extra);

                    if (reencrypt_status != PEP_CANNOT_REENCRYPT && reencrypt_msg) {
                        // This will reassign pointers and NULL out others and make sure
                        // reencrypt_msg is safe to free, FYI
                        message_transfer(src, reencrypt_msg);
                        *flags |= PEP_decrypt_flag_src_modified;
                        free_message(reencrypt_msg);
                    }
                    else
                        decrypt_status = PEP_CANNOT_REENCRYPT;
                }
            }
            else if (!has_extra_keys && session->unencrypted_subject) { // this is just unencrypted subj.
                free(src->shortmsg);
                src->shortmsg = strdup(msg->shortmsg);
                assert(src->shortmsg);
                if (!src->shortmsg)
                    goto enomem;
                *flags |= PEP_decrypt_flag_src_modified;
            }
        }
    }
    
    // by convention

    if (EMPTYSTR(msg->shortmsg) && EMPTYSTR(msg->longmsg) && EMPTYSTR(msg->longmsg_formatted)) {
        free(msg->shortmsg);
        msg->shortmsg = strdup("pEp");
        assert(msg->shortmsg);
        if (!msg->shortmsg)
            goto enomem;

        if (src->enc_format == PEP_enc_inline_EA) {
            stringpair_t *entry = new_stringpair("pEp-auto-consume", "yes");
            if (!entry)
                goto enomem;
            stringpair_list_t * spl = stringpair_list_add(msg->opt_fields, entry);
            if (!spl)
                goto enomem;
            if (!msg->opt_fields)
                msg->opt_fields = spl;
        }
    }

    // 5. Double-check sender key info

    // Double-check for message 2.1+: (note, we don't do this for already-reencrypted-messages)

    // Rating, so far, is based on the decrypt rating. We need to adjust a little and then update
    // the rating with the function.

    if (!(reencrypt && reenc_signer_key_is_own_key) && rating > PEP_rating_unreliable) {
        // We should now ALWAYS have sender_fpr filled in
        if (!EMPTYSTR(msg->_sender_fpr)) {
            // Is the sender key the signer key? They should be.
            if (!EMPTYSTR(_keylist->value) && (strcasecmp(msg->_sender_fpr, _keylist->value) != 0)) {
                if (decrypt_status == PEP_DECRYPTED_AND_VERIFIED)
                    decrypt_status = PEP_DECRYPTED;
                *rating = PEP_rating_unreliable;
            }
//            else {
//                const pEp_identity *msg_from = msg->from;
//                const char *sender_user_id = msg_from->user_id;
//                if (*rating > PEP_rating_unreliable) {
//                    if (msg_from->fpr && strcasecmp(msg_from->fpr, msg->_sender_fpr) != 0) {
//                        // check to see if the sender OWNS this key and we have a trust entry
//                        // for it. Otherwise... PROBLEMS.
//                        pEp_identity *temp_from = identity_dup(msg_from);
//                        if (!temp_from)
//                            goto enomem;
//                        free(temp_from->fpr);
//                        temp_from->fpr = strdup(msg->_sender_fpr);
//                        if (!temp_from->fpr)
//                            goto enomem;
//                        status = get_trust(session, temp_from);
//                        if (status == PEP_CANNOT_FIND_IDENTITY) {
//                            if (decrypt_status == PEP_DECRYPTED_AND_VERIFIED)
//                                decrypt_status = PEP_DECRYPTED;
//                            *rating = PEP_rating_unreliable;
//                        }
//                    }
//                }
//            }
// Covered by incoming message rating, I hope.
        }
    }

    // Adjust the incoming message rating? I think we have a problem here with reencrypted messages,
    // but I don't know what vb changed in this branch here...
    status = incoming_message_rating(session, src, msg, _keylist, extra, decrypt_status, rating);

    if (*rating == PEP_rating_have_no_key)
        *rating = PEP_rating_unreliable;

    // 6. Put this stuff on the message
    decorate_message(session, msg, *rating, _keylist, false, true);


    // 7. Set up return values
    *dst = msg;
    *keylist = _keylist;

    if (imported_key_fprs)
        *imported_key_fprs = _imported_key_list;
    if (changed_public_keys)
        *changed_public_keys = _changed_keys;

    // Force-set username?
    if (msg && msg->from && !is_me(session, msg->from) && input_from_username && *rating >= PEP_rating_reliable) {
        // Set it.
        status = force_set_identity_username(session, msg->from, input_from_username);
        // We're gonna ignore this for now - I don't think we should give up returning a decrypted message
        // for this, but FIXME ask fdik
        status = PEP_STATUS_OK;
        free(msg->from->username);
        msg->from->username = input_from_username;
        input_from_username = NULL;
    }
    free(input_from_username); // This was set to NULL in both places ownership could be legitimately grabbed.

    if (decrypt_status == PEP_DECRYPTED_AND_VERIFIED)
        return PEP_STATUS_OK;
    else
        return decrypt_status;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_error:
    free(ptext);
    free_message(msg);
    free_message(reset_msg);
    free_stringlist(_keylist);
    free_stringpair_list(revoke_replace_pairs);
    free(imported_sender_key_fpr);
    free(input_from_username);

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
    assert(session);
    assert(src);
    assert(dst);
    assert(keylist);
    assert(rating);
    assert(flags);

    if (!(session && src && dst && keylist && rating && flags))
        return PEP_ILLEGAL_VALUE;

    if (!(*flags & PEP_decrypt_flag_untrusted_server))
        *keylist = NULL;
        
    stringlist_t* imported_key_fprs = NULL;
    uint64_t changed_key_bitvec = 0;    
        
    PEP_STATUS status = _decrypt_message(session, src, dst, keylist, 
                                         rating, flags, NULL,
                                         &imported_key_fprs, &changed_key_bitvec);

    /*
    if (src->dir == PEP_dir_incoming) {
        PEP_rating rating2;
        PEP_STATUS status2 = incoming_message_rating(session, src, *dst, *keylist, NULL, status, rating);
        assert(status2 != PEP_ILLEGAL_VALUE);
    }
    */
    // This gets done internally anyway. Whyyyyy?

    message *msg = *dst ? *dst : src;

    // Ok, now we check to see if it was an administrative message. We do this by testing base_extract for success
    // with protocol families.
    if (msg && msg->from) {
        size_t size;
        const char *data = NULL;
        char *sender_fpr = NULL;

        PEP_STATUS tmp_status = PEP_UNKNOWN_ERROR; // We start with error because OK means we successfully matched

        if (session->inject_sync_event && !(*flags & PEP_decrypt_flag_dont_trigger_sync)) {
            tmp_status = base_extract_message(session, msg, BASE_SYNC, &size, &data, &sender_fpr);
            if (!tmp_status && size && data) {
                if (sender_fpr)
                    signal_Sync_message(session, *rating, data, size, msg->from, sender_fpr);
                  // FIXME: this must be changed to sender_fpr
                else if (*keylist)
                    signal_Sync_message(session, *rating, data, size, msg->from, (*keylist)->value);
            }
        }
        if (tmp_status != PEP_STATUS_OK) {
            // We process key resets differently in other versions and won't get these kind of resets
            // until this min version anyway, so:
            if (msg && msg->opt_fields) {
                const stringpair_list_t *pEp_protocol_version = NULL;
                unsigned int major_ver = 0;
                unsigned int minor_ver = 0;
                pEp_protocol_version = stringpair_list_find(msg->opt_fields, "X-pEp-Version");
                if (pEp_protocol_version && pEp_protocol_version->value)
                    pEp_version_major_minor(pEp_protocol_version->value->value, &major_ver, &minor_ver);
                if (major_ver > 2 || (major_ver == 2 && minor_ver > 1)) {
                    // Try the rest
                    PEP_STATUS tmpstatus = base_extract_message(session, msg, BASE_DISTRIBUTION, &size, &data,
                                                                &sender_fpr);
                    if (!tmpstatus && size && data) {
                        process_Distribution_message(session, msg, *rating, data, size, sender_fpr);
                    }
                }
            }
        }
        free(sender_fpr);
    }

    // Removed for now - partial fix in ENGINE-647, but we have sync issues. Need to 
    // fix testing issue.
    //
    // if (status == PEP_UNENCRYPTED || status == PEP_DECRYPTED_AND_VERIFIED) {
    //     if (session->inject_sync_event && msg && msg->from &&
    //             !(*flags & PEP_decrypt_flag_dont_trigger_sync)) {
    //         size_t size;
    //         const char *data;
    //         char *sender_fpr = NULL;
    // 
    //         PEP_STATUS tmpstatus = base_extract_message(session, msg, &size, &data, &sender_fpr);
    //         if (!tmpstatus && size && data) {
    //             bool use_extracted_fpr = (status != PEP_DECRYPTED_AND_VERIFIED) ||
    //                                       !dst || !(*dst) || !((*dst)->_sender_fpr);
    // 
    //             const char* event_sender_fpr = (use_extracted_fpr ? sender_fpr : (*dst)->_sender_fpr);
    //             // FIXME - I don't think this is OK anymore. We either have a signed beacon or a properly encrypted/signed 2.1 message
    //             // if ((!event_sender_fpr) && *keylist)
    //             //     event_sender_fpr = (*keylist)->value;
    //             if (event_sender_fpr)
    //                 signal_Sync_message(session, *rating, data, size, msg->from, event_sender_fpr);
    //         }
    //         free(sender_fpr);
    //     }

    free(imported_key_fprs);
    return status;
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
    PEP_decrypt_flags_t flags = PEP_decrypt_flag_dont_trigger_sync;

    *ident = NULL;

    identity_list *private_il = NULL;
    PEP_STATUS status = _decrypt_message(session, msg,  &dst, 
                                         &keylist, &rating, 
                                         &flags, &private_il,
                                         NULL, NULL); // FIXME - what do we do here? 
                                                      // I don't think we'd call this if this were still here
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

// CAN return PASSPHRASE errors on own keys because 
// of myself. Will not, however, return PASSPHRASE 
// errors if the incoming ident isn't marked as an own 
// identity.
// FIXME: document at top level - we RELY on knowing 
//        if this is an own identity in the input
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

    *rating = PEP_rating_undefined;

    if (ident->me)
        status = _myself(session, ident, false, true, true, true);
    else
        status = update_identity(session, ident);

    if (status == PEP_STATUS_OK)
        *rating = rating_from_comm_type(ident->comm_type);

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
/**
 *  @internal
 *
 *  <!--       asciihex_to_num()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    a        char
 *
 */
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

/**
 *  @internal
 *
 *  <!--       num_to_asciihex()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    h        short
 *
 */
static char num_to_asciihex(short h) {
    if (h < 0 || h > 16)
        return '\0';
    if (h < 10)
        return (char)(h + 0x30);
    return (char)((h - 10) + 0x41); // for readability
}

/**
 *  @internal
 *
 *  <!--       xor_hex_chars()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    a        char
 *  @param[in]    b        char
 *
 */
static char xor_hex_chars(char a, char b) {
    short a_num = asciihex_to_num(a);
    short b_num = asciihex_to_num(b);
    if (a_num < 0 || b_num < 0)
        return '\0';
    short xor_num = a_num^b_num;
    return num_to_asciihex(xor_num);
}

/**
 *  @internal
 *
 *  <!--       skip_separators()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *current        constchar
 *  @param[in]    *begin        constchar
 *
 */
static const char* skip_separators(const char* current, const char* begin) {
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

/**
 *  @internal
 *
 *  <!--       check_for_zero_fpr()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *fpr        char
 *
 */
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
    assert(session && id1 && id1->fpr && id2 && id2->fpr&& lang && words &&
            wsize);
    if (!(session && id1 && id1->fpr && id2 && id2->fpr&& lang && words &&
                wsize))
        return PEP_ILLEGAL_VALUE;

    return get_trustwords_for_fprs(session, id1->fpr, id2->fpr, lang, words,
            wsize, full);
}

/**
 *  @internal
 *
 *  <!--       remove_separators()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *str1        const char
 *  @param[in]    *str2        char
 *  @param[in]    str1len        int
 *
 */
static void remove_separators(const char* str1, char* str2, int str1len) {
    int i = 0;
    char* curr_write = str2;
    for ( ; i < str1len; i++) {
        switch (str1[i]) {
            case ' ':
            case '\t':
            case '\r':
            case '\n':
            case '\0':
                continue;
            default:
                *curr_write = str1[i];
                curr_write++;
        }
    }
    *curr_write = '\0';
}

DYNAMIC_API PEP_STATUS get_trustwords_for_fprs(
        PEP_SESSION session, const char* fpr1, const char* fpr2,
        const char* lang, char **words, size_t *wsize, bool full
    )
{
    assert(session && fpr1 && fpr2 && words && wsize);
    if (!(session && fpr1 && fpr2 && words && wsize))
        return PEP_ILLEGAL_VALUE;

    const int SHORT_NUM_TWORDS = 5; 
    PEP_STATUS status = PEP_STATUS_OK;
    
    *words = NULL;    
    *wsize = 0;

    int fpr1_len = strlen(fpr1);
    int fpr2_len = strlen(fpr2);
        
    int max_len = (fpr1_len > fpr2_len ? fpr1_len : fpr2_len);
    
    char* XORed_fpr = (char*)(calloc(max_len + 1, 1));
    *(XORed_fpr + max_len) = '\0';
    char* result_curr = XORed_fpr + max_len - 1;
    const char* fpr1_curr = fpr1 + fpr1_len - 1;
    const char* fpr2_curr = fpr2 + fpr2_len - 1;

    while (fpr1 <= fpr1_curr && fpr2 <= fpr2_curr) {
        fpr1_curr = skip_separators(fpr1_curr, fpr1);
        fpr2_curr = skip_separators(fpr2_curr, fpr2);
        
        if (fpr1_curr < fpr1 || fpr2_curr < fpr2)
            break;
            
        char xor_hex = xor_hex_chars(*fpr1_curr, *fpr2_curr);
        if (xor_hex == '\0') {
            status = PEP_ILLEGAL_VALUE;
            goto error_release;
        }
        
        *result_curr = xor_hex;
        result_curr--; fpr1_curr--; fpr2_curr--;
    }

    const char* remainder_start = NULL;
    const char* remainder_curr = NULL;
    
    if (fpr1 <= fpr1_curr) {
        remainder_start = fpr1;
        remainder_curr = fpr1_curr;
    }
    else if (fpr2 <= fpr2_curr) {
        remainder_start = fpr2;
        remainder_curr = fpr2_curr;
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
    
    if (status == PEP_TRUSTWORDS_DUPLICATE_FPR) {
        remove_separators(fpr1, XORed_fpr, fpr1_len);
        status = PEP_STATUS_OK;
    }
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
    
    char* own_id = NULL;
    status = get_default_own_userid(session, &own_id);

    if (!(status == PEP_STATUS_OK && own_id)) {
        free(own_id);
        return PEP_CANNOT_FIND_IDENTITY;
    }
    
    status = get_identity(session,
                          received_by->address,
                          own_id,
                          &stored_identity);
    free(own_id);
    own_id = NULL;                      

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

/**
 *  @internal
 *
 *  <!--       string_to_rating()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *rating        constchar
 *
 */
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
        return PEP_rating_undefined; // don't use this any more
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

/**
 *  @internal
 *
 *  <!--       string_to_keylist()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *skeylist        constchar
 *  @param[in]    **keylist        stringlist_t
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 */
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

static void remove_sync_message(message *msg)
{
    if (!(msg && msg->attachments))
        return;

    bloblist_t *b = NULL;
    for (bloblist_t *a = msg->attachments; a && a->value ; ) {
        if (a->mime_type && (
                    strcasecmp(a->mime_type, "application/pEp.sync") == 0 ||
                    strcasecmp(a->mime_type, "application/pEp.sign") == 0
                )
           )
        {
            if (b) {
                b->next = a->next;
                a->next = NULL;
                free_bloblist(a);
                a = b->next;
            }
            else {
                msg->attachments = a->next;
                a->next = NULL;
                free_bloblist(a);
                a = msg->attachments;
            }
        }
        else {
            b = a;
            a = a->next;
        }
    }
}

// CAN return PASSPHRASE errors
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
        return PEP_ILLEGAL_VALUE;

    *rating = PEP_rating_undefined;

    if (x_enc_status == PEP_rating_undefined){
        for (stringpair_list_t *i = msg->opt_fields; i && i->value ; i=i->next) {
            if (strcasecmp(i->value->key, "X-EncStatus") == 0){
                x_enc_status = string_to_rating(i->value->value);
                goto got_rating;
            }
        }
        return PEP_ILLEGAL_VALUE;
    }

got_rating:

    _rating = x_enc_status;

    if (_keylist == NULL){
        for (stringpair_list_t *i = msg->opt_fields; i && i->value ; i=i->next) {
            if (strcasecmp(i->value->key, "X-KeyList") == 0){
                status = string_to_keylist(i->value->value, &_keylist);
                if (status != PEP_STATUS_OK)
                    goto pEp_error;
                must_free_keylist = true;
                goto got_keylist;
            }
        }

        // there was no rcpt fpr, it could be an unencrypted mail
        if(_rating == PEP_rating_unencrypted) {
            *rating = _rating;
            return PEP_STATUS_OK;
        }

        return PEP_ILLEGAL_VALUE;
    }
got_keylist:

    if (!is_me(session, msg->from))
        status = update_identity(session, msg->from);
    else
        status = _myself(session, msg->from, false, true, false, true);

    switch (status) {
        case PEP_KEY_NOT_FOUND:
        case PEP_KEY_UNSUITABLE:
        case PEP_CANNOT_FIND_IDENTITY:
        case PEP_CANNOT_FIND_ALIAS:
            status = PEP_STATUS_OK;
        case PEP_STATUS_OK:
            break;
        default:
            goto pEp_error;
    }

    status = amend_rating_according_to_sender_and_recipients(session, &_rating,
             msg->from, _keylist);
    if (status == PEP_STATUS_OK) {
        remove_sync_message(msg);
        set_receiverRating(session, msg, _rating);
        *rating = _rating;
    }

pEp_error:
    if (must_free_keylist)
        free_stringlist(_keylist);

    return status;
}

DYNAMIC_API PEP_STATUS get_key_rating_for_user(
        PEP_SESSION session,
        const char *user_id,
        const char *fpr,
        PEP_rating *rating
    )
{
    assert(session && user_id && user_id[0] && fpr && fpr[0] && rating);
    if (!(session && user_id && user_id[0] && fpr && fpr[0] && rating))
        return PEP_ILLEGAL_VALUE;

    *rating = PEP_rating_undefined;

    pEp_identity *ident = new_identity(NULL, fpr, user_id, NULL);
    if (!ident)
        return PEP_OUT_OF_MEMORY;

    PEP_STATUS status = get_trust(session, ident);
    if (status)
        goto the_end;

    if (!ident->comm_type) {
        status = PEP_RECORD_NOT_FOUND;
        goto the_end;
    }

    *rating = rating_from_comm_type(ident->comm_type);

the_end:
    free_identity(ident);
    return status;
}

PEP_STATUS try_encrypt_message(
        PEP_SESSION session,
        message *src,
        stringlist_t *extra,
        message **dst,
        PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session && session->messageToSend && session->notifyHandshake);
    assert(src && src->from);
    assert(dst);

    if (!(session && session->messageToSend && session->notifyHandshake && src
                && src->from && dst))
        return PEP_ILLEGAL_VALUE;

    if (src->dir == PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;

    // https://dev.pep.foundation/Engine/MessageToSendPassphrase

    // first try with empty passphrase
    char* passphrase = session->curr_passphrase;
    session->curr_passphrase = NULL;
    status = encrypt_message(session, src, extra, dst, enc_format, flags);
    session->curr_passphrase = passphrase;
    if (!(status == PEP_PASSPHRASE_REQUIRED || status == PEP_WRONG_PASSPHRASE))
        return status;

    if (!EMPTYSTR(session->curr_passphrase)) {
        // try configured passphrase
        status = encrypt_message(session, src, extra, dst, enc_format, flags);
        if (!(status == PEP_PASSPHRASE_REQUIRED || status == PEP_WRONG_PASSPHRASE))
            return status;
    }

    do {
        // then try passphrases from the cache
        status = session->messageToSend(NULL);

        // if there will be no passphrase then exit
        if (status == PEP_SYNC_NO_CHANNEL)
            break;

        // if a passphrase is needed ask the app
        if (status == PEP_PASSPHRASE_REQUIRED || status == PEP_WRONG_PASSPHRASE) {
            pEp_identity* _me = identity_dup(src->from);
            if (!_me)
                return PEP_OUT_OF_MEMORY;
            session->notifyHandshake(_me, NULL, SYNC_PASSPHRASE_REQUIRED);
        }
        else if (status == PEP_STATUS_OK) {
            status = encrypt_message(session, src, extra, dst, enc_format, flags);
        }
    } while (status == PEP_PASSPHRASE_REQUIRED || status == PEP_WRONG_PASSPHRASE);

    return status;
}

PEP_STATUS update_identity_list(PEP_SESSION session, identity_list* idents) {
    PEP_STATUS status = PEP_STATUS_OK;
    if (idents) {
        identity_list* il = idents;
        for ( ; il && il->ident; il = il->next) {
            if (is_me(session, il->ident))
                status = myself(session, il->ident);
            else
                status = update_identity(session, il->ident);
        }
    }
    return status;
}

PEP_STATUS update_message_identities(PEP_SESSION session, message* msg) {
    PEP_STATUS status = PEP_STATUS_OK;

    if (msg->from) {
        if (is_me(session, msg->from))
            status = myself(session, msg->from);
        else
            status = update_identity(session, msg->from);
    }
    if (status == PEP_STATUS_OK) {
        status = update_identity_list(session, msg->to);
    }
    if (status == PEP_STATUS_OK) {
        status = update_identity_list(session, msg->cc);
    }
    if (status == PEP_STATUS_OK) {
        status = update_identity_list(session, msg->bcc);
    }
    return status;
}
