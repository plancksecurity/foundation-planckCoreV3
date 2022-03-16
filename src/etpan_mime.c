/**
 * @file    etpan_mime.c 
 * @brief   File description for doxygen missing. FIXME
 * @license GNU General Public License 3.0 - see LICENSE.txt
*/

#include "etpan_mime.h"
#ifndef mailmime_param_new_with_data
#include <libetpan/mailprivacy_tools.h>
#endif

#include "pEp_internal.h"
#include "platform.h"
#include "mime.h"
#include "wrappers.h"
#include "resource_id.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#define MAX_MESSAGE_ID 128

#define MAX_IMF_LINE_LEN 998

static bool ascii_exceeds_line_length(const char* data, size_t size) {

    const char* curr_pos = data;
    const char* last_pos = data;
    const char* end_pos = data + size;
    const char* crlf = "\r\n";

    while ((curr_pos + MAX_IMF_LINE_LEN) < end_pos) {
        last_pos = curr_pos;
        curr_pos = strnstr(curr_pos, crlf, end_pos - curr_pos);
        if (!curr_pos)
            return true;
        if (curr_pos - last_pos > MAX_IMF_LINE_LEN)
            return true;
        curr_pos += 2;
    }

    return false;
}

/**
 *  @internal
 *  
 *  <!--       generate_boundary()       -->
 *  
 *  @brief            TODO
 *  
 *  
 */

static char * generate_boundary(void)
{
    char id[MAX_MESSAGE_ID];

    // no cryptographically strong random needed here
    const long value1 = random();
    const long value2 = random();
    const long value3 = random();
    const long value4 = random();

    snprintf(id, MAX_MESSAGE_ID, "%.4lx%.4lx%.4lx%.4lx", value1, value2,
            value3, value4);
    
    return strdup(id);
}

struct mailmime * part_new_empty(
        struct mailmime_content * content,
        struct mailmime_fields * mime_fields,
        stringpair_list_t* param_keyvals,
        int force_single
    )
{
    struct mailmime * build_info;
    clist * list = NULL;
    int r;
    int mime_type;
    char * attr_name = NULL;
    char * attr_value = NULL;
    struct mailmime_parameter * param = NULL;
    clist * parameters = NULL;
    char *boundary = NULL;

    list = NULL;

    if (force_single) {
        mime_type = MAILMIME_SINGLE;
    }
    else {
        switch (content->ct_type->tp_type) {
            case MAILMIME_TYPE_DISCRETE_TYPE:
                mime_type = MAILMIME_SINGLE;
                break;

            case MAILMIME_TYPE_COMPOSITE_TYPE:
                switch (content->ct_type->tp_data.tp_composite_type->ct_type) {
                    case MAILMIME_COMPOSITE_TYPE_MULTIPART:
                        mime_type = MAILMIME_MULTIPLE;
                        break;

                    case MAILMIME_COMPOSITE_TYPE_MESSAGE:
                        if (strcasecmp(content->ct_subtype, "rfc822") == 0)
                            mime_type = MAILMIME_MESSAGE;
                        else
                            mime_type = MAILMIME_SINGLE;
                        break;

                    default:
                        goto enomem;
                }
                break;

            default:
                goto enomem;
        }
    }

    if (mime_type == MAILMIME_MULTIPLE) {
        list = clist_new();
        assert(list);
        if (list == NULL)
            goto enomem;

        attr_name = strdup("boundary");
        assert(attr_name);
        if (attr_name == NULL)
            goto enomem;

        boundary = generate_boundary();
        assert(boundary);
        attr_value = boundary;
        if (attr_value == NULL)
            goto enomem;

        param = mailmime_parameter_new(attr_name, attr_value);
        assert(param);
        if (param == NULL)
            goto enomem;
        attr_name = NULL;
        attr_value = NULL;

        if (content->ct_parameters == NULL) {
            parameters = clist_new();
            assert(parameters);
            if (parameters == NULL)
                goto enomem;
        }
        else {
            parameters = content->ct_parameters;
        }

        r = clist_append(parameters, param);
        if (r)
            goto enomem;
        param = NULL;

        if (content->ct_parameters == NULL)
            content->ct_parameters = parameters;
    }
    
    if (param_keyvals) {
        stringpair_list_t* cur;
        for (cur = param_keyvals; cur; cur = cur->next) {
            attr_name = strdup(cur->value->key);
            attr_value = strdup(cur->value->value);
            
            param = mailmime_parameter_new(attr_name, attr_value);
            assert(param);
            if (param == NULL)
                goto enomem;
                
            attr_name = NULL;
            attr_value = NULL;

            if (content->ct_parameters == NULL) {
                parameters = clist_new();
                assert(parameters);
                if (parameters == NULL)
                    goto enomem;
            }
            else {
                parameters = content->ct_parameters;
            }

            r = clist_append(parameters, param);
            if (r)
                goto enomem;
            param = NULL;

            if (content->ct_parameters == NULL)
                content->ct_parameters = parameters;            
        }
    }

    build_info = mailmime_new(mime_type, NULL, 0, mime_fields, content, NULL,
            NULL, NULL, list, NULL, NULL);
    if (build_info == NULL)
        goto enomem;

    return build_info;

enomem:
    if (list)
        clist_free(list);
    free(attr_name);
    free(attr_value);
    if (content->ct_parameters == NULL)
        if (parameters)
            clist_free(parameters);
    if (param)
        mailmime_parameter_free(param);
    return NULL;
}

struct mailmime * get_pgp_encrypted_part(void)
{
    struct mailmime * mime = NULL;
    struct mailmime_fields * mime_fields = NULL;
    struct mailmime_content * content = NULL;
    int r;

    content = mailmime_content_new_with_str("application/pgp-encrypted");
    if (content == NULL)
        goto enomem;

    mime_fields = mailmime_fields_new_empty();
    if (mime_fields == NULL)
        goto enomem;

    mime = part_new_empty(content, mime_fields, NULL, 1);
    if (mime == NULL)
        goto enomem;
    mime_fields = NULL;
    content = NULL;

    r = mailmime_set_body_text(mime, "Version: 1\n", 10);
    if (r != 0)
        goto enomem;

    return mime;

enomem:
    if (content)
        mailmime_content_free(content);
    if (mime_fields)
        mailmime_fields_free(mime_fields);
    if (mime)
        mailmime_free(mime);

    return NULL;
}

struct mailmime * get_text_part(
        pEp_rid_list_t* resource,
        const char * mime_type,
        const char * text,
        size_t length,
        int encoding_type
    )
{
    char * disposition_name = NULL;
    struct mailmime_fields * mime_fields = NULL;
    struct mailmime * mime = NULL;
    struct mailmime_content * content = NULL;
    struct mailmime_parameter * param = NULL;
    struct mailmime_disposition * disposition = NULL;
    struct mailmime_mechanism * encoding = NULL;
    char* content_id = NULL;
    int r;
                
    if (resource != NULL && resource->rid != NULL) {
        switch (resource->rid_type) {
            case PEP_RID_CID:
                content_id = strdup(resource->rid);
                break;
            case PEP_RID_FILENAME:
            default:
                disposition_name = strdup(resource->rid);
                if (disposition_name == NULL)
                    goto enomem;
                    
                disposition =
                        mailmime_disposition_new_with_data(MAILMIME_DISPOSITION_TYPE_INLINE,
                                disposition_name, NULL, NULL, NULL, (size_t) -1);

                if (disposition == NULL)
                    goto enomem;

                disposition_name = NULL;                
                break;
        }    
    }
    
    if (encoding_type) {
        encoding = mailmime_mechanism_new(encoding_type, NULL);
        if (encoding == NULL)
            goto enomem;
    }

    mime_fields = mailmime_fields_new_with_data(encoding, content_id, NULL,
            disposition, NULL);
    if (mime_fields == NULL)
        goto enomem;
    encoding = NULL;
    disposition = NULL;
    content_id = NULL;

    content = mailmime_content_new_with_str(mime_type);
    if (content == NULL)
        goto enomem;
    
    if (encoding_type != MAILMIME_MECHANISM_7BIT) {
        param = mailmime_param_new_with_data("charset", "utf-8");
        r = clist_append(content->ct_parameters, param);
        if (r != 0)
            goto enomem;
    }

    mime = part_new_empty(content, mime_fields, NULL, 1);
    if (mime == NULL)
        goto enomem;
    content = NULL;
    mime_fields = NULL;

    if (text) {
        r = mailmime_set_body_text(mime, (char *) text, length);
        if (r != 0)
            goto enomem;
    }
    
    return mime;

enomem:
    free(disposition_name);
    if (mime_fields)
        mailmime_fields_free(mime_fields);
    if (mime)
        mailmime_free(mime);
    if (content)
        mailmime_content_free(content);
    if (param)
        mailmime_parameter_free(param);
    if (disposition)
        mailmime_disposition_free(disposition);
    if (encoding)
        mailmime_mechanism_free(encoding);

    return NULL;
}

struct mailmime * get_file_part(
        pEp_rid_list_t* resource,
        const char * mime_type,
        char * data,
        size_t length,
        bool is_nf_message_attachment // non-forwarded msg as att
    )
{
    char * disposition_name = NULL;
    int encoding_type;
    struct mailmime_disposition * disposition = NULL;
    struct mailmime_mechanism * encoding = NULL;
    struct mailmime_content * content = NULL;
    struct mailmime * mime = NULL;
    struct mailmime_fields * mime_fields = NULL;
    char* content_id = NULL;
    int r;
                
    if (resource != NULL && resource->rid != NULL) {
        switch (resource->rid_type) {
            case PEP_RID_CID:
                content_id = strdup(resource->rid);
                disposition =
                    mailmime_disposition_new_with_data(MAILMIME_DISPOSITION_TYPE_INLINE,
                                                       NULL, NULL, NULL, NULL, (size_t) -1);
                    if (disposition == NULL)
                        goto enomem;
                break;
            case PEP_RID_FILENAME:
            default:
                disposition_name = strdup(resource->rid);
                if (disposition_name == NULL)
                    goto enomem;
                    
                disposition =
                        mailmime_disposition_new_with_data(MAILMIME_DISPOSITION_TYPE_ATTACHMENT,
                                disposition_name, NULL, NULL, NULL, (size_t) -1);
                                
                if (disposition == NULL)
                    goto enomem;
                disposition_name = NULL;
                
                break;
        }    
    }
    

    content = mailmime_content_new_with_str(mime_type);
    if (content == NULL)
        goto enomem;

    encoding = NULL;

    bool already_ascii = !(must_chunk_be_encoded(data, length, true));

    // check to be sure, if it is already ascii, that line lengths aren't also
    // exceeded. Otherwise, we should base64-encode anyway.
    
    if (!is_nf_message_attachment && !already_ascii) {
        encoding_type = MAILMIME_MECHANISM_BASE64;
        encoding = mailmime_mechanism_new(encoding_type, NULL);
        if (encoding == NULL)
            goto enomem;
    }

    mime_fields = mailmime_fields_new_with_data(encoding, content_id, NULL,
            disposition, NULL);
    if (mime_fields == NULL)
        goto enomem;
    encoding = NULL;
    disposition = NULL;

    stringpair_list_t* extra_params = NULL;
    
    if (is_nf_message_attachment)
        extra_params = new_stringpair_list(new_stringpair("forwarded", "no"));
    
    mime = part_new_empty(content, mime_fields, extra_params, 1);
    free_stringpair_list(extra_params);
    if (mime == NULL)
        goto enomem;
    content = NULL;
    mime_fields = NULL;

    if(length > 0)
    {
        r = mailmime_set_body_text(mime, data, length);
        if (r != 0)
            goto enomem;
    }

    return mime;

enomem:
    free(disposition_name);
    if (disposition)
        mailmime_disposition_free(disposition);
    if (encoding)
        mailmime_mechanism_free(encoding);
    if (content)
        mailmime_content_free(content);
    if (mime_fields)
        mailmime_fields_free(mime_fields);
    if (mime)
        mailmime_free(mime);
    
    return NULL;
}

struct mailmime * part_multiple_new(const char *type)
{
    struct mailmime_fields *mime_fields = NULL;
    struct mailmime_content *content = NULL;
    struct mailmime *mp = NULL;
    
    mime_fields = mailmime_fields_new_empty();
    if (mime_fields == NULL)
        goto enomem;
    
    content = mailmime_content_new_with_str(type);
    if (content == NULL)
        goto enomem;
    
    mp = part_new_empty(content, mime_fields, NULL, 0);
    if (mp == NULL)
        goto enomem;
    
    return mp;
    
enomem:
    if (content)
        mailmime_content_free(content);
    if (mime_fields)
        mailmime_fields_free(mime_fields);

    return NULL;
}

struct mailimf_field * _new_field(
        int type,
        _new_func_t new_func,
        void *value
    )
{
    void *data = new_func(value);
    assert(data);
    if (data == NULL)
        return NULL;

    struct mailimf_field * result = calloc(1, sizeof(struct mailimf_field));
    assert(result);
    if (result == NULL) {
        free(data);
        return NULL;
    }

    result->fld_type = type;
    result->fld_data.fld_return_path = data;

    return result;
}

void _free_field(struct mailimf_field *field)
{
    if (field)
        free(field->fld_data.fld_return_path);
    free(field);
}

int _append_field(
        clist *list,
        int type,
        _new_func_t new_func,
        void *value
    )
{
    int r;
    struct mailimf_field * field;

    assert(list);
    assert(new_func);
    assert(value);

    field = _new_field(type, new_func, value);
    if (field == NULL)
        return -1;

    r = clist_append(list, field);
    if (r)
        _free_field(field);

    return r;
}

// http://media2.giga.de/2014/02/Image-28.jpg

struct mailimf_date_time * timestamp_to_etpantime(const timestamp *ts)
{
    struct mailimf_date_time * result = calloc(1,
            sizeof(struct mailimf_date_time));
    assert(result);
    if (result == NULL)
        return NULL;

    assert(ts);

    result->dt_sec = ts->tm_sec;
    result->dt_min = ts->tm_min;
    result->dt_hour = ts->tm_hour;
    result->dt_day = ts->tm_mday;
    result->dt_month = ts->tm_mon + 1;
    result->dt_year = ts->tm_year + 1900;
    result->dt_zone = (int) (ts->tm_gmtoff / 36L);
    return result;
}

timestamp * etpantime_to_timestamp(const struct mailimf_date_time *et)
{
    timestamp * result = calloc(1, sizeof(timestamp));
    assert(result);
    if (result == NULL)
        return NULL;

    assert(et);

    result->tm_sec = et->dt_sec;
    result->tm_min = et->dt_min;
    result->tm_hour = et->dt_hour;
    result->tm_mday = et->dt_day;
    result->tm_mon = et->dt_month - 1;
    result->tm_year = et->dt_year - 1900;
    result->tm_gmtoff = 36L * (long) et->dt_zone;

    // Normalize to UTC and then forget the offset.
    time_t t = timegm_with_gmtoff(result);
    gmtime_r(&t, result);
    result->tm_gmtoff = 0;

    return result;
}

struct mailimf_mailbox * mailbox_from_string(
        const char *name,
        const char *address
    )
{
    assert(address);
    if (!address)
        return NULL;

    struct mailimf_mailbox *mb = NULL;
    char *_name = NULL;
    char *_address = NULL;

    _name = name ? strdup(name) : strdup("");
    if (_name == NULL)
        goto enomem;

    char* at = strstr(address, "@");
    if (!at) {
        // Presumed URI
        int added_char_len = 6; // " " @URI 
        int new_addr_len = strlen(address) + added_char_len + 1;
        _address = calloc(new_addr_len, 1);
        if (_address == NULL)
            goto enomem;
        
        _address[0] = '"';
        strlcat(_address, address, new_addr_len);
        strlcat(_address, "\"@URI", new_addr_len);
    }
    else {
        _address = strdup(address);
        if (_address == NULL)
            goto enomem;
    }
            
    mb = mailimf_mailbox_new(_name, _address);
    assert(mb);
    if (mb == NULL)
        goto enomem;

    return mb;

enomem:
    free(_name);
    free(_address);

    return NULL;
}


struct mailimf_field * create_optional_field(
        const char *field,
        const char *value
    )
{
    char *_field = NULL;
    char *_value = NULL;
    struct mailimf_optional_field *optional_field = NULL;

    _field = strdup(field);
    if (_field == NULL)
        goto enomem;

    if (!must_field_value_be_encoded(value))
        _value = strdup(value);
    else    
        _value = mailmime_encode_subject_header("utf-8", value, 0);
    if (_value == NULL)
        goto enomem;

    optional_field = mailimf_optional_field_new(_field, _value);
    if (optional_field == NULL)
        goto enomem;

    struct mailimf_field * result = calloc(1, sizeof(struct mailimf_field));
    assert(result);
    if (result == NULL)
        goto enomem;

    result->fld_type = MAILIMF_FIELD_OPTIONAL_FIELD;
    result->fld_data.fld_optional_field = optional_field;

    return result;

enomem:
    if (optional_field) {
        mailimf_optional_field_free(optional_field);
    }
    else {
        free(_field);
        free(_value);
    }

    return NULL;
}

int _append_optional_field(
        clist *list,
        const char *field,
        const char *value
    )
{
    int r;
    struct mailimf_field * optional_field =
            create_optional_field(field, value);

    if (optional_field == NULL)
        return -1;

    r = clist_append(list, optional_field);
    if (r)
        mailimf_field_free(optional_field);

    return r;
}

clist * _get_fields(struct mailmime * mime)
{
    clist * _fieldlist = NULL;

    assert(mime);

    if (mime->mm_data.mm_message.mm_fields &&
            mime->mm_data.mm_message.mm_fields->fld_list) {
        _fieldlist = mime->mm_data.mm_message.mm_fields->fld_list;
    }

    return _fieldlist;
}

struct mailmime_content * _get_content(struct mailmime * mime)
{
    struct mailmime_content * content = NULL;

    assert(mime);

    if (mime->mm_data.mm_message.mm_msg_mime)
        content = mime->mm_data.mm_message.mm_msg_mime->mm_content_type;

    return content;
}


/* Return a list of identifier_type and resource id (filename, cid, etc) */
pEp_rid_list_t* _get_resource_id_list(struct mailmime *mime)
{
    clist * _fieldlist = NULL;

    assert(mime);

    if (mime->mm_mime_fields && mime->mm_mime_fields->fld_list)
        _fieldlist = mime->mm_mime_fields->fld_list;
    else
        return NULL;

    clistiter *cur;

    pEp_rid_list_t* rid_list = NULL; 
    pEp_rid_list_t** rid_list_curr_p = &rid_list; 
        
    for (cur = clist_begin(_fieldlist); cur; cur = clist_next(cur)) {
        struct mailmime_field * _field = clist_content(cur);
        /* content_id */
        if (_field && _field->fld_type == MAILMIME_FIELD_ID) {
            pEp_rid_list_t* new_rid = (pEp_rid_list_t*)calloc(1, sizeof(pEp_rid_list_t));
            new_rid->rid_type = PEP_RID_CID;
            new_rid->rid = strdup(_field->fld_data.fld_id);
            *rid_list_curr_p = new_rid;
            rid_list_curr_p = &new_rid->next;
        }
        else if (_field && _field->fld_type == MAILMIME_FIELD_DISPOSITION) {
            /* filename */
            if (_field->fld_data.fld_disposition &&
                    _field->fld_data.fld_disposition->dsp_parms) {
                clist * _parmlist =
                        _field->fld_data.fld_disposition->dsp_parms;
                clistiter *cur2;
                for (cur2 = clist_begin(_parmlist); cur2; cur2 =
                        clist_next(cur2)) {
                    struct mailmime_disposition_parm * param =
                            clist_content(cur2);
                    if (param->pa_type == MAILMIME_DISPOSITION_PARM_FILENAME) {
                        pEp_rid_list_t* new_rid = (pEp_rid_list_t*)calloc(1, sizeof(pEp_rid_list_t));
                        new_rid->rid_type = PEP_RID_FILENAME;
                        new_rid->rid = strdup(param->pa_data.pa_filename);
                        *rid_list_curr_p = new_rid;
                        rid_list_curr_p = &new_rid->next;
                    }                
                }
            }
        }
    }
    /* Will almost certainly usually be a singleton, but we need to be able to decide */
    return rid_list;
}


/* FIXME: about to be obsoleted? */
char * _get_filename_or_cid(struct mailmime *mime)
{
    clist * _fieldlist = NULL;

    assert(mime);

    if (mime->mm_mime_fields && mime->mm_mime_fields->fld_list)
        _fieldlist = mime->mm_mime_fields->fld_list;
    else
        return NULL;

    clistiter *cur;
    
    char* _temp_filename_ptr = NULL;
    
    for (cur = clist_begin(_fieldlist); cur; cur = clist_next(cur)) {
        struct mailmime_field * _field = clist_content(cur);
        if (_field && _field->fld_type == MAILMIME_FIELD_ID) {
            /* We prefer CIDs to filenames when both are present */
            free(_temp_filename_ptr); /* can be null, it's ok */
            return build_uri("cid", _field->fld_data.fld_id); 
        }
        else if (_field && _field->fld_type == MAILMIME_FIELD_DISPOSITION) {
            if (_field->fld_data.fld_disposition &&
                    _field->fld_data.fld_disposition->dsp_parms &&
                    !_temp_filename_ptr) {
                clist * _parmlist =
                        _field->fld_data.fld_disposition->dsp_parms;
                clistiter *cur2;
                for (cur2 = clist_begin(_parmlist); cur2; cur2 =
                        clist_next(cur2)) {
                    struct mailmime_disposition_parm * param =
                            clist_content(cur2);
                    if (param->pa_type == MAILMIME_DISPOSITION_PARM_FILENAME) {
                        _temp_filename_ptr = build_uri("file", param->pa_data.pa_filename);
                        break;
                    }                
                }
            }
        }
    }
    /* Ok, it wasn't a CID */
    return _temp_filename_ptr;
}

/**
 *  @internal
 *  
 *  <!--       parameter_has_value()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *content        structmailmime_content
 *  @param[in]    *name        constchar
 *  @param[in]    *value        constchar
 *  
 */
static bool parameter_has_value(
        struct mailmime_content *content,       
        const char *name,
        const char *value
    )
{
    clistiter *cur;

    assert(name);
    assert(value);

    clist * list = content->ct_parameters;
    if (list == NULL)
        return false;

    for (cur = clist_begin(list); cur != NULL ; cur = clist_next(cur)) {
        struct mailmime_parameter * param = clist_content(cur);
        if (param &&
                param->pa_name && strcasecmp(name, param->pa_name) == 0 &&
                param->pa_value && strcasecmp(value, param->pa_value) == 0)
            return true;
    }

    return false;
}

bool _is_multipart(struct mailmime_content *content, const char *subtype)
{
    assert(content);

    if (content->ct_type && content->ct_type->tp_type ==
            MAILMIME_TYPE_COMPOSITE_TYPE &&
            content->ct_type->tp_data.tp_composite_type &&
            content->ct_type->tp_data.tp_composite_type->ct_type ==
            MAILMIME_COMPOSITE_TYPE_MULTIPART) {
        if (subtype)
            return content->ct_subtype &&
                    strcasecmp(content->ct_subtype, subtype) == 0;
        else
            return true;
    }

    return false;
}

bool _is_PGP_MIME(struct mailmime_content *content)
{
    assert(content);

    if (_is_multipart(content, "encrypted") &&
            parameter_has_value(content, "protocol",
                    "application/pgp-encrypted"))
        return true;

    return false;
}

bool _is_text_part(struct mailmime_content *content, const char *subtype)
{
    assert(content);

    if (content->ct_type && content->ct_type->tp_type ==
            MAILMIME_TYPE_DISCRETE_TYPE &&
            content->ct_type->tp_data.tp_discrete_type &&
            content->ct_type->tp_data.tp_discrete_type->dt_type ==
            MAILMIME_DISCRETE_TYPE_TEXT) {
        if (subtype)
            return content->ct_subtype &&
                    strcasecmp(content->ct_subtype, subtype) == 0;
        else
            return true;
    }

    return false;
}

/**
 *  @internal
 *  
 *  <!--       _is_message_part()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *content        structmailmime_content
 *  @param[in]    *subtype        constchar
 *  
 */
bool _is_message_part(struct mailmime_content *content, const char* subtype) {
    assert(content);
    if (content->ct_type && content->ct_type->tp_type == MAILMIME_TYPE_COMPOSITE_TYPE &&
            content->ct_type->tp_data.tp_composite_type &&
            content->ct_type->tp_data.tp_composite_type->ct_type ==
            MAILMIME_COMPOSITE_TYPE_MESSAGE) {
        if (subtype)
            return content->ct_subtype &&
                    strcasecmp(content->ct_subtype, subtype) == 0;
        else
            return true;                
    }
    
    return false;
}

int _get_content_type(
        const struct mailmime_content *content,
        char **type,
        char **charset
    )
{
    char *_type = NULL;
    char *_charset = NULL;

    assert(content);
    assert(type);
    assert(charset);

    *type = NULL;
    *charset = NULL;

    if (content->ct_subtype == NULL)
        return EINVAL;

    if (content->ct_type && content->ct_type->tp_data.tp_discrete_type) {
        size_t len;
        const char *_main_type;

        switch  (content->ct_type->tp_data.tp_discrete_type->dt_type) {
            case MAILMIME_DISCRETE_TYPE_TEXT:
                _main_type = (content->ct_subtype && 
                              strcasecmp(content->ct_subtype, "rfc822") == 0 ?
                              "message" : "text");
                break;
            case MAILMIME_DISCRETE_TYPE_IMAGE:
                _main_type = "image";
                break;
            case MAILMIME_DISCRETE_TYPE_AUDIO:
                _main_type = "audio";
                break;
            case MAILMIME_DISCRETE_TYPE_VIDEO:
                _main_type = "video";
                break;
            case MAILMIME_DISCRETE_TYPE_APPLICATION:
                _main_type = "application";
                break;
            case MAILMIME_DISCRETE_TYPE_EXTENSION:
                _main_type = "extension";
                break;
            default:
                return EINVAL;
        }

        len = strlen(_main_type) + 1 + strlen(content->ct_subtype) + 1;
        _type = calloc(1, len);
        assert(_type);
        if (_type == NULL)
            return ENOMEM;

        strncpy(_type, _main_type, len);
        len -= strlen(_main_type);
        strncat(_type, "/", len--);
        strncat(_type, content->ct_subtype, len);

        if (content->ct_parameters) {
            clistiter *cur;
            for (cur = clist_begin(content->ct_parameters); cur; cur =
                    clist_next(cur)) {
                struct mailmime_parameter * param = clist_content(cur);
                if (param && param->pa_name && strcasecmp(param->pa_name,
                            "charset") == 0) {
                    _charset = param->pa_value;
                    break;
                }
            }
            if (_charset)
                *charset = strdup(_charset);
        }

        *type = _type;
        return 0;
    }

    return EINVAL;
}

// Only for null-terminated field strings.
// can this field be transported as is without modification?)
// (See rfc2822, section 2.2.3 - libetpan's handling isn't quite what
// we need here.)
bool must_field_value_be_encoded(const char* field_value) {
    if (!field_value)
        return false;
        
    return must_chunk_be_encoded((const void*)field_value, strlen(field_value), false);    
}

bool must_chunk_be_encoded(const void* value, size_t size, bool ignore_fws) {

    const char* begin_ptr = (const char*)value;    

    const char* end_ptr = begin_ptr + size;

    const char* cur_char_ptr = begin_ptr;
    while (cur_char_ptr < end_ptr) {
        char cur_char = *cur_char_ptr;
        if (cur_char > 127 || cur_char < 0)
            return true;
        // FIXME - do we need to deal with CRCRLF here?
        //         I guess in the worst case, it gets encoded, which
        //         is *supposed* to be harmless...
        if (!ignore_fws) {
            if (cur_char == '\r') {
                const char* next = cur_char_ptr + 1;
                const char* nextnext = next + 1;
                if (next >= end_ptr || nextnext >= end_ptr
                    || *next != '\n'
                    || (*nextnext != ' ' && *nextnext != '\t')) {
                    return true;
                }            
            }
            else if (cur_char == '\n') {
                const char* prev = cur_char_ptr - 1;
                if (prev == begin_ptr || *prev != '\r')
                    return true;
            }
        }
        cur_char_ptr++;
    }

    return ascii_exceeds_line_length(value, size);
}

#define TMP_TEMPLATE "pEp.XXXXXXXXXXXXXXXXXXXX"
#ifdef _WIN32
#define PATH_SEP '\\'
#else
#define PATH_SEP '/'
#endif

static PEP_STATUS interpret_MIME(struct mailmime *mime,
                                 message *msg,
                                 bool* has_possible_pEp_msg);

// This function was rewritten to use in-memory buffers instead of
// temporary files when the pgp/mime support was implemented for
// outlook, as the existing code did not work well on windows.

/**
 *  @internal
 *  
 *  <!--       render_mime()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *mime        structmailmime
 *  @param[in]    **mimetext        char
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
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

/**
 *  @internal
 *  
 *  <!--       mime_attachment()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *blob        bloblist_t
 *  @param[in]    **result        structmailmime
 *  @param[in]    is_nf_message_attachment        bool
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 *  
 */
static PEP_STATUS mime_attachment(
        bloblist_t *blob,
        struct mailmime **result,
        bool is_nf_message_attachment // non-forwarded msg as att
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

    mime = get_file_part(resource, mime_type, blob->value, blob->size, 
                         is_nf_message_attachment);
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


// This ONLY deals with handling the body 
// content when html parts are present - thus,
// text/plain and text/html of the body, and 
// related inline attachments for the html 
// part. Non-inline attachments are handled 
// outside this call!!!!
//
// N.B. As a result, this will only touch the 
// "contained message" of pEp 2.x messages 
// on the initial encoding where it is turned 
// into attachment data!!
/**
 *  @internal
 *  
 *  <!--       mime_html_text()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *plaintext        constchar
 *  @param[in]    *htmltext        constchar
 *  @param[in]    *attachments        bloblist_t
 *  @param[in]    **result        structmailmime
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
static PEP_STATUS mime_html_text(
        const char *plaintext,
        const char *htmltext,
        bloblist_t *attachments,
        struct mailmime **result
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

    pEp_rid_list_t* resource = NULL;
        
    bool already_ascii = false;
    int encoding_type = 0;    
    if (*plaintext != '\0') {
        mime = part_multiple_new("multipart/alternative");
        assert(mime);
        if (mime == NULL)
            goto enomem;
            
        // KB: pEpMIME transition comment - if we start getting 
        // underencoding errors here, the change to checking 
        // for ASCII and then encoding - or not - is one place 
        // to start looking.
        int pt_length = strlen(plaintext);
        already_ascii = !(must_chunk_be_encoded(plaintext, pt_length, true));                
        encoding_type = (already_ascii ? 0 : MAILMIME_MECHANISM_QUOTED_PRINTABLE);
                
        submime = get_text_part(NULL, "text/plain", plaintext, 
                                pt_length,
                                encoding_type);
        
        // reset                        
        already_ascii = false;
        encoding_type = 0;
                                    
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

        // This is where all of the html MIME stuff will go
        top_level_html_mime = submime;
        
        if (!mime)
            mime = top_level_html_mime;
        else {    
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
    }
    else {
        // Otherwise, html MIME stuff gets added to the top node 
        // - may be NULL if there's no multipart!
        top_level_html_mime = mime;
    }

//    resource = new_rid_node(PEP_RID_FILENAME, "msg.html");
    int ht_length = strlen(htmltext);
    already_ascii = !(must_chunk_be_encoded(htmltext, ht_length, true));                
    encoding_type = (already_ascii ? 0 : MAILMIME_MECHANISM_QUOTED_PRINTABLE);
            
    submime = get_text_part(NULL, "text/html", htmltext, 
                            ht_length,
                            encoding_type);

    free_rid_list(resource);
    resource = NULL;
    
    assert(submime);
    if (submime == NULL)
        goto enomem;
        
    // IF there are no inlined attachments AND mime is NULL, then 
    // we just have an HTML body here and won't need to 
    // process inlined attachments - submime will actually be 
    // the mime root of from this function, at least.    

    if (!top_level_html_mime) {
        mime = submime;
        submime = NULL;
    }
    else {    
        r = mailmime_smart_add_part(top_level_html_mime, submime);
        assert(r == MAILIMF_NO_ERROR);
        if (r == MAILIMF_ERROR_MEMORY)
            goto enomem;
        else {
            // mailmime_smart_add_part() takes ownership of submime
            submime = NULL;
        }

        bloblist_t *_a;

        // This will never have an embedded pEp message attachment 
        // sent for encoding here, so we don't need to pass down 
        // "(don't) transport encode this" info. If it's here and 
        // it's not an ASCII "text/*" attachment, it'll get encoded
        for (_a = attachments; _a != NULL; _a = _a->next) {
            if (_a->disposition != PEP_CONTENT_DISP_INLINE)
                continue;
            status = mime_attachment(_a, &submime, false);
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


/**
 *  @internal
 *  
 *  <!--       identity_to_mailbox()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *ident        constpEp_identity
 *  
 */
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

/**
 *  @internal
 *  
 *  <!--       identity_to_mbl()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *ident        constpEp_identity
 *  
 */
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

/**
 *  @internal
 *  
 *  <!--       identity_list_to_mal()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *il        identity_list
 *  
 */
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

// KB: This seems to be always called with "true",
//     but there was probably a reason for this. So 
//     leave it for now.
/**
 *  @internal
 *  
 *  <!--       stringlist_to_clist()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *sl        stringlist_t
 *  @param[in]    transport_encode        bool
 *  
 */
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

/**
 *  @internal
 *  
 *  <!--       build_fields()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *msg	    constmessage
 *  @param[in]    **result        structmailimf_fields
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
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
    char *subject = msg->shortmsg && msg->shortmsg[0] ? msg->shortmsg : altstr;

    assert(msg);
    assert(result);

    *result = NULL;

    fields_list = clist_new();
    assert(fields_list);
    if (fields_list == NULL)
        goto enomem;

    if (msg->id && msg->id[0]) {
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

     if (msg->from) {
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

    if (msg->to && msg->to->ident) {
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

    if (msg->cc && msg->cc->ident) {
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
    
    if (msg->bcc && msg->bcc->ident) {
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
    
    if (msg->reply_to && msg->reply_to->ident) {
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

    if (msg->in_reply_to && msg->in_reply_to->value) {
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

    if (msg->references && msg->references->value) {
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

    if (msg->keywords && msg->keywords->value) {
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

    if (msg->comments && msg->comments[0]) {
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

    if (msg->opt_fields && msg->opt_fields->value) {
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

/**
 *  @internal
 *  
 *  <!--       has_exceptional_extension()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *filename        char
 *  
 */
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

/**
 *  @internal
 *  
 *  <!--       choose_resource_id()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *rid_list        pEp_rid_list_t
 *  
 */
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


/**
 *  @internal
 *  
 *  <!--       mime_encode_message_plain()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *msg        constmessage
 *  @param[in]    omit_fields        bool
 *  @param[in]    **result        structmailmime
 *  @param[in]    has_pEp_msg_attachment        bool
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
static PEP_STATUS mime_encode_message_plain(
        const message *msg,
        bool omit_fields,
        struct mailmime **result,
        bool has_pEp_msg_attachment
    )
{
    struct mailmime * mime = NULL;
    struct mailmime * submime = NULL;
    int r;
    PEP_STATUS status;
    //char *subject;
    const char *plaintext;
    char *htmltext;

    assert(msg);
    assert(result);

    // * Process body content, including html's inlined attachments *
    plaintext = (msg->longmsg) ? msg->longmsg : "";
    htmltext = msg->longmsg_formatted;

    if (htmltext && (htmltext[0] != '\0')) {
        /* first, we need to strip out the inlined attachments to ensure this
           gets set up correctly */
           
        // Note: this only, regardless of whether this is being done 
        // for the to-be-embedded message attachment generation or 
        // an encapsulating message which contains this, touches 
        // the body text of this input message. So transport encoding 
        // only refers to the body content here and inlined-attachments, and 
        // is decided WITHIN this function, not as an argument. 
        status = mime_html_text(plaintext, htmltext, msg->attachments, &mime);
                
        if (status != PEP_STATUS_OK)
            goto pEp_error;
    }
    else { /* body content only consists of a plaintext block */
        pEp_rid_list_t* resource = NULL;

        int pt_length = strlen(plaintext);

        if (is_PGP_message_text(plaintext)) {
            resource = NULL;
            
            // So... I think we got overencoding here once, which would be a bug 
            // in libetpan, unless it had to do with whitespace. If removing
            // transport encoding as a calculation here somehow leads to overencoding,
            // either we or libetpan are doing something bad.
//            int encoding_type = (transport_encode ? MAILMIME_MECHANISM_7BIT : 0);
            mime = get_text_part(resource, "application/octet-stream", plaintext,
                                 pt_length, MAILMIME_MECHANISM_7BIT);
        }
        else {
            resource = NULL;
            bool already_ascii = !(must_chunk_be_encoded(plaintext, pt_length, true));                
            int encoding_type = (already_ascii ? MAILMIME_MECHANISM_7BIT : MAILMIME_MECHANISM_QUOTED_PRINTABLE);
            mime = get_text_part(resource, "text/plain", plaintext, strlen(plaintext),
                    encoding_type);
        }
        free_rid_list(resource);
        
        assert(mime);
        if (mime == NULL)
            goto enomem;
    }

    /* Body content processed, now process normal attachments */
    
    bool normal_attachments = false;
    
    bloblist_t* traversal_ptr = msg->attachments;
    
    // If there were any inline attachments, they should have 
    // been stripped out in mime_html_text and dealt with. 
    // I'm not entirely sure what the alternative case 
    // is here. But basically, if there are any non-inlined 
    // attachments to deal with, this is designed to 
    // make sure we process them. So flag it for 
    // "hey, Bob, you got some regular attachments here"
    // so Bob (obviously, the MIME engine is called Bob)
    // can do the right thing in the next block.
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
        bool first_one = true;
        
        // Go through the non-inline attachments and add em.
        for (_a = msg->attachments; _a != NULL; _a = _a->next) {

            if (_a->disposition == PEP_CONTENT_DISP_INLINE)
                continue;

            // solely for readability.
            bool is_pEp_msg_attachment = (first_one && has_pEp_msg_attachment);

            status = mime_attachment(_a, &submime, 
                                     is_pEp_msg_attachment);                         

            if (status != PEP_STATUS_OK)
                goto pEp_error;
            
            first_one = false;    

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

/**
 *  @internal
 *  
 *  <!--       mime_encode_message_PGP_MIME()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *msg        const message
 *  @param[in]    omit_fields        bool
 *  @param[in]    **result        struct mailmime
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 *  
 */
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
        char **mimetext,
        bool has_pEp_msg_attachment
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
            status = mime_encode_message_plain(msg, omit_fields, &mime, has_pEp_msg_attachment);
            break;

        // I'm presuming we should hardcore ignoring has_pEp_msg_attachment here...
        case PEP_enc_inline:
            status = mime_encode_message_plain(msg, omit_fields, &mime, false);
            break;

        case PEP_enc_S_MIME:
            NOT_IMPLEMENTED
                
        case PEP_enc_PGP_MIME:
            status = mime_encode_message_PGP_MIME(msg, omit_fields, &mime);
            break;

        case PEP_enc_PEP:
            // today's pEp message format is PGP/MIME from the outside
            status = mime_encode_message_PGP_MIME(msg, omit_fields, &mime);
            break;

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

/**
 *  @internal
 *  
 *  <!--       mailbox_to_identity()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *mb        const struct mailimf_mailbox
 *  
 */
static pEp_identity *mailbox_to_identity(const struct mailimf_mailbox * mb)
{
    char *username = NULL;
    char *address = NULL;

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

    const char* raw_addr = mb->mb_addr_spec;
    if (raw_addr && raw_addr[0] == '"') {
        int addr_len = strlen(raw_addr);
        if (addr_len >= 6) { // ""@URI
            const char* endcheck = strstr(raw_addr + 1, "\"@URI");
            if (endcheck && *(endcheck + 5) == '\0') {
                int actual_size = addr_len - 6;
                address = calloc(actual_size + 1, 1);
                if (!address)
                    goto enomem;
                strlcpy(address, raw_addr + 1, actual_size + 1);    
            }
        }
    }

    pEp_identity *ident = new_identity(address ? address : raw_addr, NULL, NULL, username);
    if (ident == NULL)
        goto enomem;
    free(username);
    free(address);
    return ident;

enomem:
    free(address);
    free(username);
    return NULL;
}

/**
 *  @internal
 *  
 *  <!--       mbl_to_identity()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *mbl        const struct mailimf_mailbox_list
 *  
 */
static pEp_identity * mbl_to_identity(const struct mailimf_mailbox_list * mbl)
{
    struct mailimf_mailbox * mb = clist_content(clist_begin(mbl->mb_list));
    return mailbox_to_identity(mb);
}

/**
 *  @internal
 *  
 *  <!--       mal_to_identity_list()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *mal        const struct mailimf_address_list
 *  
 */
static identity_list * mal_to_identity_list(
        const struct mailimf_address_list *mal
    )
{
    identity_list *il = new_identity_list(NULL);
    if (il == NULL)
        goto enomem;

    // if we have nothing to translate then return an empty list
    if (!mal)
        return il;

    clist *list = mal->ad_list;

    identity_list *_il = il;
    for (clistiter *cur = clist_begin(list); cur != NULL ; cur = clist_next(cur)) {
        pEp_identity *ident;

        struct mailimf_address *addr = clist_content(cur);
        if (addr) {
            switch (addr->ad_type) {
                case MAILIMF_ADDRESS_MAILBOX:
                    ident = mailbox_to_identity(addr->ad_data.ad_mailbox);
                    if (ident == NULL)
                        goto enomem;
                    _il = identity_list_add(_il, ident);
                    if (_il == NULL)
                        goto enomem;
                    break;

                case MAILIMF_ADDRESS_GROUP: {
                    struct mailimf_mailbox_list *mbl =
                            addr->ad_data.ad_group->grp_mb_list;
                    if (mbl) {
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
                }
                    break;

                default:
                    assert(0);
                    goto enomem;
            }
        }
    }

    return il;

enomem:
    free_identity_list(il);
    return NULL;
}

/**
 *  @internal
 *  
 *  <!--       clist_to_stringlist()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *list        const clist
 *  
 */
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

/**
 *  @internal
 *  
 *  <!--       read_fields()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *msg        message
 *  @param[in]    *fieldlist        clist
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
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
                    identity_list *il = mal ? mal_to_identity_list(mal) : new_identity_list(NULL);
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

/**
 *  @internal
 *  
 *  <!--       interpret_body()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *part        struct mailmime
 *  @param[in]    **longmsg        char
 *  @param[in]    *size        size_t
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
static PEP_STATUS interpret_body(struct mailmime *part, char **longmsg, size_t *size)
{
    const char *text;
    char *_longmsg;
    size_t length;
    size_t _size;
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
        int code = part->mm_body->dt_encoding;
        index = 0;
        int r = mailmime_part_parse(text, length, &index, code, &_longmsg, &_size);
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
            // We can be more elegant about this later.
            if (charset && strncasecmp(charset, "utf-8", 5) != 0 && strncasecmp(charset, "utf8", 4) != 0) {
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
                _size = strlen(_longmsg);
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
/**
 *  @internal
 *  
 *  <!--       interpret_protected_headers()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *mime        struct mailmime
 *  @param[in]    *msg        message
 *  
 */
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
            headerblock = strstr(headerblock, subj_start);
            if (headerblock) {
                size_t subj_len = strlen(subj_start);
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

// ONLY for main part!!!
/**
 *  @internal
 *  
 *  <!--       process_multipart_related()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *mime        struct mailmime
 *  @param[in]    *msg        message
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval any other value on error
 *  
 */
static PEP_STATUS process_multipart_related(struct mailmime *mime,
                                            message *msg) {
    PEP_STATUS status = PEP_STATUS_OK;

    assert(mime);
    assert(msg);

    clist *partlist = mime->mm_data.mm_multipart.mm_mp_list;                                                

    if (partlist == NULL)
        return PEP_ILLEGAL_VALUE;

    clistiter *cur = clist_begin(partlist);
    struct mailmime *part = clist_content(cur);
    
    if (part == NULL)
        return PEP_ILLEGAL_VALUE;

    struct mailmime_content *content = part->mm_content_type;    
    assert(content);
    
    if (content == NULL)
        return PEP_ILLEGAL_VALUE;

    if (_is_text_part(content, "html")) {
        status = interpret_body(part, &msg->longmsg_formatted,
                NULL);
        if (status)
            return status;
    }
    else {
        // ???
        // This is what we would have done before, so... no
        // worse than the status quo. But FIXME!
        status = interpret_MIME(part, msg, NULL);
        if (status)
            return status;
    }
    
    for (cur = clist_next(cur); cur; cur = clist_next(cur)) {
        part = clist_content(cur);
        if (part == NULL)
            return PEP_ILLEGAL_VALUE;

        content = part->mm_content_type;
        assert(content);
        if (content == NULL)
            return PEP_ILLEGAL_VALUE;

        status = interpret_MIME(part, msg, NULL);
        if (status)
            return status;
    }
    return status;
}

/**
 *  @internal
 *  
 *  <!--       _is_marked_as_attachment()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *fields        structmailmime_fields
 *  
 */
static bool _is_marked_as_attachment(struct mailmime_fields *fields)
{
    if (!(fields && fields->fld_list))
        return false;

    clistiter *cur;
    for (cur = clist_begin(fields->fld_list); cur != NULL ; cur = clist_next(cur)) {
        struct mailmime_field * field = clist_content(cur);
        if (!(field && field->fld_type == MAILMIME_FIELD_DISPOSITION &&
                    field->fld_data.fld_disposition &&
                    field->fld_data.fld_disposition->dsp_type))
            continue;
        if (field->fld_data.fld_disposition->dsp_type->dsp_type ==
                MAILMIME_DISPOSITION_TYPE_ATTACHMENT)
            return true;
    }

    return false;
}

/**
 *  @internal
 *  
 *  <!--       interpret_MIME()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *mime        struct mailmime
 *  @param[in]    *msg        message
 *  @param[in]    *has_possible_pEp_msg        bool
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
static PEP_STATUS interpret_MIME(
        struct mailmime *mime,
        message *msg,
        bool* has_possible_pEp_msg
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(mime);
    assert(msg);

    struct mailmime_fields *fields = mime->mm_mime_fields;
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
                else if (_is_multipart(content, "related") && 
                    msg->longmsg_formatted == NULL) {
                    status = process_multipart_related(part, msg);
                    if (status)
                        return status;
                }
                else /* add as attachment */ {
                    status = interpret_MIME(part, msg, NULL);
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

                status = interpret_MIME(part, msg, NULL);
                if (status != PEP_STATUS_OK)
                    return status;
            }
        }
        else if (_is_multipart(content, NULL)) {
            clist *partlist = mime->mm_data.mm_multipart.mm_mp_list;
            if (partlist == NULL)
                return PEP_ILLEGAL_VALUE;

            clistiter *cur;
            // only add has_possible_pEp_msg on 2nd part!
            int _att_count = 0;
            for (cur = clist_begin(partlist); cur; cur = clist_next(cur), _att_count++) {
                struct mailmime *part= clist_content(cur);
                if (part == NULL)
                    return PEP_ILLEGAL_VALUE;
                status = interpret_MIME(part, msg, _att_count == 1 ? has_possible_pEp_msg : NULL);
                if (status != PEP_STATUS_OK)
                    return status;
            }
        }
        else {
            if (_is_text_part(content, "html") &&
                    !_is_marked_as_attachment(fields) &&
                    msg->longmsg_formatted == NULL &&
                    msg->longmsg == NULL) {
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
            else if (_is_text_part(content, "plain") && 
                    !_is_marked_as_attachment(fields) &&
                    msg->longmsg == NULL && msg->longmsg_formatted == NULL) {
                status = interpret_body(mime, &msg->longmsg, NULL);
                if (status)
                    return status;
            }            
            else if (_is_text_part(content, NULL) && 
                    !_is_marked_as_attachment(fields) &&
                    !_is_text_part(content, "plain") &&
                    msg->longmsg == NULL) {
                status = interpret_body(mime, &msg->longmsg, NULL);
                if (status)
                    return status;
            }
            else {
                // Fixme - we need a control on recursion level here - KG: maybe NOT. We only go to depth 1.
                if (has_possible_pEp_msg != NULL) {
                    bool is_msg = (_is_message_part(content, "rfc822") || _is_text_part(content, "rfc822"));
                    if (is_msg) {
                        if (content->ct_parameters) {
                            clistiter *cur;
                            for (cur = clist_begin(content->ct_parameters); cur; cur =
                                 clist_next(cur)) {
                                struct mailmime_parameter * param = clist_content(cur);
                                if (param && param->pa_name && strcasecmp(param->pa_name, "forwarded") == 0) {
                                    if (param->pa_value && strcasecmp(param->pa_value, "no") == 0) {
                                        *has_possible_pEp_msg = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
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
        message **msg,
        bool* has_possible_pEp_msg
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
                _msg, has_possible_pEp_msg);
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
