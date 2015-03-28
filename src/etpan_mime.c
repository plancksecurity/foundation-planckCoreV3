#include "etpan_mime.h"
#ifndef mailmime_param_new_with_data
#include <libetpan/mailprivacy_tools.h>
#endif

#include "platform.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>


time_t mail_mkgmtime(struct tm * tmp);

#define MAX_MESSAGE_ID 512

static char * generate_boundary(void)
{
    char id[MAX_MESSAGE_ID];
    long value1;
    long value2;
    long value3;
    long value4;
 
    // no random needed here

    value1 = random();
    value2 = random();
    value3 = random();
    value4 = random();

    snprintf(id, MAX_MESSAGE_ID, "%.4lx%.4lx%.4lx%.4lx", value1, value2,
            value3, value4);
    
    return strdup(id);
}

struct mailmime * part_new_empty(
        struct mailmime_content * content,
        struct mailmime_fields * mime_fields,
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

	mime = part_new_empty(content, mime_fields, 1);
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
        const char * filename,
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
    int r;
    
    if (filename != NULL) {
        disposition_name = strdup(filename);
        if (disposition_name == NULL)
            goto enomem;
    }

    if (encoding_type) {
        encoding = mailmime_mechanism_new(encoding_type, NULL);
        if (encoding == NULL)
            goto enomem;
    }

    disposition =
            mailmime_disposition_new_with_data(MAILMIME_DISPOSITION_TYPE_INLINE,
                    disposition_name, NULL, NULL, NULL, (size_t) -1);
    if (disposition == NULL)
        goto enomem;
    disposition_name = NULL;

    mime_fields = mailmime_fields_new_with_data(encoding, NULL, NULL,
            disposition, NULL);
    if (mime_fields == NULL)
        goto enomem;
    encoding = NULL;
    disposition = NULL;

	content = mailmime_content_new_with_str(mime_type);
    if (content == NULL)
        goto enomem;
    
    if (encoding_type != MAILMIME_MECHANISM_7BIT) {
        param = mailmime_param_new_with_data("charset", "utf-8");
        r = clist_append(content->ct_parameters, param);
        if (r != 0)
            goto enomem;
    }

	mime = part_new_empty(content, mime_fields, 1);
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
        const char * filename,
        const char * mime_type,
        char * data,
        size_t length
    )
{
    char * disposition_name = NULL;
    int encoding_type;
    struct mailmime_disposition * disposition = NULL;
    struct mailmime_mechanism * encoding = NULL;
    struct mailmime_content * content = NULL;
    struct mailmime * mime = NULL;
    struct mailmime_fields * mime_fields = NULL;
    int r;

    if (filename != NULL) {
        disposition_name = strdup(filename);
        if (disposition_name == NULL)
            goto enomem;
    }

    disposition =
            mailmime_disposition_new_with_data(MAILMIME_DISPOSITION_TYPE_ATTACHMENT,
                    disposition_name, NULL, NULL, NULL, (size_t) -1);
    if (disposition == NULL)
        goto enomem;
    disposition_name = NULL;

    content = mailmime_content_new_with_str(mime_type);
    if (content == NULL)
        goto enomem;

    encoding_type = MAILMIME_MECHANISM_BASE64;
    encoding = mailmime_mechanism_new(encoding_type, NULL);
    if (encoding == NULL)
        goto enomem;

    mime_fields = mailmime_fields_new_with_data(encoding, NULL, NULL,
            disposition, NULL);
    if (mime_fields == NULL)
        goto enomem;
    encoding = NULL;
    disposition = NULL;

    mime = part_new_empty(content, mime_fields, 1);
    if (mime == NULL)
        goto enomem;
    content = NULL;
    mime_fields = NULL;

    r = mailmime_set_body_text(mime, data, length);
    if (r != 0)
        goto enomem;

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
    
    mp = part_new_empty(content, mime_fields, 0);
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

struct mailimf_date_time * timestamp_to_etpantime(const struct tm *ts)
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
#ifndef WIN32
    result->dt_zone = (int) (ts->tm_gmtoff / 36L);
#endif
    return result;
}

struct tm * etpantime_to_timestamp(const struct mailimf_date_time *et)
{
    struct tm * result = calloc(1, sizeof(struct tm));
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
#ifndef WIN32
    result->tm_gmtoff = 36L * (long) et->dt_zone;
#endif
    return result;
}

struct mailimf_mailbox * mailbox_from_string(
        const char *name,
        const char *address
    )
{
    struct mailimf_mailbox *mb = NULL;
    char *_name = NULL;
    char *_address = NULL;

    assert(address);

    _name = name ? strdup(name) : strdup("");
    if (_name == NULL)
        goto enomem;

    _address = strdup(address);
    if (_address == NULL)
        goto enomem;

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

static bool parameter_has_value(
        clist *list,
        const char *name,
        const char *value
    )
{
    clistiter *cur;

    assert(list);
    assert(name);
    assert(value);

    for (cur = clist_begin(list); cur != NULL ; cur = clist_next(cur)) {
        struct mailmime_parameter * param = clist_content(cur);
        if (param &&
                param->pa_name && strcmp(name, param->pa_name) == 0 &&
                param->pa_value && strcmp(value, param->pa_value) == 0)
            return true;
    }

    return false;
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

bool _is_multipart(struct mailmime_content *content)
{
    bool result = false;

    assert(content);

    if (content->ct_type && content->ct_type->tp_type ==
            MAILMIME_TYPE_COMPOSITE_TYPE &&
            content->ct_type->tp_data.tp_composite_type &&
            content->ct_type->tp_data.tp_composite_type->ct_type ==
            MAILMIME_COMPOSITE_TYPE_MULTIPART)
        result = true;

    return result;
}

bool _is_multipart_alternative(struct mailmime_content *content)
{
    bool result = false;

    assert(content);

    if (_is_multipart(content) && content->ct_subtype &&
            strcmp(content->ct_subtype, "alternative") == 0)
        result = true;

    return result;
}

bool _is_PGP_MIME(struct mailmime_content *content)
{
    bool result = false;

    assert(content);

    if (_is_multipart(content) && content->ct_subtype &&
            strcmp(content->ct_subtype, "encrypted") == 0 &&
            content->ct_parameters &&
            parameter_has_value(content->ct_parameters, "protocol",
                    "application/pgp-encrypted"))
        result = true;

    return result;
}

