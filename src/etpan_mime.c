#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "etpan_mime.h"
#ifndef mailmime_param_new_with_data
#include <libetpan/mailprivacy_tools.h>
#endif

time_t mail_mkgmtime(struct tm * tmp);

#define MAX_MESSAGE_ID 512

static char * generate_boundary(const char * boundary_prefix)
{
    char id[MAX_MESSAGE_ID];
    time_t now;
    char name[MAX_MESSAGE_ID];
    long value;
 
    id[MAX_MESSAGE_ID - 1] = 0;
    name[MAX_MESSAGE_ID - 1] = 0;

    now = time(NULL);

    value = random();
    gethostname(name, MAX_MESSAGE_ID - 1);
    
    if (boundary_prefix == NULL)
        boundary_prefix = "";
    
    snprintf(id, MAX_MESSAGE_ID, "%s%lx_%lx_%x", boundary_prefix, now, value,
            getpid());
    
    return strdup(id);
}

struct mailmime * part_new_empty(
        struct mailmime_content * content,
        struct mailmime_fields * mime_fields,
        const char * boundary_prefix,
        int force_single
    )
{
	struct mailmime * build_info;
	clist * list;
	int r;
	int mime_type;

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
				goto err;
			}
			break;

			default:
			goto err;
		}
	}

	if (mime_type == MAILMIME_MULTIPLE) {
		char * attr_name;
		char * attr_value;
		struct mailmime_parameter * param;
		clist * parameters;
		char * boundary;

		list = clist_new();
		if (list == NULL)
			goto err;

		attr_name = strdup("boundary");
		boundary = generate_boundary(boundary_prefix);
		attr_value = boundary;
		if (attr_name == NULL) {
			free(attr_name);
			goto free_list;
		}

		param = mailmime_parameter_new(attr_name, attr_value);
		if (param == NULL) {
			free(attr_value);
			free(attr_name);
			goto free_list;
		}

		if (content->ct_parameters == NULL) {
			parameters = clist_new();
			if (parameters == NULL) {
				mailmime_parameter_free(param);
				goto free_list;
			}
		}
		else
			parameters = content->ct_parameters;

		r = clist_append(parameters, param);
		if (r) {
			clist_free(parameters);
			mailmime_parameter_free(param);
			goto free_list;
		}

		if (content->ct_parameters == NULL)
			content->ct_parameters = parameters;
	}

	build_info = mailmime_new(mime_type,
		NULL, 0, mime_fields, content,
		NULL, NULL, NULL, list,
		NULL, NULL);
	if (build_info == NULL) {
		clist_free(list);
		return NULL;
	}

	return build_info;

	free_list:
	clist_free(list);
	err:
	return NULL;
}

struct mailmime * get_text_part(
        const char * mime_type,
        const char * text,
        size_t length,
        int encoding_type
    )
{
	struct mailmime_fields * mime_fields;
	struct mailmime * mime;
	struct mailmime_content * content;
	struct mailmime_parameter * param;
	struct mailmime_disposition * disposition;
	struct mailmime_mechanism * encoding;
    
	encoding = mailmime_mechanism_new(encoding_type, NULL);
	disposition = mailmime_disposition_new_with_data(MAILMIME_DISPOSITION_TYPE_INLINE,
		NULL, NULL, NULL, NULL, (size_t) -1);
	mime_fields = mailmime_fields_new_with_data(encoding,
		NULL, NULL, disposition, NULL);

	content = mailmime_content_new_with_str(mime_type);
	param = mailmime_param_new_with_data("charset", "utf-8");
	clist_append(content->ct_parameters, param);
	mime = part_new_empty(content, mime_fields, NULL, 1);
	mailmime_set_body_text(mime, (char *) text, length);
	
	return mime;
}

struct mailmime * get_file_part(
        const char * filename,
        const char * mime_type,
        char * data,
        size_t length
    )
{
    char * disposition_name;
    int encoding_type;
    struct mailmime_disposition * disposition;
    struct mailmime_mechanism * encoding;
    struct mailmime_content * content;
    struct mailmime * mime;
    struct mailmime_fields * mime_fields;

    disposition_name = NULL;
    if (filename != NULL) {
        disposition_name = strdup(filename);
    }
    disposition =
        mailmime_disposition_new_with_data(MAILMIME_DISPOSITION_TYPE_ATTACHMENT,
                disposition_name, NULL, NULL, NULL, (size_t) -1);
    content = mailmime_content_new_with_str(mime_type);

    encoding_type = MAILMIME_MECHANISM_BASE64;
    encoding = mailmime_mechanism_new(encoding_type, NULL);
    mime_fields = mailmime_fields_new_with_data(encoding,
        NULL, NULL, disposition, NULL);
    mime = part_new_empty(content, mime_fields, NULL, 1);
    mailmime_set_body_text(mime, data, length);

    return mime;
}

struct mailmime * part_multiple_new(
        const char * type,
        const char * boundary_prefix
    )
{
    struct mailmime_fields * mime_fields;
    struct mailmime_content * content;
    struct mailmime * mp;
    
    mime_fields = mailmime_fields_new_empty();
    if (mime_fields == NULL)
        goto err;
    
    content = mailmime_content_new_with_str(type);
    if (content == NULL)
        goto free_fields;
    
    mp = part_new_empty(content, mime_fields, boundary_prefix, 0);
    if (mp == NULL)
        goto free_content;
    
    return mp;
    
free_content:
    mailmime_content_free(content);
free_fields:
    mailmime_fields_free(mime_fields);
err:
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
    result->dt_zone = (int) (ts->tm_gmtoff / 36L);

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
    result->tm_gmtoff = 36L * (long) et->dt_zone;

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

