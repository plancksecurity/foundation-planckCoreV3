// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include <libetpan/libetpan.h>
#include <libetpan/mailmime.h>
#include <libetpan/mailmime_encode.h>

struct mailmime * part_new_empty(
        struct mailmime_content * content,
        struct mailmime_fields * mime_fields,
        int force_single
    );

struct mailmime * get_pgp_encrypted_part(void);

struct mailmime * get_text_part(
        const char * filename,
        const char * mime_type,
        const char * text,
        size_t length,
        int encoding_type
    );

struct mailmime * get_file_part(
        const char * filename,
        const char * mime_type,
        char * data,
        size_t length
    );

struct mailmime * part_multiple_new(const char *type);

typedef void *(*_new_func_t)(void *);

struct mailimf_field * _new_field(
        int type,
        _new_func_t new_func,
        void *value
    );

void _free_field(struct mailimf_field *field);

int _append_field(
        clist *list,
        int type,
        _new_func_t new_func,
        void *value
    );

struct mailimf_date_time * timestamp_to_etpantime(const struct tm *ts);
struct tm * etpantime_to_timestamp(const struct mailimf_date_time *et);

struct mailimf_mailbox * mailbox_from_string(
        const char *name,
        const char *address
    );

struct mailimf_field * create_optional_field(
        const char *field,
        const char *value
    );

int _append_optional_field(
        clist *list,
        const char *field,
        const char *value
    );

clist * _get_fields(struct mailmime * mime);
struct mailmime_content * _get_content(struct mailmime * mime);
char * _get_filename(struct mailmime *mime);
char * _get_content_id(struct mailmime *mime);
bool _is_multipart(struct mailmime_content *content, const char *subtype);
bool _is_PGP_MIME(struct mailmime_content *content);
bool _is_text_part(struct mailmime_content *content, const char *subtype);

int _get_content_type(
        const struct mailmime_content *content,
        char **type,
        char **charset
    );
