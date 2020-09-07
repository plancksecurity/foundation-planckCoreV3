/**
 * @file    etpan_mime.h
 * @brief   Driver for the libetpan MIME implementation (@see mime.h for the general API)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#define _EXPORT_PEP_ENGINE_DLL

#include <libetpan/libetpan.h>
#include <libetpan/mailmime.h>
#include <libetpan/mailmime_encode.h>

#include "resource_id.h"
#include "stringpair.h"
#include "timestamp.h"

struct mailmime * part_new_empty(
        struct mailmime_content * content,
        struct mailmime_fields * mime_fields,
        stringpair_list_t* param_keyvals,        
        int force_single
    );

struct mailmime * get_pgp_encrypted_part(void);

struct mailmime * get_text_part(
        pEp_rid_list_t* resource,
        const char * mime_type,
        const char * text,
        size_t length,
        int encoding_type
    );

struct mailmime * get_file_part(
        pEp_rid_list_t* resource,
        const char * mime_type,
        char * data,
        size_t length,
        bool set_attachment_forward_comment
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

struct mailimf_date_time * timestamp_to_etpantime(const timestamp *ts);
timestamp * etpantime_to_timestamp(const struct mailimf_date_time *et);

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
char * _get_filename_or_cid(struct mailmime *mime);
pEp_rid_list_t* _get_resource_id_list(struct mailmime *mime);
char* _build_uri(char* uri_prefix, char* resource);
bool _is_multipart(struct mailmime_content *content, const char *subtype);
bool _is_PGP_MIME(struct mailmime_content *content);
bool _is_text_part(struct mailmime_content *content, const char *subtype);
bool must_field_value_be_encoded(const char* field_value);
bool must_chunk_be_encoded(const void* value, size_t size, bool ignore_fws);


int _get_content_type(
        const struct mailmime_content *content,
        char **type,
        char **charset
    );
