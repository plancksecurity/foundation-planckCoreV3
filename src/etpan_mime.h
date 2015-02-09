#pragma once

#include <libetpan/libetpan.h>


struct mailmime * part_new_empty(
        struct mailmime_content * content,
        struct mailmime_fields * mime_fields,
        const char * boundary_prefix,
        int force_single
    );

struct mailmime * get_text_part(
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

struct mailmime * part_multiple_new(
        const char * type,
        const char * boundary_prefix
    );

