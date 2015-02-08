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

struct mailmime * part_multiple_new(
        const char * type,
        const char * boundary_prefix
    );

