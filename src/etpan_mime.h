/**
 * @internal
 * @file    etpan_mime.h
 * @brief   Driver for the libetpan MIME implementation (@see mime.h for the general API)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef ETPAN_MIME_H
#define ETPAN_MIME_H

#define _EXPORT_PEP_ENGINE_DLL

#include <libetpan/libetpan.h>
#include <libetpan/mailmime.h>
#include <libetpan/mailmime_encode.h>

#include "resource_id.h"
#include "stringpair.h"
#include "timestamp.h"

/**
 *  @internal
 *  <!--       part_new_empty()       -->
 *  
 *  @brief        TODO
 *  
 *  @param[in]  content             struct mailmime_content*
 *  @param[in]  mime_fields         struct mailmime_fields*
 *  @param[in]  param_keyvals       stringpair_list_t*
 *  @param[in]  force_single        int
 *  
 */
struct mailmime * part_new_empty(
        struct mailmime_content * content,
        struct mailmime_fields * mime_fields,
        stringpair_list_t* param_keyvals,        
        int force_single
    );

/**
 *  @internal
 *  <!--       get_pgp_encrypted_part()       -->
 *  
 *  @brief          TODO
 *  
 *  
 */
struct mailmime * get_pgp_encrypted_part(void);

/**
 *  @internal
 *  <!--       get_text_part()       -->
 *  
 *  @brief          TODO
 *  
 *  @param[in]  resource         pEp_rid_list_t*
 *  @param[in]  mime_type        const char*
 *  @param[in]  text             const char*
 *  @param[in]  length           size_t
 *  @param[in]  encoding_type    int
 *  
 */
struct mailmime * get_text_part(
        pEp_rid_list_t* resource,
        const char * mime_type,
        const char * text,
        size_t length,
        int encoding_type
    );

/**
 *  @internal
 *  <!--       get_file_part()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  resource                         pEp_rid_list_t*
 *  @param[in]  mime_type                        const char*
 *  @param[in]  data                             char*
 *  @param[in]  length                           size_t
 *  @param[in]  set_attachment_forward_comment   bool
 *  
 */
struct mailmime * get_file_part(
        pEp_rid_list_t* resource,
        const char * mime_type,
        char * data,
        size_t length,
        bool set_attachment_forward_comment
    );

/**
 *  @internal
 *  <!--       part_multiple_new()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  type         const char*
 *  
 */
struct mailmime * part_multiple_new(const char *type);

typedef void *(*_new_func_t)(void *);

/**
 *  @internal
 *  <!--       _new_field()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  type        int
 *  @param[in]  new_func    _new_func_t
 *  @param[in]  value       void*
 *  
 */
struct mailimf_field * _new_field(
        int type,
        _new_func_t new_func,
        void *value
    );

/**
 *  @internal
 *  <!--       _free_field()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  field         struct mailimf_field*
 *  
 */
void _free_field(struct mailimf_field *field);

/**
 *  @internal
 *  <!--       _append_field()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  list         clist*
 *  @param[in]  type         int
 *  @param[in]  new_func     _new_func_t
 *  @param[in]  value        void*
 *  
 */
int _append_field(
        clist *list,
        int type,
        _new_func_t new_func,
        void *value
    );

/**
 *  @internal
 *  <!--       timestamp_to_etpantime()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  ts         const timestamp*
 *  
 */
struct mailimf_date_time * timestamp_to_etpantime(const timestamp *ts);
/**
 *  @internal
 *  <!--       etpantime_to_timestamp()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  et         const struct mailimf_date_time*
 *  
 */
timestamp * etpantime_to_timestamp(const struct mailimf_date_time *et);

/**
 *  @internal
 *  <!--       mailbox_from_string()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  name         const char**
 *  @param[in]  address      const char**
 *  
 */
struct mailimf_mailbox * mailbox_from_string(
        const char *name,
        const char *address
    );

/**
 *  @internal
 *  <!--       create_optional_field()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  field         const char*
 *  @param[in]  value         const char*
 *  
 */
struct mailimf_field * create_optional_field(
        const char *field,
        const char *value
    );

/**
 *  @internal
 *  <!--       _append_optional_field()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  list         clist*
 *  @param[in]  field        const char*
 *  @param[in]  value        const char*
 *  
 */
int _append_optional_field(
        clist *list,
        const char *field,
        const char *value
    );

/**
 *  @internal
 *  <!--       _get_fields()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  mime         struct mailmime*
 *  
 */
clist * _get_fields(struct mailmime * mime);
/**
 *  @internal
 *  <!--       _get_content()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  mime         struct mailmime*
 *  
 */
struct mailmime_content * _get_content(struct mailmime * mime);
/**
 *  @internal
 *  <!--       _get_filename_or_cid()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  mime         struct mailmime*
 *  
 */
char * _get_filename_or_cid(struct mailmime *mime);
/**
 *  @internal
 *  <!--       _get_resource_id_list()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  mime         struct mailmime*
 *  
 */
pEp_rid_list_t* _get_resource_id_list(struct mailmime *mime);
/**
 *  @internal
 *  <!--       _build_uri()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  uri_prefix       char*
 *  @param[in]  resource         char*
 *  
 */
char* _build_uri(char* uri_prefix, char* resource);
/**
 *  @internal
 *  <!--       _is_multipart()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  content         struct mailmime_content*
 *  @param[in]  subtype         const char*
 *  
 */
bool _is_multipart(struct mailmime_content *content, const char *subtype);
/**
 *  @internal
 *  <!--       _is_PGP_MIME()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  content         struct mailmime_content*
 *  
 */
bool _is_PGP_MIME(struct mailmime_content *content);
/**
 *  @internal
 *  <!--       _is_text_part()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  content         struct mailmime_content*
 *  @param[in]  subtype         const char*
 *  
 */
bool _is_text_part(struct mailmime_content *content, const char *subtype);
/**
 *  @internal
 *  <!--       must_field_value_be_encoded()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  field_value         const char*
 *  
 */
bool must_field_value_be_encoded(const char* field_value);
/**
 *  @internal
 *  <!--       must_chunk_be_encoded()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  value         const void*
 *  @param[in]  size          size_t
 *  @param[in]  ignore_fws    bool
 *  
 */
bool must_chunk_be_encoded(const void* value, size_t size, bool ignore_fws);


/**
 *  @internal
 *  <!--       _get_content_type()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  content         const struct mailmime_content*
 *  @param[in]  type            char**
 *  @param[in]  charset         char**
 *  
 */
int _get_content_type(
        const struct mailmime_content *content,
        char **type,
        char **charset
    );


#endif
