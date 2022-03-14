/**
 * @internal
 * @file    resource_id.h
 * @brief   resource id (filenames, uids) structs and access/generation/manipulation functions
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef RESOURCE_ID_H
#define RESOURCE_ID_H

/* structs to contain info about parsed resource ids (filenames, uids) */
/**
 *  @internal
 *  @enum    pEp_resource_id_type
 *  
 *  @brief    TODO
 *  
 */
typedef enum _resource_id_type {
    PEP_RID_FILENAME,
    PEP_RID_CID
} pEp_resource_id_type;

typedef struct pEp_rid_list_t pEp_rid_list_t;

/**
 *  @internal
 *  @struct    pEp_rid_list_t
 *  
 *  @brief    TODO
 *  
 */
struct pEp_rid_list_t {
    pEp_resource_id_type rid_type;
    char* rid;
    pEp_rid_list_t* next;    
};

pEp_rid_list_t* new_rid_node(pEp_resource_id_type type, const char* resource);

/**
 *  @internal
 *  <!--       free_rid_list()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  list         pEp_rid_list_t*
 *  
 */
void free_rid_list(pEp_rid_list_t* list);

/**
 *  @internal
 *  <!--       parse_uri()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  uri         const char*
 *  
 */
pEp_rid_list_t* parse_uri(const char* uri);

/**
 *  @internal
 *  <!--       build_uri()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  uri_prefix         const char*
 *  @param[in]  resource         const char*
 *  
 */
char* build_uri(const char* uri_prefix, const char* resource);

/**
 *  @internal
 *  <!--       get_resource_ptr_noown()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  uri         const char*
 *  
 */
const char* get_resource_ptr_noown(const char* uri);

/**
 *  @internal
 *  <!--       get_resource()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  uri         char*
 *  
 */
char* get_resource(char* uri);

/**
 *  @internal
 *  <!--       is_file_uri()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  str         char*
 *  
 */
bool is_file_uri(char* str);

/**
 *  @internal
 *  <!--       is_cid_uri()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  str         const char*
 *  
 */
bool is_cid_uri(const char* str);

#endif
