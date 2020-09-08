/**
 * @file    resource_id.h
 * @brief   resource id (filenames, uids) structs and access/generation/manipulation functions
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

/* structs to contain info about parsed resource ids (filenames, uids) */
typedef enum _resource_id_type {
    PEP_RID_FILENAME,
    PEP_RID_CID
} pEp_resource_id_type;

typedef struct pEp_rid_list_t pEp_rid_list_t;

/**
 *  @struct	pEp_rid_list_t
 *  
 *  @brief	TODO
 *  
 */
struct pEp_rid_list_t {
    pEp_resource_id_type rid_type;
    char* rid;
    pEp_rid_list_t* next;    
};

pEp_rid_list_t* new_rid_node(pEp_resource_id_type type, const char* resource);

/**
 *  <!--       free_rid_list()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*list		pEp_rid_list_t
 *  
 */
void free_rid_list(pEp_rid_list_t* list);

/**
 *  <!--       parse_uri()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*uri		constchar
 *  
 */
pEp_rid_list_t* parse_uri(const char* uri);

/**
 *  <!--       build_uri()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*uri_prefix		constchar
 *  @param[in]	*resource		constchar
 *  
 */
char* build_uri(const char* uri_prefix, const char* resource);

/**
 *  <!--       get_resource_ptr_noown()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*uri		constchar
 *  
 */
const char* get_resource_ptr_noown(const char* uri);

/**
 *  <!--       get_resource()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*uri		char
 *  
 */
char* get_resource(char* uri);

/**
 *  <!--       is_file_uri()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*str		char
 *  
 */
bool is_file_uri(char* str);

/**
 *  <!--       is_cid_uri()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*str		constchar
 *  
 */
bool is_cid_uri(const char* str);
