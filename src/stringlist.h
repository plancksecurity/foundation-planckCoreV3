/**
 * @file    stringlist.h
 * @brief   stringlist struct builders, accessorsm manipulators
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#include "dynamic_api.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 *  @struct    stringlist_t
 *  
 *  @brief    TODO
 *  
 */
typedef struct _stringlist_t {
    char *value;
    struct _stringlist_t *next;
} stringlist_t;


/**
 *  <!--       new_stringlist()       -->
 *  
 *  @brief Allocate a new stringlist
 *  
 *  @param[in]   value    initial value as C string or NULL for empty list
 *  
 *  @retval pointer to stringlist_t object or NULL if out of memory
 *  
 *  @warning the value is being copied before being added to the list
 *           the original string is still being owned by the caller
 *           the "next" pointer of the returned object is NULL
 *  
 */

DYNAMIC_API stringlist_t *new_stringlist(const char *value);


/**
 *  <!--       stringlist_dup()       -->
 *  
 *  @brief Duplicate a stringlist
 *  
 *  @param[in]   src    stringlist to copy
 *  
 *  @retval pointer to stringlist_t object or NULL if out of memory
 *  
 *  
 */

DYNAMIC_API stringlist_t *stringlist_dup(const stringlist_t *src);


/**
 *  <!--       stringlist_add()       -->
 *  
 *  @brief Add key to stringlist
 *  
 *  @param[in]   stringlist    stringlist struct or NULL to create a new one
 *  @param[in]   value         value as C string
 *  
 *  @retval pointer to last element in stringlist or NULL if out of memory
 *  
 *  @warning the value is being copied before being added to the list
 *           the original string is still being owned by the caller
 *  
 */

DYNAMIC_API stringlist_t *stringlist_add(
        stringlist_t *stringlist,
        const char *value
    );

/**
 *  <!--       stringlist_add_unique()       -->
 *  
 *  @brief Add string to stringlist, if not already there
 *  
 *  @param[in]   stringlist    stringlist struct or NULL to create a new one
 *  @param[in]   value         value as C string
 *  
 *  @retval pointer to last element in stringlist or NULL if out of memory
 *  
 *  @warning the value is being copied before being added to the list
 *           the original string is still being owned by the caller
 *  
 */

DYNAMIC_API stringlist_t *stringlist_add_unique(
        stringlist_t *stringlist,
        const char *value
    );


/**
 *  <!--       stringlist_append()       -->
 *  
 *  @brief Append stringlist to stringlist
 *  
 *  @param[in]   stringlist    stringlist struct to append to
 *  @param[in]   second        stringlist struct to append
 *  
 *  @retval pointer to last element in stringlist or NULL if out of memory
 *  @retval or stringpair_list is NULL
 *  
 *  @warning all values are being copied before being added to the list
 *           the original values are still being owned by the caller
 *  
 */

DYNAMIC_API stringlist_t *stringlist_append(
        stringlist_t *stringlist,
        stringlist_t *second
    );


/**
 *  <!--       stringlist_length()       -->
 *  
 *  @brief Get length of stringlist
 *  
 *  @param[in]   stringlist    stringlist struct to determine length of
 *  
 *  @retval length of stringlist in number of elements
 *  
 *  
 */

DYNAMIC_API int stringlist_length(const stringlist_t *stringlist);


/**
 *  <!--       stringlist_delete()       -->
 *  
 *  @brief Delete entry from stringlist
 *  
 *  @param[in]   stringlist    stringlist struct to delete from
 *  @param[in]   value         data to delete
 *  
 *  @retval modified stringlist
 *  
 *  
 */

DYNAMIC_API stringlist_t *stringlist_delete(
        stringlist_t *stringlist,
        const char *value
    );


/**
 *  <!--       free_stringlist()       -->
 *  
 *  @brief Free memory occupied by stringlist
 *  
 *  @param[in]   stringlist    stringlist to free
 *  
 *  
 */

DYNAMIC_API void free_stringlist(stringlist_t *stringlist);

/**
 *  <!--       stringlist_search()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  head         stringlist_t*
 *  @param[in]  value        const char*
 *  
 */
stringlist_t* stringlist_search(stringlist_t* head, const char* value);
stringlist_t* stringlist_get_tail(stringlist_t* sl);

// create comma-separated string
/**
 *  <!--       stringlist_to_string()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  list        stringlist_t*
 *  
 */
char* stringlist_to_string(stringlist_t* list);
/**
 *  <!--       string_to_stringlist()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  str         const char*
 *  
 */
stringlist_t* string_to_stringlist(const char* str);

/**
 *  <!--       dedup_stringlist()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  stringlist         stringlist_t*
 *  
 */
void dedup_stringlist(stringlist_t* stringlist);

#ifdef __cplusplus
}
#endif
