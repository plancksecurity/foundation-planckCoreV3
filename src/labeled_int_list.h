/**
 * @file    labeled_int_list.h
 * @brief   list structure which binds ints to labels
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#include "dynamic_api.h"
#include "stringpair.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @struct	labeled_int_list_t
 *  
 *  @brief	TODO
 *  
 */
typedef struct _labeled_int_list_t {
    int value;
    char* label;                                // UTF-8 string, null-terminated
    struct _labeled_int_list_t *next;           // this is a single linked list
} labeled_int_list_t;

DYNAMIC_API labeled_int_list_t *new_labeled_int_list(int value, const char* label);

/**
 *  <!--       free_labeled_int_list()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*labeled_int_list		labeled_int_list_t
 *  
 */
DYNAMIC_API void free_labeled_int_list(labeled_int_list_t *labeled_int_list);

/**
 *  <!--       labeled_int_list_dup()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*src		constlabeled_int_list_t
 *  
 */
DYNAMIC_API labeled_int_list_t *labeled_int_list_dup(const labeled_int_list_t *src);

/**
 *  <!--       labeled_int_list_add()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*labeled_int_list		labeled_int_list_t
 *  @param[in]	value		int
 *  @param[in]	*label		constchar
 *  
 */
DYNAMIC_API labeled_int_list_t *labeled_int_list_add(labeled_int_list_t *labeled_int_list, int value, const char* label);

/**
 *  <!--       labeled_int_list_length()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*labeled_int_list		constlabeled_int_list_t
 *  
 */
DYNAMIC_API int labeled_int_list_length(const labeled_int_list_t *labeled_int_list);

#ifdef __cplusplus
}
#endif
