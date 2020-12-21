/**
 * @file    pEp_string.h
 * @brief   external interface for allocation and deletion of NUL-terminated char strings within the engine
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PeP_STRING_H
#define PeP_STRING_H

#include <string.h>
#include "dynamic_api.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 *  <!--       new_string()       -->
 *  
 *  @brief Allocate a new string
 *  
 *  @param[in]   src    string to copy or NULL
 *  @param[in]   len    length of newly created string or 0 for default
 *  
 *  @retval pointer to string object or NULL if out of memory
 *  @retval calling with str and len is equivalent to strndup()
 *  @retval calling with str but len=0 is equivalent to strdup()
 *  @retval calling with str=NULL is equivalent to calloc()
 *  
 *  
 */

DYNAMIC_API char * new_string(const char *src, size_t len);


/**
 *  <!--       free_string()       -->
 *  
 *  @brief Free memory occupied by string
 *  
 *  @param[in]   s    pointer to string to free
 *  
 *  
 */

DYNAMIC_API void free_string(char *s);


/**
 *  <!--       string_dup()       -->
 *  
 *  @brief Duplicate a string
 *  
 *  @param[in]   src    string to duplicate
 *  @param[in]   len    length of newly created string or 0 for default
 *  
 *  @retval pointer to copy or NULL if out of memory
 *  
 *  
 */

DYNAMIC_API char * string_dup(const char *src, size_t len);


#ifdef __cplusplus
}
#endif

#endif
