// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef STRINGPAIR_H
#define STRINGPAIR_H

#include "dynamic_api.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct _stringpair_t {
    char * key;   // may point to "" but must not be NULL!
    char * value; // may point to "" but must not be NULL!
} stringpair_t;


// new_stringpair() - allocate new stringpair_t
//
//  parameters:
//      key (in)        utf-8 string used as key, should not be NULL
//      value (in)      utf-8 string containing the value, should not be NULL
//
//  return value:
//      pointer to stringpair_t or NULL on failure
//
//  caveat:
//      key and value are copied and remain in the ownership of the caller

DYNAMIC_API stringpair_t * new_stringpair(const char *key, const char *value);


// free_stringpair() - free memory allocated by stringpair_t
//
//  parameters:
//      pair (in)       pointer to stringpair_t to free

DYNAMIC_API void free_stringpair(stringpair_t * pair);


// stringpair_dup() - duplicate stringpair_t (deep copy)
//
//  parameters:
//      src (in)        pointer to stringpair_t to duplicate
//
//  return value:
//      pointer to copy of src or NULL on failure

DYNAMIC_API stringpair_t * stringpair_dup(const stringpair_t *src);


typedef struct _stringpair_list_t {
    stringpair_t *value;
    struct _stringpair_list_t *next;
} stringpair_list_t;


// new_stringpair_list() - allocate a new stringpair_list
//
//  parameters:
//      value (in)              initial value
//
//  return value:
//      pointer to stringpair_list_t object or NULL if out of memory
//
//  caveat:
//      the ownership of the value goes to the stringpair_list
//      next pointer is NULL

DYNAMIC_API stringpair_list_t *new_stringpair_list(stringpair_t *value);


// stringpair_list_dup() - duplicate a stringpair_list (deep copy)
//
//  parameters:
//      src (in)                stringpair_list to copy
//
//  return value:
//      pointer to stringpair_list_t object or NULL if out of memory
//      stringpair value copies created by this function belong to the returned list

DYNAMIC_API stringpair_list_t *stringpair_list_dup(
        const stringpair_list_t *src
    );


// stringpair_list_add() - add key to stringpair_list
//
//  parameters:
//      stringpair_list (in)    stringpair_list struct or NULL to create a new
//                              one
//      value (in)              stringpair to add
//
//  return value:
//      pointer to last element in stringpair_list or NULL if out of memory
//
//  caveat:
//      the ownership of the value goes to the stringpair_list if add is successful

DYNAMIC_API stringpair_list_t *stringpair_list_add(
        stringpair_list_t *stringpair_list,
        stringpair_t *value
    );


// stringpair_list_append() - append stringpair_list to stringpair_list
//
//  parameters:
//      stringpair_list (in)    stringpair_list struct to append to
//      second (in)             stringpair_list struct to append
//
//  return value:
//      pointer to last element in stringpair_list or NULL if out of memory
//      or stringpair_list is NULL
//
//  caveat:
//      all values are being copied before being added to the list
//      the original values are still being owned by the caller

DYNAMIC_API stringpair_list_t *stringpair_list_append(
        stringpair_list_t *stringpair_list,
        stringpair_list_t *second
    );


// stringpair_list_length() - get length of stringpair_list
//
//  parameters:
//      stringpair_list (in)    stringpair_list struct to determine length of
//
//  return value:
//      length of stringpair_list in number of elements

DYNAMIC_API int stringpair_list_length(
        const stringpair_list_t *stringpair_list
    );


// free_stringpair_list() - free memory occupied by stringpair_list
//
//  parameters:
//      stringpair_list (in)    stringpair_list to free

DYNAMIC_API void free_stringpair_list(stringpair_list_t *stringpair_list);


// stringpair_list_find() - find element in list using key
//
//  parameters:
//      stringpair_list (in)    list to search
//      key (in)                key to search for
//
//  return value:
//      node with result if found or NULL if not

DYNAMIC_API stringpair_list_t *stringpair_list_find(
        stringpair_list_t *stringpair_list,
        const char *key
    );

/**
 *  <!--       stringpair_list_find_case_insensitive()       -->
 *  
 *  @brief Identical to stringpair_list_find except that the key comparison
 *         is performed case-insensitively; of course there is no restriction
 *         on values.
 *  
 */
DYNAMIC_API stringpair_list_t *stringpair_list_find_case_insensitive(
        stringpair_list_t *stringpair_list,
        const char *key
    );

// ONLY DELETES ONE.
DYNAMIC_API stringpair_list_t *stringpair_list_delete_by_key(
        stringpair_list_t *sp_list,
        const char *key
    );


#ifdef __cplusplus
}
#endif

#endif
