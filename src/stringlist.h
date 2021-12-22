// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef STRINGLIST_H
#define STRINGLIST_H

#include "dynamic_api.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct _stringlist_t {
    char *value;
    struct _stringlist_t *next;
} stringlist_t;


// new_stringlist() - allocate a new stringlist
//
//  parameters:
//      value (in)        initial value as C string or NULL for empty list
//
//  return value:
//      pointer to stringlist_t object or NULL if out of memory
//
//  caveat:
//      the value is being copied before being added to the list
//      the original string is still being owned by the caller
//      the "next" pointer of the returned object is NULL

DYNAMIC_API stringlist_t *new_stringlist(const char *value);


// stringlist_dup() - duplicate a stringlist
//
//  parameters:
//      src (in)            stringlist to copy
//
//  return value:
//      pointer to stringlist_t object or NULL if out of memory

DYNAMIC_API stringlist_t *stringlist_dup(const stringlist_t *src);


// stringlist_add() - add key to stringlist
//
//  parameters:
//      stringlist (in)     stringlist struct or NULL to create a new one
//      value (in)          value as C string
//
//  return value:
//      pointer to last element in stringlist or NULL if out of memory
//
//  caveat:
//      the value is being copied before being added to the list
//      the original string is still being owned by the caller

DYNAMIC_API stringlist_t *stringlist_add(
        stringlist_t *stringlist,
        const char *value
    );

// stringlist_add_unique() - add string to stringlist, if not already there
//
//  parameters:
//      stringlist (in)     stringlist struct or NULL to create a new one
//      value (in)          value as C string
//
//  return value:
//      pointer to last element in stringlist or NULL if out of memory
//
//  caveat:
//      the value is being copied before being added to the list
//      the original string is still being owned by the caller

DYNAMIC_API stringlist_t *stringlist_add_unique(
        stringlist_t *stringlist,
        const char *value
    );


// stringlist_append() - append stringlist to stringlist
//
//  parameters:
//      stringlist (in)     stringlist struct to append to
//      second (in)         stringlist struct to append
//
//  return value:
//      pointer to last element in stringlist or NULL if out of memory
//      or stringpair_list is NULL
//
//  caveat:
//      all values are being copied before being added to the list
//      the original values are still being owned by the caller

DYNAMIC_API stringlist_t *stringlist_append(
        stringlist_t *stringlist,
        stringlist_t *second
    );


// stringlist_length() - get length of stringlist
//
//  parameters:
//      stringlist (in)     stringlist struct to determine length of
//
//  return value:
//      length of stringlist in number of elements

DYNAMIC_API int stringlist_length(const stringlist_t *stringlist);


// stringlist_delete() - delete entry from stringlist
//
//  parameters:
//      stringlist (in)     stringlist struct to delete from
//      value (in)          data to delete
//
//  return value:
//      modified stringlist

DYNAMIC_API stringlist_t *stringlist_delete(
        stringlist_t *stringlist,
        const char *value
    );


// free_stringlist() - free memory occupied by stringlist
//
//  parameters:
//      stringlist (in)    stringlist to free

DYNAMIC_API void free_stringlist(stringlist_t *stringlist);

stringlist_t* stringlist_search(stringlist_t* head, const char* value);
stringlist_t* stringlist_get_tail(stringlist_t* sl);

// create comma-separated string
char* stringlist_to_string(stringlist_t* list);
stringlist_t* string_to_stringlist(const char* str);

void dedup_stringlist(stringlist_t* stringlist);

#ifdef __cplusplus
}
#endif

#endif
