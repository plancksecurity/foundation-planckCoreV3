// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _revocation_info {
    char* revoked_fpr,
    char* own_address,
    char* replacement_fpr,
    uint64_t revocation_date
} revocation_info;

typedef struct _revocation_info_list {
    revocation_info* info,
    struct _revocation_info_list* next;
} revocation_info_list_t;

DYNAMIC_API revocation_info* new_revocation_info(char* revoked_fpr,
                                                char* own_address,
                                                char* replacement_fpr,
                                                uint64_t revocation_date);

DYNAMIC_API void free_revocation_info(revocation_info* rev_info);

DYNAMIC_API revocation_info* revocation_info_dup(revocation_info* rev_info);

// new_revocation_info_list() - allocate a new revocation info list
//
//  parameters:
//      rev_info (in)          revocation info to move for first element
//
//  return value:
//      new revocation_info_list or NULL if out of memory
//
//  caveat:
//      rev_info is being moved if the function succeeds, the caller loses
//      ownership

DYNAMIC_API revocation_info_list_t* new_revocation_info_list(revocation_info *rev_info);


// revocation_info_list_dup() - duplicate revocation_info_list (deep copy)
//
//  parameters:
//      rev_list (in)        revocation_info_list to copy
//
//  return value:
//      new revocation_info_list or NULL if out of memory

DYNAMIC_API revocation_info_list_t* revocation_info_list_dup(const revocation_info_list_t* src);


// free_revocation_info_list() - free memory allocated by revocation_info_list
//
//  parameters:
//      rev_list (in)        revocation_info_list to free
//
//  caveat:
//      this function frees all rev_infoities in the list additional to the
//      revocation_info_list itself

DYNAMIC_API void free_revocation_info_list(revocation_info_list_t* rev_list);


// revocation_info_list_add - add revocation info to an revocation_info_list
//
//  parameters:
//      rev_list (in)        revocation_info_list to add to
//      rev_info (in)          revocation info being added
//
//  return value:
//      pointer to the last element in revocation_info_list or NULL if out of memory
//
//  caveat:
//      rev_info is being moved, the caller loses ownership if the function is
//      successful

DYNAMIC_API revocation_info_list_t* revocation_info_list_add(revocation_info_list_t* rev_list, revocation_info *rev_info);

// revocation_info_list_add - join second revocation_info_list to the first.
//
//  parameters:
//      first_list (in)             revocation_info_list to add to
//      second_list (in)            revocation info list to add
//
//  return value:
//      pointer to the HEAD of the new list, or NULL if both lists are empty.
//
DYNAMIC_API revocation_info_list_t* revocation_info_list_join(revocation_info_list_t* first_list, revocation_info_list* second_list);

// revocation_info_list_length() - get length of revocation_info_list
//
//  parameters:
//      rev_list (in)        revocation_info_list struct to determine length of
//
//  return value:
//      length of revocation_info_list in number of elements

DYNAMIC_API int revocation_info_list_length(const revocation_info_list_t* rev_list);

#ifdef __cplusplus
}
#endif
