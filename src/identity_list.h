// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef IDENTITY_LIST_H
#define IDENTITY_LIST_H

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif


// new_identity_list() - allocate a new identity list
//
//  parameters:
//      ident (in)          identity to move for first element
//
//  return value:
//      new identity_list or NULL if out of memory
//
//  caveat:
//      ident is being moved if the function succeeds, the caller loses
//      ownership

DYNAMIC_API identity_list *new_identity_list(pEp_identity *ident);


// identity_list_dup() - duplicate identity_list (deep copy)
//
//  parameters:
//      id_list (in)        identity_list to copy
//
//  return value:
//      new identity_list or NULL if out of memory

DYNAMIC_API identity_list *identity_list_dup(const identity_list *src);


// free_identity_list() - free memory allocated by identity_list
//
//  parameters:
//      id_list (in)        identity_list to free
//
//  caveat:
//      this function frees all identities in the list additional to the
//      identity_list itself

DYNAMIC_API void free_identity_list(identity_list *id_list);


// identity_list_add - add identity to an identity_list
//
//  parameters:
//      id_list (in)        identity_list to add to
//      ident (in)          identity being added
//
//  return value:
//      pointer to the last element in identity_list or NULL if out of memory
//
//  caveat:
//      ident is being moved, the caller loses ownership if the function is
//      successful

DYNAMIC_API identity_list *identity_list_add(identity_list *id_list, pEp_identity *ident);

// identity_list_add - join second identity_list to the first.
//
//  parameters:
//      first_list (in)             identity_list to add to
//      second_list (in)            identity list to add
//
//  return value:
//      pointer to the HEAD of the new list, or NULL if both lists are empty.
//
DYNAMIC_API identity_list *identity_list_join(identity_list *first_list, identity_list* second_list);

// identity_list_length() - get length of identity_list
//
//  parameters:
//      id_list (in)        identity_list struct to determine length of
//
//  return value:
//      length of identity_list in number of elements

DYNAMIC_API int identity_list_length(const identity_list *id_list);

// Internal
PEP_STATUS set_all_userids_in_list(identity_list* id_list, const char* user_id);

#ifdef __cplusplus
}
#endif

#endif
