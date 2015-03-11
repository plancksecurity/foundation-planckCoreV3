#pragma once

#include "dynamic_api.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct _identity_list {
    pEp_identity *ident;
    struct _identity_list *next;
} identity_list;


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


#ifdef __cplusplus
}
#endif

