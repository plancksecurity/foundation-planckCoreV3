/**
 * @file    identity_list.h
 * @brief   identity list functions and data structures (@see pEpIdentity)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef IDENTITY_LIST_H
#define IDENTITY_LIST_H

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 *  <!--       identity_list_cons()       -->
 *
 *  @brief Given an element and a list return a new list starting with the
 *         element and having the old list as tail.
 *         If the element is null just return the old list as-is.
 *         This function is non-destructive: the old list remains usable and
 *         unchanged.
 *
 *  @param[in]   element    new element
 *  @param[in]   old_list   old list
 *
 *  @retval      new list; NULL if out of memory
 *
 *  @warning     element is being moved if the function succeeds: the caller
 *               loses its ownership
 *
 */
DYNAMIC_API identity_list *identity_list_cons(pEp_identity *element,
                                              identity_list *old_list);

/**
 *  <!--       identity_list_cons_copy()       -->
 *
 *  @brief Exactly like identity_list_cons, but copy the given identity (when
 *         non-null) instead of losing it.  The list is *not* copied.
 */
DYNAMIC_API identity_list *identity_list_cons_copy(pEp_identity *element,
                                                   identity_list *old_list);

/**
 *  <!--       identity_list_reversed()       -->
 *
 *  @brief Return a copy if the given list with copies of the elements in
 *         reversed order, and no null values.  This function is
 *         non-destructive: the old list remains usable and unchanged.
 *         Identities are copied.
 *
 *  @param[in]   old_list  old list
 *
 *  @retval      new list.  NULL if out of memory
 *
 */
DYNAMIC_API identity_list *identity_list_reversed(identity_list *old_list);

/**
 *  <!--       new_identity_list()       -->
 *  
 *  @brief Allocate a new identity list
 *  
 *  @param[in]   ident    identity to move for first element
 *  
 *  @retval        new identity_list or NULL if out of memory
 *  
 *  @warning       ident is being moved if the function succeeds, the caller loses
 *                 ownership
 *  
 */

DYNAMIC_API identity_list *new_identity_list(pEp_identity *ident);


/**
 *  <!--       identity_list_dup()       -->
 *  
 *  @brief Duplicate identity_list (deep copy)
 *  
 *  @param[in]   src    identity_list to copy
 *  
 *  @retval        new identity_list or NULL if out of memory
 *  
 *  
 */

DYNAMIC_API identity_list *identity_list_dup(const identity_list *src);


/**
 *  <!--       free_identity_list()       -->
 *  
 *  @brief Free memory allocated by identity_list
 *  
 *  @param[in]   id_list    identity_list to free
 *  
 *  @warning this function frees all identities in the list additional to the
 *           identity_list itself
 *  
 */

DYNAMIC_API void free_identity_list(identity_list *id_list);


/**
 *  <!--       identity_list_add()       -->
 *  
 *  @brief Add identity to an identity_list
 *  
 *  @param[in]   id_list    identity_list to add to
 *  @param[in]   ident      identity being added
 *  
 *  @retval pointer to the last element in identity_list or NULL if out of memory
 *  
 *  @warning ident is being moved, the caller loses ownership if the function is
 *           successful
 *  
 */

DYNAMIC_API identity_list *identity_list_add(identity_list *id_list, pEp_identity *ident);

/**
 *  <!--       identity_list_add_or_update()       -->
 *
 *  @brief Add identity to an identity_list or updates the FIRST
 *  identity with the same address, used for fpr, name, etc..
 *  adjacent updates to a list where the address is maintained
 *  but these are changed.
 *
 *  @param[in]   id_list    identity_list to add to
 *  @param[in]   ident      identity being added or updated
 *
 *  @retval pointer to the inserted or modified element in identity_list or NULL if
 *  out of memory or nothing is inserted
 *
 *  @warning ident is being moved, the caller loses ownership if the function is
 *           successful
 *
 */

DYNAMIC_API identity_list *identity_list_add_or_update(identity_list *id_list, pEp_identity *ident);


/**
 *  <!--       identity_list_add()       -->
 *  
 *  @brief Join second identity_list to the first.
 *  
 *  @param[in]   first_list     identity_list to add to
 *  @param[in]   second_list    identity list to add
 *  
 *  @retval pointer to the HEAD of the new list, or NULL if both lists are empty.
 *  
 *  
 */
DYNAMIC_API identity_list *identity_list_join(identity_list *first_list, identity_list* second_list);

/**
 *  <!--       identity_list_length()       -->
 *  
 *  @brief Get length of identity_list
 *  
 *  @param[in]   id_list    identity_list struct to determine length of
 *  
 *  @retval length of identity_list in number of elements
 *  
 *  
 */

DYNAMIC_API int identity_list_length(const identity_list *id_list);

// Internal
/**
 *  <!--       set_all_userids_in_list()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  id_list         identity_list*
 *  @param[in]  user_id         const char*
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *
 */
PEP_STATUS set_all_userids_in_list(identity_list* id_list, const char* user_id);

#ifdef __cplusplus
}
#endif

#endif
