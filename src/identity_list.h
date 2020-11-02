/**
 * @file    identity_list.h
 * @brief   identity list functions and data structures (@see pEpIdentity)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif


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
 *  @param[in]   id_list    identity_list to copy
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
 */
PEP_STATUS set_all_userids_in_list(identity_list* id_list, const char* user_id);

#ifdef __cplusplus
}
#endif
