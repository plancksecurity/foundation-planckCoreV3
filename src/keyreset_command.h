/**
 * @file    keyreset_command.h
 * @brief   keyreset command structure and list memory, manipulation and informational functions
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#include "dynamic_api.h"
#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @struct	keyreset_command
 *  
 *  @brief	TODO
 *  
 */
typedef struct _keyreset_command {
    pEp_identity * ident;
    char * new_key;
} keyreset_command;

/**
 *  <!--       new_keyreset_command()       -->
 *  
 *  @brief Allocate new keyreset_command
 *  
 *  @param[in]     ident      identity to reset, including fpr of existing key
 *  @param[in]     new_key    fpr of new key
 *  
 *  @retval pointer to keyreset_command or NULL on failure
 *  
 *  @warning ident, new_key are copied and remain in the ownership of the caller
 *  
 */

DYNAMIC_API keyreset_command * new_keyreset_command(const pEp_identity * ident, const char * new_key);


/**
 *  <!--       free_keyreset_command()       -->
 *  
 *  @brief Free memory allocated by keyreset_command
 *  
 *  @param[in]     command    pointer to keyreset_command to free
 *  
 *  
 */

DYNAMIC_API void free_keyreset_command(keyreset_command * command);


/**
 *  <!--       keyreset_command_dup()       -->
 *  
 *  @brief Duplicate keyreset_command (deep copy)
 *  
 *  @param[in]     src    pointer to keyreset_command to duplicate
 *  
 *  @retval pointer to copy of src or NULL on failure
 *  
 *  
 */

DYNAMIC_API keyreset_command * keyreset_command_dup(const keyreset_command * src);


/**
 *  @struct	keyreset_command_list
 *  
 *  @brief	TODO
 *  
 */
typedef struct _keyreset_command_list {
    keyreset_command * command;
    struct _keyreset_command_list * next;
} keyreset_command_list;


/**
 *  <!--       new_keyreset_command_list()       -->
 *  
 *  @brief Allocate a new keyreset_command_list
 *  
 *  @param[in]     command    initial command
 *  
 *  @retval pointer to keyreset_command_list object or NULL if out of memory
 *  
 *  @warning the ownership of the command goes to the keyreset_command_list
 *           next pointer is NULL
 *  
 */

DYNAMIC_API keyreset_command_list * new_keyreset_command_list(keyreset_command * command);


/**
 *  <!--       keyreset_command_list_dup()       -->
 *  
 *  @brief Duplicate a keyreset_command_list (deep copy)
 *  
 *  @param[in]     src    keyreset_command_list to copy
 *  
 *  @retval pointer to keyreset_command_list object or NULL if out of memory
 *  @retval keyreset_command command copies created by this function belong to the returned list
 *  
 *  
 */

DYNAMIC_API keyreset_command_list * keyreset_command_list_dup(
        const keyreset_command_list * src
    );


/**
 *  <!--       keyreset_command_list_add()       -->
 *  
 *  @brief Add key to keyreset_command_list
 *  
 *  @param[in]     command_list    keyreset_command_list struct or NULL to create a new one
 *  @param[in]     command         keyreset_command to add
 *  
 *  @retval pointer to last element in keyreset_command_list or NULL if out of memory
 *  
 *  @warning the ownership of the command goes to the keyreset_command_list if add is successful
 *  
 */

DYNAMIC_API keyreset_command_list * keyreset_command_list_add(
        keyreset_command_list * command_list,
        keyreset_command * command
    );


/**
 *  <!--       keyreset_command_list_append()       -->
 *  
 *  @brief Append keyreset_command_list to keyreset_command_list
 *  
 *  @param[in]     command_list    keyreset_command_list struct to append to
 *  @param[in]     second          keyreset_command_list struct to append
 *  
 *  @retval pointer to last element in command_list or NULL if out of memory
 *  @retval or command_list is NULL
 *  
 *  @warning all commands are being copied before being added to the list
 *           the original commands are still being owned by the caller
 *  
 */

DYNAMIC_API keyreset_command_list * keyreset_command_list_append(
        keyreset_command_list * command_list,
        keyreset_command_list * second
    );


/**
 *  <!--       keyreset_command_list_length()       -->
 *  
 *  @brief Get length of keyreset_command_list
 *  
 *  @param[in]     command_list    keyreset_command_list struct to determine length of
 *  
 *  @retval length of command_list in number of elements
 *  
 *  
 */

DYNAMIC_API int keyreset_command_list_length(
        const keyreset_command_list * command_list
    );


/**
 *  <!--       free_keyreset_command_list()       -->
 *  
 *  @brief Free memory occupied by command_list
 *  
 *  @param[in]     command_list    keyreset_command_list to free
 *  
 *  
 */

DYNAMIC_API void free_keyreset_command_list(keyreset_command_list * command_list);


#ifdef __cplusplus
}
#endif

