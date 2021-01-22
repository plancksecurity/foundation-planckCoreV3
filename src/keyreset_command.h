// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef KEYRESET_COMMAND_H
#define KEYRESET_COMMAND_H

#include "dynamic_api.h"
#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _keyreset_command {
    pEp_identity * ident;
    char * new_key;
} keyreset_command;

// new_keyreset_command() - allocate new keyreset_command
//
//  parameters:
//      ident (in)      identity to reset, including fpr of existing key
//      new_key (in)    fpr of new key
//
//  return value:
//      pointer to keyreset_command or NULL on failure
//
//  caveat:
//      ident, new_key are copied and remain in the ownership of the caller

DYNAMIC_API keyreset_command * new_keyreset_command(const pEp_identity * ident, const char * new_key);


// free_keyreset_command() - free memory allocated by keyreset_command
//
//  parameters:
//      command (in)    pointer to keyreset_command to free

DYNAMIC_API void free_keyreset_command(keyreset_command * command);


// keyreset_command_dup() - duplicate keyreset_command (deep copy)
//
//  parameters:
//      src (in)        pointer to keyreset_command to duplicate
//
//  return value:
//      pointer to copy of src or NULL on failure

DYNAMIC_API keyreset_command * keyreset_command_dup(const keyreset_command * src);


typedef struct _keyreset_command_list {
    keyreset_command * command;
    struct _keyreset_command_list * next;
} keyreset_command_list;


// new_keyreset_command_list() - allocate a new keyreset_command_list
//
//  parameters:
//      command (in)              initial command
//
//  return value:
//      pointer to keyreset_command_list object or NULL if out of memory
//
//  caveat:
//      the ownership of the command goes to the keyreset_command_list
//      next pointer is NULL

DYNAMIC_API keyreset_command_list * new_keyreset_command_list(keyreset_command * command);


// keyreset_command_list_dup() - duplicate a keyreset_command_list (deep copy)
//
//  parameters:
//      src (in)                keyreset_command_list to copy
//
//  return value:
//      pointer to keyreset_command_list object or NULL if out of memory
//      keyreset_command command copies created by this function belong to the returned list

DYNAMIC_API keyreset_command_list * keyreset_command_list_dup(
        const keyreset_command_list * src
    );


// keyreset_command_list_add() - add key to keyreset_command_list
//
//  parameters:
//      command_list (in)       keyreset_command_list struct or NULL to create a new one
//      command (in)            keyreset_command to add
//
//  return value:
//      pointer to last element in keyreset_command_list or NULL if out of memory
//
//  caveat:
//      the ownership of the command goes to the keyreset_command_list if add is successful

DYNAMIC_API keyreset_command_list * keyreset_command_list_add(
        keyreset_command_list * command_list,
        keyreset_command * command
    );


// keyreset_command_list_append() - append keyreset_command_list to keyreset_command_list
//
//  parameters:
//      command_list (in)       keyreset_command_list struct to append to
//      second (in)             keyreset_command_list struct to append
//
//  return value:
//      pointer to last element in command_list or NULL if out of memory
//      or command_list is NULL
//
//  caveat:
//      all commands are being copied before being added to the list
//      the original commands are still being owned by the caller

DYNAMIC_API keyreset_command_list * keyreset_command_list_append(
        keyreset_command_list * command_list,
        keyreset_command_list * second
    );


// keyreset_command_list_length() - get length of keyreset_command_list
//
//  parameters:
//      command_list (in)       keyreset_command_list struct to determine length of
//
//  return value:
//      length of command_list in number of elements

DYNAMIC_API int keyreset_command_list_length(
        const keyreset_command_list * command_list
    );


// free_keyreset_command_list() - free memory occupied by command_list
//
//  parameters:
//      command_list (in)       keyreset_command_list to free

DYNAMIC_API void free_keyreset_command_list(keyreset_command_list * command_list);


#ifdef __cplusplus
}
#endif

#endif

