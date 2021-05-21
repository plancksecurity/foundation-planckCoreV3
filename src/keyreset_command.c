/**
 * @file    keyreset_command.c
 * @brief   implementation of keyreset command structure and list memory,
 *          manipulation and informational functions
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#include "pEp_internal.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "keyreset_command.h"

DYNAMIC_API keyreset_command * new_keyreset_command(const pEp_identity * ident, const char * new_key)
{
    keyreset_command * command = NULL;

    // key and command should not be NULL, that's bad style (while legal)

    assert(ident);
    assert(new_key);

    command = calloc(1, sizeof(keyreset_command));
    assert(command);
    if (command == NULL)
        goto enomem;

    command->ident = ident ? identity_dup(ident) : new_identity(NULL, NULL, NULL, NULL);
    if (command->ident == NULL)
        goto enomem;
    
    if (command->ident && command->ident->fpr) {
        // make content uppercase
        for (size_t i=0; i<strlen(command->ident->fpr); i++)
            command->ident->fpr[i] = toupper(command->ident->fpr[i]);
    }
    
    command->new_key = new_key ? strdup(new_key) : strdup("");
    assert(command->new_key);
    if (command->new_key == NULL)
        goto enomem;

    // make content uppercase
    for (size_t i=0; i<strlen(command->new_key); i++)
        command->new_key[i] = toupper(command->new_key[i]);
    
    return command;

enomem:
    free_keyreset_command(command);
    return NULL;
}

DYNAMIC_API void free_keyreset_command(keyreset_command * command)
{
    if (command) {
        free_identity(command->ident);
        free(command->new_key);
        free(command);
    }
}

DYNAMIC_API keyreset_command * keyreset_command_dup(const keyreset_command * src)
{
    assert(src);
    if (src == NULL)
        return NULL;
    
    return new_keyreset_command(src->ident, src->new_key);
}

DYNAMIC_API keyreset_command_list * new_keyreset_command_list(keyreset_command * command)
{
    keyreset_command_list * result = calloc(1, sizeof(keyreset_command_list));
    assert(result);

    if (result && command)
        result->command = command;
    
    return result;
}

DYNAMIC_API keyreset_command_list * keyreset_command_list_dup(
        const keyreset_command_list * src
    )
{
    assert(src);
    if (src == NULL)
        return NULL;

    keyreset_command * cpy = keyreset_command_dup(src->command);
    
    keyreset_command_list * dst = new_keyreset_command_list(cpy);
    if (dst == NULL)
        return NULL;

    keyreset_command_list * src_curr = src->next;
    keyreset_command_list ** dst_curr_ptr = &dst->next;

    while (src_curr) {
        cpy = keyreset_command_dup(src_curr->command);
        if (cpy == NULL) {
            free_keyreset_command_list(dst);
            return NULL;
        }
        *dst_curr_ptr = new_keyreset_command_list(cpy);
        if (*dst_curr_ptr == NULL) {
            free_keyreset_command(cpy);
            free_keyreset_command_list(dst);
            return NULL;
        }
        src_curr = src_curr->next;
        dst_curr_ptr = &((*dst_curr_ptr)->next);
    }

    return dst;
}

DYNAMIC_API keyreset_command_list * keyreset_command_list_add(
        keyreset_command_list * command_list,
        keyreset_command * command
    )
{
    assert(command);

    // empty list (no nodes)
    if (command_list == NULL)
        return new_keyreset_command_list(command);

    // empty list (one node, no command)
    if (command_list->command == NULL) {
        if (command_list->next)
            return NULL; // invalid list
            
        command_list->command = command;
        assert(command_list->command);
        
        if (command_list->command == NULL)
            return NULL;
        
        return command_list;
    }
    
    keyreset_command_list * list_curr = command_list;
    
    while (list_curr->next)
        list_curr = list_curr->next;
     
    list_curr->next = new_keyreset_command_list(command);

    assert(list_curr->next);
    if (list_curr->next == NULL)
        return NULL;

    return list_curr->next;
}

DYNAMIC_API keyreset_command_list * keyreset_command_list_append(
        keyreset_command_list * command_list,
        keyreset_command_list * second
    )
{
    assert(command_list);
    if (command_list == NULL)
        return NULL;

    // second list is empty
    if (second == NULL || second->command == NULL)
        return command_list;

    keyreset_command_list * _s = command_list;
    for (keyreset_command_list * _s2 = second; _s2 != NULL; _s2 = _s2->next) {
        keyreset_command * _sp = keyreset_command_dup(_s2->command);
        if (_sp == NULL)
            return NULL;
        _s = keyreset_command_list_add(_s, _sp);
        if (_s == NULL){
            free_keyreset_command(_sp);
            return NULL;
        }
    }
    return _s;
}

DYNAMIC_API int keyreset_command_list_length(
        const keyreset_command_list * command_list
    )
{
    int len = 0;

    for (const keyreset_command_list * _sl = command_list; _sl && _sl->command; _sl = _sl->next)
        len++;

    return len;
}

DYNAMIC_API void free_keyreset_command_list(keyreset_command_list * command_list)
{
    if (command_list) {
        free_keyreset_command_list(command_list->next);
        free_keyreset_command(command_list->command);
        free(command_list);
    }
}

