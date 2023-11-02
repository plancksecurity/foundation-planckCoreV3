/**
 * @file    identity_list.c
 * @brief   implementation of identity list functions
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#include "pEp_internal.h"

#include <stdlib.h>
#include <assert.h>

#include "pEpEngine.h"
#include "identity_list.h"

DYNAMIC_API identity_list *identity_list_cons(pEp_identity *element,
                                              identity_list *old_list)
{
    /* Handle the special NULL case: */
    if (element == NULL)
        return old_list;

    identity_list *cons = calloc(1, sizeof(identity_list));
    assert(cons != NULL);
    if (cons == NULL)
        return NULL;

    cons->ident = element;
    cons->next = old_list;
    return cons;
}

DYNAMIC_API identity_list *identity_list_cons_copy(pEp_identity *element,
                                                   identity_list *old_list)
{
    /* Handle the special NULL case: */
    if (element == NULL)
        return old_list;

    /* From now on we can assume that element is not null. */
    identity_list *result = NULL;
    pEp_identity *element_copy = identity_dup(element);
    if (element_copy == NULL)
        goto out_of_memory;
    result = identity_list_cons(element_copy, old_list);
    if (result == NULL)
        goto out_of_memory;
    return result;

 out_of_memory:
    free_identity(element_copy);
    free_identity_list(result);
    return NULL;
}

DYNAMIC_API identity_list *identity_list_reversed(identity_list *old_list)
{
    /* Scan the old list starting from the first element; prepend any non-NULL
       element we find to a new list, and return the new list at the end.
          A B C
       will be copied into
          C B A .  */
    identity_list *result = NULL;
    identity_list *rest;
    for (rest = old_list; rest != NULL; rest = rest->next) {
        pEp_identity *old_identity = rest->ident;
        /* If we find a silly NULL element just skip it. */
        if (old_identity == NULL)
            continue;
        identity_list *new_result = identity_list_cons_copy(old_identity,
                                                            result);
        if (new_result == NULL) {
            free_identity_list(result);
            return NULL;
        }
        else
            result = new_result;
    }
    return result;
}

DYNAMIC_API identity_list *new_identity_list(pEp_identity *ident)
{
    identity_list *id_list = calloc(1, sizeof(identity_list));
    assert(id_list);
    if (id_list == NULL)
        return NULL;

    id_list->ident = ident;

    return id_list;
}

DYNAMIC_API identity_list *identity_list_dup(const identity_list *src)
{
    assert(src);
    if (src == NULL)
        return NULL;

    if (src->ident == NULL)
        return new_identity_list(NULL);
        
    pEp_identity *_ident = identity_dup(src->ident);
    if (_ident == NULL)
        return NULL;

    identity_list *id_list = new_identity_list(_ident);
    if (id_list == NULL) {
        free_identity(_ident);
        return NULL;
    }

    identity_list* src_curr = src->next;
    identity_list** dst_curr_ptr = &id_list->next;
    
    while (src_curr) {
        _ident = identity_dup(src_curr->ident);
        if (_ident == NULL) {
            free_identity_list(id_list);
            return NULL;
        }
        
        *dst_curr_ptr = new_identity_list(_ident);
        if (*dst_curr_ptr == NULL) {
            free_identity(_ident);
            free_identity_list(id_list);
            return NULL;
        }
        
        src_curr = src_curr->next;
        dst_curr_ptr = &((*dst_curr_ptr)->next);
    }
    
    return id_list;
    
}

DYNAMIC_API void free_identity_list(identity_list *id_list)
{
    identity_list *curr = id_list;
    
    while (curr) {
        identity_list *next = curr->next;
        free_identity(curr->ident);
        free(curr);
        curr = next;
    }
}

DYNAMIC_API identity_list *identity_list_add(identity_list *id_list, pEp_identity *ident)
{
    assert(ident);
    if (ident == NULL)
        return NULL;
    
    if (id_list == NULL)
        return new_identity_list(ident);

    // empty list
    if (id_list->ident == NULL) {
        if (id_list->next)
            return NULL; // invalid list
            
        id_list->ident = ident;
        
        if (id_list->ident == NULL)
            return NULL;
        
        return id_list;
    }
 
    identity_list* list_curr = id_list;
    while (list_curr->next)
        list_curr = list_curr->next;
    
    list_curr->next = new_identity_list(ident);
    
    return list_curr->next;
}

DYNAMIC_API identity_list *identity_list_add_or_update(identity_list *id_list, pEp_identity *ident)
{
    assert(ident);
    if (ident == NULL)
        return NULL;

    if (id_list == NULL)
        return new_identity_list(ident);

    // empty list
    if (id_list->ident == NULL) {
        if (id_list->next)
            return NULL; // invalid list

        id_list->ident = ident;

        if (id_list->ident == NULL)
            return NULL;

        return id_list;
    }

    identity_list* list_curr = id_list;
    //navigates to the either the latest one *or* the FIRST identity address twin.
    while (list_curr->next && strcmp(list_curr->ident->address, ident->address))
        list_curr = list_curr->next;

    if(strcmp(list_curr->ident->address, ident->address)==0){
        free_identity(list_curr->ident);
        list_curr->ident = NULL;
        list_curr->ident = ident;
        return list_curr;
    } else {
        list_curr->next = new_identity_list(ident);
        return list_curr->next;
    }
}

// returns *head* of list
DYNAMIC_API identity_list* identity_list_join(identity_list *first_list, identity_list *second_list) {
    if (!first_list) {
        if (!second_list)
            return NULL;
        return second_list;
    }
    if (second_list) {
        identity_list* list_curr = first_list;
        while (list_curr->next)
            list_curr = list_curr->next;    
            
        list_curr->next = second_list;
    }        
    return first_list;    
}

DYNAMIC_API int identity_list_length(const identity_list *id_list)
{
    int len = 0;

    for (; id_list && id_list->ident; id_list = id_list->next)
        ++len;

    return len;
}

PEP_STATUS set_all_userids_in_list(identity_list* id_list, const char* user_id) {
    if (!user_id || user_id[0] == '\0')
        return PEP_ILLEGAL_VALUE;
        
    identity_list* curr_list = id_list;
    
    while (curr_list) {
        if (curr_list->ident) {
            free(curr_list->ident->user_id);
            curr_list->ident->user_id = NULL;
            char* dup_userid = strdup(user_id);
            if (dup_userid == NULL)
                return PEP_OUT_OF_MEMORY;
            curr_list->ident->user_id = dup_userid;    
        }    
        curr_list = curr_list->next;
    }
    return PEP_STATUS_OK;
}
