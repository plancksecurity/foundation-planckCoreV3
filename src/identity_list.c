/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"

#include <stdlib.h>
#include <assert.h>

#include "pEpEngine.h"
#include "identity_list.h"

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
