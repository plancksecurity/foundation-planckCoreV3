// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <assert.h>
#include "revocation_info.h"

DYNAMIC_API revocation_info* new_revocation_info(char* revoked_fpr,
                                                 char* own_address,
                                                 char* replacement_fpr,
                                                 uint64_t revocation_date) {
    revocation_info* retval = calloc(1, sizeof(revocation_info));
    if (!retval)
        return NULL;
    retval->revoked_fpr = revoked_fpr;
    retval->own_address = own_address;
    retval->replacement_fpr = replacement_fpr;
    retval->revocation_date = revocation_date;    
    
    return retval;    
}

DYNAMIC_API void free_revocation_info(revocation_info* rev_info) {
    if (rev_info) {
        free(rev_info->revoked_fpr);
        free(rev_info->own_address);
        free(rev_inf0->replacement_fpr);
        free(rev_info);
    }        
}

DYNAMIC_API revocation_info* revocation_info_dup(revocation_info* rev_info) {
    revocation_info* retval = calloc(1, sizeof(revocation_info)); 
    if (!retval)
        return NULL;
        
    if (rev_info->revoked_fpr) {
        retval->revoked_fpr = strdup(rev_info->revoked_fpr);
        if (!retval->revoked_fpr)
            goto pEp_free;
    }
    if (rev_info->own_address) {
        retval->own_address = strdup(rev_info->own_address);
        if (!retval->own_address)
            goto pEp_free;        
    }
    if (rev_info->replacement_fpr) {
        retval->replacement_fpr = strdup(rev_info->replacement_fpr);
        if (!retval->replacement_fpr)
            goto pEp_free;        
    }
    
    retval->revocation_date = rev_info->revocation_date; 
    return retval;

pEp_free:
    if (retval)
        free_revocation_info(retval);
    return NULL;        
}

DYNAMIC_API revocation_info_list_t* new_revocation_info_list(revocation_info *rev_info) {
    revocation_info_list_t* rev_list = calloc(1, sizeof(revocation_info_list));
    if (!rev_list)
        return NULL;
    rev_list->info = rev_info;
    return rev_list;    
}


DYNAMIC_API revocation_info_list_t* revocation_info_list_dup(const revocation_info_list_t* src)
{
    if (src == NULL)
        return NULL;

    if (src->info == NULL)
        return new_revocation_info_list(NULL);
            
        revocation_info *_rev_info = revocation_info_dup(src->info);
        if (_rev_info == NULL)
            return NULL;

        revocation_info_list_t *rev_list  = new_revocation_info_list(_rev_info);
        if (rev_list  == NULL) {
            free_revocation_info(_rev_info);
            return NULL;
        }

        revocation_info_list_t* src_curr = src->next;
        revocation_info_list_t** dst_curr_ptr = &rev_list->next;
        
        while (src_curr) {
            _rev_info = revocation_info_dup(src_curr->info);
            if (_rev_info == NULL) {
                free_revocation_info_list(rev_list );
                return NULL;
            }
            
            *dst_curr_ptr = new_revocation_info_list(_rev_info);
            if (*dst_curr_ptr == NULL) {
                free_revocation_info(_rev_info);
                free_revocation_info_list(rev_list );
                return NULL;
            }
            
            src_curr = src_curr->next;
            dst_curr_ptr = &((*dst_curr_ptr)->next);
        }
        return rev_list;
    }
}


DYNAMIC_API void free_revocation_info_list(revocation_info_list_t* rev_list) {
    revocation_info_list_t *curr = rev_list;
        
    while (curr) {
        revocation_info_list_t *next = curr->next;
        free_revocation_info(curr->info);
        free(curr);
        curr = next;
    }
}

DYNAMIC_API revocation_info_list_t* revocation_info_list_add(revocation_info_list_t* rev_list, revocation_info *rev_info) {
    assert(rev_info);
    if (rev_info == NULL)
        return NULL;
    
    if (rev_list == NULL)
        return new_revocation_info_list(rev_info);

    // empty list
    if (rev_list->info == NULL) {
        if (rev_list->next)
            return NULL; // invalid list
            
        rev_list->info = rev_info;
        
        if (rev_list->info == NULL)
            return NULL;
        
        return rev_list;
    }
 
    revocation_info_list_t* list_curr = rev_list;
    while (list_curr->next)
        list_curr = list_curr->next;
    
    list_curr->next = new_revocation_info_list(rev_info);
    
    return list_curr->next;
}

DYNAMIC_API revocation_info_list_t* revocation_info_list_join(revocation_info_list_t* first_list, revocation_info_list_t* second_list) {
    if (!first_list) {
        if (!second_list)
            return NULL;
        return second_list;
    }
    if (second_list) {
        revocation_info_list_t* list_curr = first_list;
        while (list_curr->next)
            list_curr = list_curr->next;    
            
        list_curr->next = second_list;
    }        
    return first_list;    
}

// revocation_info_list_length() - get length of revocation_info_list
//
//  parameters:
//      rev_list (in)        revocation_info_list struct to determine length of
//
//  return value:
//      length of revocation_info_list in number of elements

DYNAMIC_API int revocation_info_list_length(const revocation_info_list_t* rev_list) {
    int len = 0;

    for (; rev_list && rev_list->info; rev_list = rev_list->next)
        ++len;

    return len;
}
