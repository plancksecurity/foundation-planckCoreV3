/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "stringlist.h"


DYNAMIC_API stringlist_t *new_stringlist(const char *value)
{
    stringlist_t *result = calloc(1, sizeof(stringlist_t));
    assert(result);

    if (result && value) {
        result->value = strdup(value);
        assert(result->value);
        if (!result->value) {
            free(result);
            return NULL;
        }
    }

    return result;
}

DYNAMIC_API stringlist_t *stringlist_dup(const stringlist_t *src)
{
    assert(src);
    if (src == NULL)
        return NULL;

    stringlist_t *dst = new_stringlist(src->value);
    if (dst == NULL)
        return NULL;

    stringlist_t* src_curr = src->next;
    stringlist_t** dst_curr_ptr = &dst->next;
    
    while (src_curr) {
        *dst_curr_ptr = new_stringlist(src_curr->value);
        if (*dst_curr_ptr == NULL) {
            free_stringlist(dst);
            return NULL;
        }
        src_curr = src_curr->next;
        dst_curr_ptr = &((*dst_curr_ptr)->next);
    }

    return dst;
}

/**
 *  @internal
 *  
 *  <!--       _stringlist_add_first()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*stringlist		stringlist_t
 *  @param[in]	**result		stringlist_t
 *  @param[in]	*value		constchar
 *  
 */
static bool _stringlist_add_first(
        stringlist_t *stringlist,
        stringlist_t **result,
        const char *value
    )
{  
    // empty list (no nodes)
    if (stringlist == NULL) {
        *result = new_stringlist(value);
        return true;
    }

    // empty list (one node, no value)
    if (stringlist->value == NULL) {
        if (stringlist->next) {
            *result = NULL; // invalid list
            return true;
        } 
            
        stringlist->value = strdup(value);
        assert(stringlist->value);
        
        if (stringlist->value == NULL) {
            *result = NULL;
            return true;
        }
        
        *result = stringlist;
        return true;
    }
    return false;
}

DYNAMIC_API stringlist_t *stringlist_add(
        stringlist_t *stringlist,
        const char *value
    )
{  
    assert(value);
    if (value == NULL)
        return NULL;

    stringlist_t *result = NULL;
    if(_stringlist_add_first(stringlist, &result, value))
        return result;
    
    stringlist_t* list_curr = stringlist;

    while (list_curr->next)
        list_curr = list_curr->next;
     
    list_curr->next = new_stringlist(value);

    assert(list_curr->next);
    if (list_curr->next == NULL)
        return NULL;

    return list_curr->next;
}

const stringlist_t* stringlist_search(const stringlist_t* head, const char* value) {
    if (!head || !value || !head->value)
        return NULL;
    const stringlist_t* retval = NULL;
    
    const stringlist_t* curr = head;
    for (; curr ; curr = curr->next) {
        if (strcmp(curr->value, value) == 0) {
            retval = curr;
            break;
        }    
    }
    return retval;
}


DYNAMIC_API stringlist_t *stringlist_add_unique(
        stringlist_t *stringlist,
        const char *value
    )
{  
    assert(value);
    if (value == NULL)
        return NULL;

    stringlist_t *result = NULL;

    if(_stringlist_add_first(stringlist, &result, value))
        return result;

    if (!stringlist)
        return NULL; // If the previous call fails somehow. this code is bizarre.

    stringlist_t* list_curr = stringlist;

    stringlist_t** next_ptr_addr = NULL;

    while (list_curr) {
        next_ptr_addr = &list_curr->next;
        if (strcmp(list_curr->value, value) == 0)
            return list_curr;
        list_curr = list_curr->next;
    }

    if (!next_ptr_addr)
        return NULL; // This is an error, because stringlist_add_first should
                     // have handled this case

    *next_ptr_addr = new_stringlist(value);

    if (!*next_ptr_addr)
        return NULL;

    return *next_ptr_addr;

}


DYNAMIC_API stringlist_t *stringlist_append(
        stringlist_t *stringlist,
        stringlist_t *second
    )
{
    assert(stringlist);
    if (stringlist == NULL)
        return NULL;

    // Second list is empty
    if (second == NULL || second->value == NULL)
        return stringlist;

    stringlist_t *_s = stringlist;

    if (stringlist == second) {
        // Passing in the same pointer twice is not cool.
        // Since the semantics are to copy the second list,
        // we'll just do that, presuming that the
        // caller wants this.
        second = stringlist_dup(stringlist);

        stringlist_t** end_ptr = NULL;

        while (_s) {
            end_ptr = &_s->next;
            _s = _s->next;
        }
        if (!end_ptr)
            return NULL;
        *end_ptr = second;

        return stringlist;
    }

    stringlist_t *_s2;
    for (_s2 = second; _s2 != NULL; _s2 = _s2->next) {
        _s = stringlist_add(_s, _s2->value);
        if (_s == NULL)
            return NULL;
    }
    return _s;
}

DYNAMIC_API int stringlist_length(const stringlist_t *stringlist)
{
    int len = 0;

    const stringlist_t *_sl;
    for (_sl = stringlist; _sl && _sl->value; _sl = _sl->next)
        len++;

    return len;
}

DYNAMIC_API stringlist_t *stringlist_delete(
        stringlist_t *stringlist,
        const char *value
    )
{
    assert(stringlist);
    assert(value);

    if (stringlist->value == NULL) {
        free_stringlist(stringlist);
        return NULL;
    }

    if (value == NULL)
        return stringlist;

    stringlist_t *_sl;
    stringlist_t *last = NULL;
    for (_sl = stringlist; _sl && _sl->value; _sl = _sl->next) {
        if (strcmp(_sl->value, value) == 0) {
            if (last == NULL)
                stringlist = stringlist->next;
            else
                last->next = _sl->next;
            _sl->next = NULL;
            free_stringlist(_sl);
            break;
        }
        last = _sl;
    }
    return stringlist;
}

/**
 *  @internal
 *  
 *  <!--       stringlist_multi_delete()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*stringlist		stringlist_t
 *  @param[in]	*value		constchar
 *  
 */
static stringlist_t* stringlist_multi_delete(stringlist_t* stringlist, const char* value) {
    if (stringlist == NULL || !stringlist->value)
        return stringlist;
    
    stringlist_t* list_curr = stringlist;
    stringlist_t* prev_ptr = NULL;
    
    while (list_curr) {
        if (strcmp(list_curr->value, value) == 0) {
            stringlist_t* victim = list_curr;
            if (prev_ptr)
                prev_ptr->next = list_curr->next;    
            else
                stringlist = list_curr->next;
            
            list_curr = list_curr->next;

            victim->next = NULL;
            
            free_stringlist(victim);
        }
        else {
            prev_ptr = list_curr;
            list_curr = list_curr->next;
        }
    }
    return stringlist;
}



void dedup_stringlist(stringlist_t* stringlist) {
    if (stringlist == NULL || !stringlist->value)
        return;
        
    stringlist_t* list_curr = stringlist;

    while (list_curr && list_curr->next) {
        stringlist_t* new_next = stringlist_multi_delete(list_curr->next, list_curr->value);
        list_curr->next = new_next;
        list_curr = list_curr->next;
    }    
}

DYNAMIC_API void free_stringlist(stringlist_t *stringlist)
{
    stringlist_t *curr = stringlist;
    
    while (curr) {
        stringlist_t *next = curr->next;
        free(curr->value);
        curr->value = NULL;
        free(curr);
        curr = next;
    }
}

char* stringlist_to_string(stringlist_t* list) {
    if (!list)
        return NULL;
    
    unsigned int size = 0;
    unsigned int count = 0;
    stringlist_t* curr;

    // calc size
    for (curr = list; curr; curr = curr->next) {
        if (!curr->value)
            return NULL;
        size += strlen(curr->value);
        count++;
    }    
    
    size += (count - 1) + 1;
    
    char* retval = calloc(size, 1);
    
    int i;
    strlcpy(retval, list->value, size);
    
    for (i = 1, curr = list->next; curr && (i < count); i++, curr = curr->next) {
        strlcat(retval, ",", size);
        strlcat(retval, curr->value, size);
    }
    
    return retval;
}

stringlist_t* string_to_stringlist(const char* str) {
    if (!str || str[0] == '\0')
        return NULL;
        
    // Because of strtok, we do this
    char* workstr = strdup(str);
    if (!workstr)
        return NULL;
        
    char* token = strtok(workstr, ",");
    stringlist_t* retval = new_stringlist(NULL);
    
    while (token) {
        if (token && token[0] != '\0')
            stringlist_add(retval, token);
        token = strtok(NULL, ",");
    }    
    free(workstr);
    
    if (!retval->value) {
        free_stringlist(retval);
        retval = NULL;
    }
    return retval;
}
