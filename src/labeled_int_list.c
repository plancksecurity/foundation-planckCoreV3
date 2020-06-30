/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "platform.h"
#include "labeled_int_list.h"

DYNAMIC_API labeled_int_list_t *new_labeled_int_list(int value, const char* label)
{
    assert(label);
    if (!label)
        return NULL;
        
    labeled_int_list_t * labeled_int_list = calloc(1, sizeof(labeled_int_list_t));
    assert(labeled_int_list);
    if (labeled_int_list == NULL)
        return NULL;

    labeled_int_list->value = value;
    labeled_int_list->label = strdup(label);
    if (!labeled_int_list->label) {
        free(labeled_int_list);
        labeled_int_list = NULL;
    }
    return labeled_int_list;
}

DYNAMIC_API void free_labeled_int_list(labeled_int_list_t *labeled_int_list)
{
    labeled_int_list_t *curr = labeled_int_list;

    while (curr) {
        labeled_int_list_t *next = curr->next;
        free(curr->label);
        free(curr);
        curr = next;
    }
}

DYNAMIC_API labeled_int_list_t *labeled_int_list_dup(const labeled_int_list_t *src)
{
    assert(src);
    if (src == NULL)
        return NULL;
    
    labeled_int_list_t *labeled_int_list = NULL;

    labeled_int_list = new_labeled_int_list(src->value, src->label);
    if (labeled_int_list == NULL)
        goto enomem;

    labeled_int_list_t* src_curr = src->next;
    labeled_int_list_t** dst_curr_ptr = &labeled_int_list->next;

    // list
    while (src_curr) {
        *dst_curr_ptr = new_labeled_int_list(src_curr->value, src_curr->label);
        if (*dst_curr_ptr == NULL)
            goto enomem;

        src_curr = src_curr->next;
        dst_curr_ptr = &((*dst_curr_ptr)->next);
    }

    return labeled_int_list;

enomem:
    free_labeled_int_list(labeled_int_list);
    return NULL;
}

DYNAMIC_API labeled_int_list_t *labeled_int_list_add(labeled_int_list_t *labeled_int_list, int value, const char* label)
{
    if (!label)
        return NULL;
        
    if (!labeled_int_list)
        return new_labeled_int_list(value, label);

    if (!labeled_int_list->label) { // empty list
        assert(!labeled_int_list->next);
        if (labeled_int_list->next)
            return NULL; // invalid list

        labeled_int_list->value = value;
        labeled_int_list->label = strdup(label);
        if (!labeled_int_list->label) {
            free(labeled_int_list);
            labeled_int_list = NULL;
        }

        return labeled_int_list;
    }

    labeled_int_list_t* list_curr = labeled_int_list;

    while (list_curr->next)
        list_curr = list_curr->next;

    list_curr->next = new_labeled_int_list(value, label);

    assert(list_curr->next);
    if (!list_curr->next)
        return NULL;

    return list_curr->next;
}

DYNAMIC_API int labeled_int_list_length(const labeled_int_list_t *labeled_int_list)
{
    int len = 0;

    for (const labeled_int_list_t *_li = labeled_int_list; _li && _li->label; _li = _li->next)
        len++;

    return len;
}

