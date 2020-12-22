// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef LABELED_INT_LIST_H
#define LABELED_INT_LIST_H

#include "dynamic_api.h"
#include "stringpair.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _labeled_int_list_t {
    int value;
    char* label;                                // UTF-8 string, null-terminated
    struct _labeled_int_list_t *next;           // this is a single linked list
} labeled_int_list_t;

DYNAMIC_API labeled_int_list_t *new_labeled_int_list(int value, const char* label);

DYNAMIC_API void free_labeled_int_list(labeled_int_list_t *labeled_int_list);

DYNAMIC_API labeled_int_list_t *labeled_int_list_dup(const labeled_int_list_t *src);

DYNAMIC_API labeled_int_list_t *labeled_int_list_add(labeled_int_list_t *labeled_int_list, int value, const char* label);

DYNAMIC_API int labeled_int_list_length(const labeled_int_list_t *labeled_int_list);

#ifdef __cplusplus
}
#endif

#endif
