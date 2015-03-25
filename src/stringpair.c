#include "pEp_internal.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "stringpair.h"

DYNAMIC_API stringpair_t * new_stringpair(const char *key, const char *value)
{
    stringpair_t *pair = NULL;

    assert(key);
    assert(value),

    pair = calloc(1, sizeof(stringpair_t));
    assert(pair);
    if (pair == NULL)
        goto enomem;

    pair->key = strdup(key);
    assert(pair->key);
    if (pair->key == NULL)
        goto enomem;

    pair->value = strdup(value);
    assert(pair->value);
    if (pair->value == NULL)
        goto enomem;

    return pair;

enomem:
    free_stringpair(pair);
    return NULL;
}

DYNAMIC_API void free_stringpair(stringpair_t * pair)
{
    if (pair) {
        free(pair->key);
        free(pair->value);
        free(pair);
    }
}

DYNAMIC_API stringpair_t * stringpair_dup(const stringpair_t *src)
{
    assert(src);
    return new_stringpair(src->key, src->value);
}

DYNAMIC_API stringpair_list_t *new_stringpair_list(const stringpair_t *value)
{
    stringpair_list_t *result = calloc(1, sizeof(stringpair_list_t));
    assert(result);

    if (result && value) {
        result->value = stringpair_dup(value);
        if (result->value == 0) {
            free(result);
            return NULL;
        }
    }

    return result;
}

DYNAMIC_API stringpair_list_t *stringpair_list_dup(
        const stringpair_list_t *src
    )
{
    assert(src);
    if (src == NULL)
        return NULL;

    stringpair_list_t *dst = new_stringpair_list(src->value);
    if (dst == NULL)
        return NULL;

    if (src->next) {
        dst->next = stringpair_list_dup(src->next);
        if (dst->next == NULL) {
            free_stringpair_list(dst);
            return NULL;
        }
    }

    return dst;
}

DYNAMIC_API stringpair_list_t *stringpair_list_add(
        stringpair_list_t *stringpair_list,
        const stringpair_t *value
    )
{
    assert(value);

    if (stringpair_list == NULL)
        return new_stringpair_list(value);

    if (stringpair_list->next != NULL)
        return stringpair_list_add(stringpair_list->next, value);
    if (stringpair_list->value == NULL) {
        stringpair_list->value = stringpair_dup(value);
        if (stringpair_list->value == NULL)
            return NULL;
        return stringpair_list;
    }

    stringpair_list->next = new_stringpair_list(value);
    if (stringpair_list->next == NULL)
        return NULL;

    return stringpair_list->next;
}

DYNAMIC_API stringpair_list_t *stringpair_list_append(
        stringpair_list_t *stringpair_list,
        stringpair_list_t *second
    )
{
    assert(stringpair_list);

    if (second == NULL || second->value == NULL)
        return stringpair_list;

    stringpair_list_t *_s = stringpair_list;
    stringpair_list_t *_s2;
    for (_s2 = second; _s2 != NULL; _s2 = _s2->next) {
        _s = stringpair_list_add(_s, _s2->value);
        if (_s == NULL)
            return NULL;
    }
    return _s;
}

DYNAMIC_API int stringpair_list_length(
        const stringpair_list_t *stringpair_list
    )
{
    int len = 1;
    stringpair_list_t *_stringpair_list;

    assert(stringpair_list);

    if (stringpair_list->value == NULL)
        return 0;

    for (_stringpair_list=stringpair_list->next; _stringpair_list!=NULL;
            _stringpair_list=_stringpair_list->next)
        len += 1;

    return len;
}

DYNAMIC_API void free_stringpair_list(stringpair_list_t *stringpair_list)
{
    if (stringpair_list) {
        free_stringpair_list(stringpair_list->next);
        free_stringpair(stringpair_list->value);
        free(stringpair_list);
    }
}

DYNAMIC_API stringpair_list_t *stringpair_list_find(
        stringpair_list_t *stringpair_list,
        const char *key
    )
{
    assert(key);

    stringpair_list_t *_l;
    for (_l = stringpair_list; _l; _l = _l->next) {
        if (strcoll(key, _l->value->key) == 0)
            return _l;
    }

    return NULL;
}

