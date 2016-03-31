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
        if (result->value == 0) {
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

    if (src->next) {
        dst->next = stringlist_dup(src->next);
        if (dst->next == NULL) {
            free_stringlist(dst);
            return NULL;
        }
    }

    return dst;
}

DYNAMIC_API stringlist_t *stringlist_add(
        stringlist_t *stringlist,
        const char *value
    )
{
    assert(value);

    if (stringlist == NULL)
        return new_stringlist(value);

    if (stringlist->next != NULL)
        return stringlist_add(stringlist->next, value);
    if (stringlist->value == NULL) {
        stringlist->value = strdup(value);
        assert(stringlist->value);
        if (stringlist->value == NULL)
            return NULL;
        return stringlist;
    }

    stringlist->next = new_stringlist(value);
    assert(stringlist->next);
    if (stringlist->next == NULL)
        return NULL;

    return stringlist->next;
}

DYNAMIC_API stringlist_t *stringlist_append(
        stringlist_t *stringlist,
        stringlist_t *second
    )
{
    assert(stringlist);

    if (second == NULL || second->value == NULL)
        return stringlist;

    stringlist_t *_s = stringlist;
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

DYNAMIC_API void free_stringlist(stringlist_t *stringlist)
{
    if (stringlist) {
        free_stringlist(stringlist->next);
        free(stringlist->value);
        free(stringlist);
    }
}

