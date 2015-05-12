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

    pEp_identity *_ident = identity_dup(src->ident);
    if (_ident == NULL)
        return NULL;

    identity_list *id_list = new_identity_list(_ident);
    if (id_list == NULL)
        return NULL;

    if (src->next) {
        id_list->next = identity_list_dup(src->next);
        if (id_list->next == NULL) {
            free_identity_list(id_list);
            return NULL;
        }
    }

    return id_list;
}

DYNAMIC_API void free_identity_list(identity_list *id_list)
{
    if (id_list) {
        free_identity_list(id_list->next);
        free_identity(id_list->ident);
        free(id_list);
    }
}

DYNAMIC_API identity_list *identity_list_add(identity_list *id_list, pEp_identity *ident)
{
    assert(ident);

    if (id_list == NULL)
        return new_identity_list(ident);

    if (id_list->ident == NULL) {
        id_list->ident = ident;
        return id_list;
    }
    else if (id_list->next == NULL) {
        id_list->next = new_identity_list(ident);
        return id_list->next;
    }
    else {
        return identity_list_add(id_list->next, ident);
    }
}

DYNAMIC_API int identity_list_length(const identity_list *id_list)
{
    int len = 0;

    for (; id_list && id_list->ident; id_list = id_list->next)
        ++len;

    return len;
}
