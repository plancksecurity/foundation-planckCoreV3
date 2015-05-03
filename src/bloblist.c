#include "pEp_internal.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "bloblist.h"

DYNAMIC_API bloblist_t *new_bloblist(char *blob, size_t size, const char *mime_type,
        const char *filename)
{
    bloblist_t * bloblist = calloc(1, sizeof(bloblist_t));
    assert(bloblist);
    if (bloblist == NULL)
        return NULL;

    if (mime_type) {
        bloblist->mime_type = strdup(mime_type);
        if (bloblist->mime_type == NULL) {
            free(bloblist);
            return NULL;
        }
    }

    if (filename) {
        bloblist->filename = strdup(filename);
        if (bloblist->filename == NULL) {
            free(bloblist->mime_type);
            free(bloblist);
            return NULL;
        }
    }

    assert((blob == NULL && size == 0) || (blob && size));

    bloblist->data = blob;
    bloblist->size = size;

    return bloblist;
}

DYNAMIC_API void free_bloblist(bloblist_t *bloblist)
{
    if (bloblist) {
        if (bloblist->next)
            free_bloblist(bloblist->next);
        free(bloblist->data);
        free(bloblist->mime_type);
        free(bloblist->filename);
        free(bloblist);
    }
}

DYNAMIC_API bloblist_t *bloblist_dup(const bloblist_t *src)
{
    bloblist_t *bloblist = NULL;

    assert(src);

    bloblist = new_bloblist(src->data, src->size, src->mime_type, src->filename);
    if (bloblist == NULL)
        goto enomem;

    if (src->next) {
        bloblist->next = bloblist_dup(src->next);
        if (bloblist->next == NULL)
            goto enomem;
    }

    return bloblist;

enomem:
    free_bloblist(bloblist);
    return NULL;
}

DYNAMIC_API bloblist_t *bloblist_add(bloblist_t *bloblist, char *blob, size_t size,
        const char *mime_type, const char *filename)
{
    assert(blob);

    if (bloblist == NULL)
        return new_bloblist(blob, size, mime_type, filename);

    if (bloblist->data == NULL) {
        if (mime_type) {
            bloblist->mime_type = strdup(mime_type);
            if (bloblist->mime_type == NULL) {
                free(bloblist);
                return NULL;
            }
        }
        if (filename) {
            bloblist->filename = strdup(filename);
            if (bloblist->filename == NULL) {
                free(bloblist->mime_type);
                free(bloblist);
                return NULL;
            }
        }

        assert((blob == NULL && size == 0) || (blob && size));

        bloblist->data = blob;
        bloblist->size = size;

        return bloblist;
    }

    if (bloblist->next == NULL) {
        bloblist->next = new_bloblist(blob, size, mime_type, filename);
        return bloblist->next;
    }

    return bloblist_add(bloblist->next, blob, size, mime_type, filename);
}

DYNAMIC_API int bloblist_length(const bloblist_t *bloblist)
{
    int len = 1;
    bloblist_t *_bloblist;

    assert(bloblist);

    if (bloblist->data == NULL)
        return 0;

    for (_bloblist = bloblist->next; _bloblist != NULL;
        _bloblist = _bloblist->next)
        len += 1;

    return len;
}
