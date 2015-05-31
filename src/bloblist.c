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

    if (blob) {
        bloblist->value = blob;
        bloblist->size = size;
    }

    return bloblist;
}

DYNAMIC_API void free_bloblist(bloblist_t *bloblist)
{
    if (bloblist) {
        if (bloblist->next)
            free_bloblist(bloblist->next);
        free(bloblist->value);
        free(bloblist->mime_type);
        free(bloblist->filename);
        free(bloblist);
    }
}

DYNAMIC_API bloblist_t *bloblist_dup(const bloblist_t *src)
{
    bloblist_t *bloblist = NULL;

    assert(src);

    char *blob2 = malloc(src->size + 1);
    assert(blob2);
    if (blob2 == NULL)
        goto enomem;

    memcpy(blob2, src->value, src->size);
    blob2[src->size] = 0; // safeguard

    bloblist = new_bloblist(blob2, src->size, src->mime_type, src->filename);
    if (bloblist == NULL)
        goto enomem;
    blob2 = NULL;

    if (src->next) {
        bloblist->next = bloblist_dup(src->next);
        if (bloblist->next == NULL)
            goto enomem;
    }

    return bloblist;

enomem:
    free(blob2);
    free_bloblist(bloblist);
    return NULL;
}

DYNAMIC_API bloblist_t *bloblist_add(bloblist_t *bloblist, char *blob, size_t size,
        const char *mime_type, const char *filename)
{
    assert(blob);

    if (bloblist == NULL)
        return new_bloblist(blob, size, mime_type, filename);

    if (bloblist->value == NULL) {
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

        bloblist->value = blob;
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
    int len = 0;

    for (const bloblist_t *_bl = bloblist; _bl && _bl->value; _bl = _bl->next)
        len++;

    return len;
}
