// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "dynamic_api.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct _bloblist_t {
    char *value;                    // blob
    size_t size;                    // size of blob
    char *mime_type;                // UTF-8 string of MIME type of blob or
                                    // NULL if unknown
    char *filename;                // UTF-8 string of file name of blob or
                                    // NULL if unknown
    char *content_id;              // UTF-8 string of content id or NULL if
                                   // unknown
    struct _bloblist_t *next;
} bloblist_t;


// new_bloblist() - allocate a new bloblist
//
//  parameters:
//      blob (in)           blob to add to the list
//      size (in)           size of the blob
//      mime_type (in)      MIME type of the blob data or NULL if unknown
//      filename (in)       file name of origin of blob data or NULL if unknown
//      content_id (in)     content_id of attachment blob or NULL if known
//
//  return value:
//      pointer to new bloblist_t or NULL if out of memory
//
//  caveat:
//      the ownership of the blob goes to the bloblist; mime_type and filename
//      are being copied, the originals remain in the ownership of the caller

DYNAMIC_API bloblist_t *new_bloblist(char *blob, size_t size, const char *mime_type,
        const char *filename, const char *content_id);


// free_bloblist() - free bloblist
//
//  parameters:
//      bloblist (in)   bloblist to free

DYNAMIC_API void free_bloblist(bloblist_t *bloblist);


// bloblist_dup() - duplicate bloblist
//
//  parameters:
//      src (in)    bloblist to duplicate
//
//  return value:
//      pointer to a new bloblist_t or NULL if out of memory
//
//  caveat:
//      this is an expensive operation because all blobs are copied

DYNAMIC_API bloblist_t *bloblist_dup(const bloblist_t *src);

// bloblist_add() - add reference to a blob to bloblist
//
//  parameters:
//      bloblist (in)       bloblist to add to
//      blob (in)           blob
//      size (in)           size of the blob
//      mime_type (in)      MIME type of the blob or NULL if unknown
//      filename (in)       file name of the blob or NULL if unknown
//      content_id (in)     content_id of attachment blob or NULL if known
//
//  return value:
//      pointer to the last element of bloblist or NULL if out of memory or
//      NULL passed in as blob value
//
//  caveat:
//      the ownership of the blob goes to the bloblist; mime_type and filename
//      are being copied, the originals remain in the ownership of the caller.
//      bloblist input parameter equal to NULL or with value == NULL is a valid
//      empty input list.

DYNAMIC_API bloblist_t *bloblist_add(bloblist_t *bloblist, char *blob, size_t size,
        const char *mime_type, const char *filename, const char *content_id);


// bloblist_length() - get length of bloblist
//
//  parameters:
//      bloblist (in)   bloblist struct to determine length of
//
//  return value:
//      length of bloblist in number of elements

DYNAMIC_API int bloblist_length(const bloblist_t *bloblist);

#ifdef __cplusplus
}
#endif
