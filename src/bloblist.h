// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef BLOBLIST_H
#define BLOBLIST_H

#include <stddef.h> 

#include "dynamic_api.h"
#include "stringpair.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PEP_CONTENT_DISP_ATTACHMENT = 0,
    PEP_CONTENT_DISP_INLINE = 1,
    PEP_CONTENT_DISP_OTHER = -1      // must be affirmatively set
} content_disposition_type;

typedef struct _bloblist_t {
    char *value;                        // blob
    size_t size;                        // size of blob
    char *mime_type;                    // UTF-8 string of MIME type of blob or
                                        // NULL if unknown
    char *filename;                     // UTF-8 string of file name of blob or
                                        // NULL if unknown
    content_disposition_type disposition;
                                        // default is attachment when allocated
                                        // (see mime.h and RFC2183)
    struct _bloblist_t *next;           // this is a single linked list
    void (*release_value)(char *);      // pointer to release function;
                                        // pEp_free() if not set
} bloblist_t;


// new_bloblist() - allocate a new bloblist
//
//  parameters:
//      blob (in)       blob to add to the list
//      size (in)       size of the blob
//      mime_type (in)  MIME type of the blob data or NULL if unknown
//      filename (in)  file name of origin of blob data or NULL if unknown
//
//  return value:
//      pointer to new bloblist_t or NULL if out of memory
//
//  caveat:
//      the ownership of the blob goes to the bloblist; mime_type and filename
//      are being copied, the originals remain in the ownership of the caller
//
//      if blob is on a different heap then after the call release_value has to
//      be set by the adapter; this is relevant on operating systems with
//      multiple heaps like Microsoft Windows

DYNAMIC_API bloblist_t *new_bloblist(char *blob, size_t size, const char *mime_type,
        const char *filename);


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
//      bloblist (in)   bloblist to add to
//      blob (in)       blob
//      size (in)       size of the blob
//      mime_type (in)  MIME type of the blob or NULL if unknown
//      filename (in)  file name of the blob or NULL if unknown
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
//
//      If there is release_value set in bloblist it is copied to the added
//      leaf

DYNAMIC_API bloblist_t *bloblist_add(bloblist_t *bloblist, char *blob, size_t size,
        const char *mime_type, const char *filename);


// bloblist_length() - get length of bloblist
//
//  parameters:
//      bloblist (in)   bloblist struct to determine length of
//
//  return value:
//      length of bloblist in number of elements

DYNAMIC_API int bloblist_length(const bloblist_t *bloblist);


// set_blob_content_disposition() - set blob content disposition and parameters
//                                  when necessary
//
//  parameters:
//      blob (in)               bloblist struct to change disposition for
//      disposition (in)        disposition type (see enum)

DYNAMIC_API void set_blob_disposition(bloblist_t* blob, 
        content_disposition_type disposition);

// bloblist_join() - append second list to the first.
//
//  parameters:
//      first (in)              first bloblist, to be head of list if not NULL
//      second (in)             bloblist to append to first bloblist; if first
//                              bloblist is NULL, this will be the head of the list
//
//  return value:
//      head of the joined bloblist
//
//  caveats:
//      This function appends the actual bloblist to the end of the first - ownership
//      of the second bloblist goes to the list. THERE IS NO COPYING.
//      Also, if the same pointer is sent in twice, there is no join - the original
//      list will be returned as is.
DYNAMIC_API bloblist_t* bloblist_join(bloblist_t* first, bloblist_t* second);

#ifdef __cplusplus
}
#endif

#endif
