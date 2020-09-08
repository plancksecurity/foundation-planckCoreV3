/**
 * @file    bloblist.h
 * @brief   functions for list structure to hold data of unspecified format (hence,
 *          "blob list"); can contain addition format information in structure's mime info
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

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

/**
 *  @struct	bloblist_t
 *  
 *  @brief	TODO
 *  
 */
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


/**
 *  <!--       new_bloblist()       -->
 *  
 *  @brief Allocate a new bloblist
 *  
 *  @param[in]     blob         blob to add to the list
 *  @param[in]     size         size of the blob
 *  @param[in]     mime_type    MIME type of the blob data or NULL if unknown
 *  @param[in]     filename     file name of origin of blob data or NULL if unknown
 *  
 *  @retval pointer to new bloblist_t or NULL if out of memory
 *  
 *  @ownership 
 *  -  the ownership of the blob goes to the bloblist struct
 *  -  mime_type and filename are copied (copies belong to bloblist struct, 
 *     the originals remain in the ownership of the caller)
 * 
 * @warning  if blob is on a different heap, then after the call, release_value has to
 *           be set by the adapter; this is relevant on operating systems with
 *           multiple heaps like Microsoft Windows
 *  
 */

DYNAMIC_API bloblist_t *new_bloblist(char *blob, size_t size, const char *mime_type,
        const char *filename);


/**
 *  <!--       free_bloblist()       -->
 *  
 *  @brief Free bloblist
 *  
 *  @param[in]     bloblist    bloblist to free
 *  
 *  
 */

DYNAMIC_API void free_bloblist(bloblist_t *bloblist);


/**
 *  <!--       bloblist_dup()       -->
 *  
 *  @brief Duplicate bloblist
 *  
 *  @param[in]     src    bloblist to duplicate
 *  
 *  @retval pointer to a new bloblist_t or NULL if out of memory
 *  
 *  @warning this is an expensive operation because all blobs are copied
 *  
 */

DYNAMIC_API bloblist_t *bloblist_dup(const bloblist_t *src);


/**
 *  <!--       bloblist_add()       -->
 *  
 *  @brief Add reference to a blob to bloblist
 *  
 *  @param[in]     bloblist     bloblist to add to
 *  @param[in]     blob         blob
 *  @param[in]     size         size of the blob
 *  @param[in]     mime_type    MIME type of the blob or NULL if unknown
 *  @param[in]     filename     file name of the blob or NULL if unknown
 *  
 *  @retval pointer to the last element of bloblist or NULL if out of memory or
 *  @retval NULL passed in as blob value
 *  
 *  @ownership 
 *  - the ownership of the blob goes to the bloblist struct 
 *  - mime_type and filename are copied and belong to the bloblist struct, the originals remain in the ownership of the caller.
 *           
 *  @note Bloblist input parameter equal to NULL or with value == NULL is a valid
 *        empty input list.
 * 
 *  @note If there is release_value set in bloblist it is copied to the added
 *        leaf
 *  
 */

DYNAMIC_API bloblist_t *bloblist_add(bloblist_t *bloblist, char *blob, size_t size,
        const char *mime_type, const char *filename);


/**
 *  <!--       bloblist_length()       -->
 *  
 *  @brief Get length of bloblist
 *  
 *  @param[in]     bloblist    bloblist struct to determine length of
 *  
 *  @retval length of bloblist in number of elements
 *  
 *  
 */

DYNAMIC_API int bloblist_length(const bloblist_t *bloblist);


/**
 *  <!--       set_blob_content_disposition()       -->
 *  
 *  @brief Set blob content disposition and parameters
 *         when necessary
 *  
 *  @param[in]     blob           bloblist struct to change disposition for
 *  @param[in]     disposition    disposition type (see enum)
 *  
 *  
 */

DYNAMIC_API void set_blob_disposition(bloblist_t* blob, 
        content_disposition_type disposition);

/**
 *  <!--       bloblist_join()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*first		bloblist_t
 *  @param[in]	*second		bloblist_t
 *  
 */
DYNAMIC_API bloblist_t* bloblist_join(bloblist_t* first, bloblist_t* second);

#ifdef __cplusplus
}
#endif
