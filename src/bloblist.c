/** 
 * @file    bloblist.c
 * @brief   implemantation of functions for list structure to hold data of unspecified 
 *          format (hence, "blob list"); can contain additional format information in structure's mime info
 * @license GNU General Public License 3.0 - see LICENSE.txt
*/

#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "platform.h"
#include "bloblist.h"

static bool set_blob_data(bloblist_t* bloblist, char* blob, size_t size, const char* mime_type,
        const char* filename)
{
    if (!bloblist)
        return false;
        
    if (mime_type) {
       bloblist->mime_type = strdup(mime_type);
       if (bloblist->mime_type == NULL) {
           return false;
       }
    }
    
    if (filename) {
       bloblist->filename = strdup(filename);
       if (bloblist->filename == NULL) {
           free(bloblist->mime_type);
           return false;
       }
       /* Default behaviour, can be overwritten post-allocation with
          set_blob_content_disposition */
       if (strncmp(filename, "cid://", 6) == 0)
           bloblist->disposition = PEP_CONTENT_DISP_INLINE;
    }               
    
    if (blob) {
        bloblist->value = blob;
        bloblist->size = size;
    }
    
    return true;
}

DYNAMIC_API bloblist_t *new_bloblist(char *blob, size_t size, const char *mime_type,
        const char *filename)
{
    bloblist_t * bloblist = calloc(1, sizeof(bloblist_t));
    assert(bloblist);
    if (bloblist == NULL)
        return NULL;

    if (!set_blob_data(bloblist, blob, size, mime_type, filename)) {
        free(bloblist);
        bloblist = NULL;
    }

    return bloblist;
}

DYNAMIC_API void free_bloblist(bloblist_t *bloblist)
{
    bloblist_t *curr = bloblist;

    while (curr) {
        bloblist_t *next = curr->next;
        if (curr->release_value)
            curr->release_value(curr->value);
        else
            free(curr->value);
        free(curr->mime_type);
        free(curr->filename);
        free(curr);
        curr = next;
    }
}

DYNAMIC_API bloblist_t *bloblist_dup(const bloblist_t *src)
{
    assert(src);
    if (src == NULL)
        return NULL;

    bloblist_t* head_ptr = NULL;
    bloblist_t** dst_curr_ptr = &head_ptr;

    const bloblist_t* src_curr = src;

    char* blob2 = NULL;

    for ( ; src_curr; src_curr = src_curr->next, dst_curr_ptr = &((*dst_curr_ptr)->next)) {
        blob2 = malloc(src_curr->size);

        assert(blob2);
        if (blob2 == NULL)
            goto enomem;

        // This is why we don't calloc
        memcpy(blob2, src_curr->value, src_curr->size);

        *dst_curr_ptr = new_bloblist(blob2, src_curr->size, src_curr->mime_type, src_curr->filename);
        if (*dst_curr_ptr == NULL)
            goto enomem;
    }

    if (!head_ptr)
        return NULL;

    return head_ptr;

enomem:
    free(blob2);
    free_bloblist(head_ptr);
    return NULL;
}

DYNAMIC_API bloblist_t *bloblist_add(bloblist_t *bloblist, char *blob, size_t size,
        const char *mime_type, const char *filename)
{
    assert(blob);
    if (!blob)
        return NULL;

    if (!bloblist)
        return new_bloblist(blob, size, mime_type, filename);

    if (!bloblist->value) { // empty list
        assert(!bloblist->next);
        if (bloblist->next)
            return NULL; // invalid list
            
        if (!set_blob_data(bloblist, blob, size, mime_type, filename)) {
            free(bloblist);
            bloblist = NULL;
        }

        return bloblist;
    }

    bloblist_t* list_curr = bloblist;
    void (*release_value)(char *) = list_curr->release_value;

    while (list_curr->next)
        list_curr = list_curr->next;

    list_curr->next = new_bloblist(blob, size, mime_type, filename);
    list_curr->next->release_value = release_value;

    assert(list_curr->next);
    if (!list_curr->next)
        return NULL;

    return list_curr->next;
}

DYNAMIC_API bloblist_t* bloblist_join(bloblist_t* first, bloblist_t* second) {
    if (!first)
        return second;
    if (!second)
        return first;

    if (first == second)
        return first;

    bloblist_t* list_curr = first;
    
    while (list_curr->next) {
        list_curr = list_curr->next;
    }
    list_curr->next = second;
    
    return first;
}

DYNAMIC_API int bloblist_length(const bloblist_t *bloblist)
{
    int len = 0;

    for (const bloblist_t *_bl = bloblist; _bl && _bl->value; _bl = _bl->next)
        len++;

    return len;
}

DYNAMIC_API void set_blob_disposition(bloblist_t* blob, 
        content_disposition_type disposition)
{
    if (blob)                                    
        blob->disposition = disposition;
}

bloblist_t* find_blob_by_URI(bloblist_t* bloblist, const char* uri) {
    if (!bloblist || !uri)
        return NULL;
    bloblist_t* retval = bloblist;
    for (; retval ; retval = retval->next) {
        if (retval->filename && strcmp(retval->filename, uri) == 0) {
            break;
        }    
    }
    return retval;    
}
