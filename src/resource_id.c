// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "resource_id.h"

pEp_rid_list_t* new_rid_node(pEp_resource_id_type type, const char* resource) {
    pEp_rid_list_t* retval = (pEp_rid_list_t*)calloc(1, sizeof(pEp_rid_list_t));
    retval->rid_type = type;
    retval->rid = strdup(resource);
    return retval;
}

void free_rid_list(pEp_rid_list_t* list) {
    while (list) {
        pEp_rid_list_t* nextptr = list->next;
        free(list->rid);
        free(list);
        list = nextptr;
    }
}

const char* get_resource_ptr_noown(const char* uri) {
    char* uri_delim = strstr(uri, "://");
    if (!uri_delim)
        return uri;
    else
        return uri + 3;
}

char* get_resource(char* uri) {
    const char* resource_ptr = get_resource_ptr_noown(uri);
    char* resource_str = NULL;
    if (resource_ptr)
        resource_str = strdup(resource_ptr);
    return resource_str;
}

bool is_file_uri(char* str) {
    return(!str ? false : strncmp(str, "file://", 7) == 0);
}

bool is_cid_uri(const char* str) {
    return(!str ? false : strncmp(str, "cid://", 6) == 0);
}

pEp_rid_list_t* parse_uri(const char* uri) {
    if (!uri)
        return NULL;
    pEp_resource_id_type type = (is_cid_uri(uri) ? PEP_RID_CID : PEP_RID_FILENAME);
    const char* resource = get_resource_ptr_noown(uri);
    return new_rid_node(type, resource);
}
