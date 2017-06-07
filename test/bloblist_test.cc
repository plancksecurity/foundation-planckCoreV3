// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>

#include "bloblist.h"

using namespace std;

/*
 *     char *address;              // C string with address UTF-8 encoded
    char *fpr;                  // C string with fingerprint UTF-8 encoded
    char *user_id;              // C string with user ID UTF-8 encoded
    char *username;             // C string with user name UTF-8 encoded
    PEP_comm_type comm_type;    // type of communication with this ID
    char lang[3];               // language of conversation
                                // ISO 639-1 ALPHA-2, last byte is 0
    bool me;                    // if this is the local user herself/himself
    */

bool test_blob_equals(size_t size1, char* blob1, size_t size2, char* blob2) {
    if (size1 != size2)
        return false;
    size_t i;
    for (i = 0; i < size1; i++) {
        if (blob1[i] != blob2[i])
            return false;
    }
    return true;
}

bool test_bloblist_node_equals(bloblist_t* val1, bloblist_t* val2) {
    assert(val1);
    assert(val2);
    assert(val1->size == val2->size);
    assert(test_blob_equals(val1->size, val1->value, val2->size, val2->value));
    return( ((!val1->mime_type && !val2->mime_type) || (strcmp(val1->mime_type, val2->mime_type) == 0))
        && ((!val1->filename && !val2->filename) || (strcmp(val1->filename, val2->filename) == 0)));
}

int main() {
    cout << "\n*** data structures: bloblist_test ***\n\n";
    char* text1 = strdup("This is just some text.");
    char* text2 = strdup("More text.");
    char* text3 = strdup("Unpleasant news and witty one-liners.");
    char* text4 = strdup("I AM URDNOT WREX AND THIS IS MY PLANET!");
    bloblist_t* bl1 = new_bloblist(text1, strlen(text1) + 1, "text/plain", NULL, "<julio12345@iglesias.com>");
    bloblist_t* bl2 = new_bloblist(text2, strlen(text2) + 1, "text/richtext", "bob.rtf",NULL);
    bloblist_t* bl3 = new_bloblist(text3, strlen(text3) + 1, NULL, "dummy.bin",NULL);
    bloblist_t* bl4 = new_bloblist(text4, strlen(text4) + 1, NULL, NULL,NULL);
    
    bloblist_t* bl_arr[4] = {bl1, bl2, bl3, bl4};
        
    int i;
        
    cout << "duping one-element bloblist...\n";
    
    bloblist_t* new_bl = bloblist_dup(bl1);
    assert(new_bl);
    assert(test_bloblist_node_equals(bl1, new_bl));
    assert(new_bl->next == NULL);
    assert(bl1->value != new_bl->value);
    assert(bl1->mime_type != new_bl->mime_type || !(bl1->mime_type || new_bl->mime_type));
    assert(bl1->filename != new_bl->filename || !(bl1->filename || new_bl->filename));
    assert(bl1->content_id != new_bl->content_id || !(bl1->content_id || new_bl->content_id));
    cout << "one-element bloblist duplicated.\n\n";
    
    cout << "freeing bloblist...\n";
    free_bloblist(new_bl);
    new_bl = NULL;
    
    bloblist_t* p;
    cout << "\ncreating four-element list...\n";
    bloblist_t* to_copy = bl_arr[0];
    new_bl = bloblist_add(new_bl, strdup(to_copy->value), to_copy->size, to_copy->mime_type, to_copy->filename, to_copy->content_id);
    for (i = 1; i < 4; i++) {
        to_copy = bl_arr[i];
        p = bloblist_add(new_bl, strdup(to_copy->value), to_copy->size, to_copy->mime_type, to_copy->filename, to_copy->content_id);

        assert(p);
    }
    
    p = new_bl;
    
    for (i = 0; i < 4; i++) {
        assert(p);
        
        assert(test_bloblist_node_equals(p, bl_arr[i]));
        assert(p->value != bl_arr[i]->value);
        assert(p->mime_type != bl_arr[i]->mime_type || !(p->mime_type || bl_arr[i]->mime_type));
        assert(p->filename != bl_arr[i]->filename || !(p->filename || bl_arr[i]->filename));
        assert(p->content_id != bl_arr[i]->content_id || !(p->content_id || bl_arr[i]->content_id));
        
        p = p->next;
    }
    assert(p == NULL);
    
    cout << "\nduplicating four-element list...\n\n";
    bloblist_t* duplist = bloblist_dup(new_bl);
    
    p = new_bl;
    bloblist_t* dup_p = duplist;
    
    while (dup_p) {
        assert(test_bloblist_node_equals(p, dup_p));
        assert(p != dup_p);
        assert(p->value != dup_p->value);
        assert(p->mime_type != dup_p->mime_type || !(p->mime_type || dup_p->mime_type));
        assert(p->filename != dup_p->filename || !(p->filename || dup_p->filename));
        assert(p->content_id != dup_p->content_id || !(p->content_id || dup_p->content_id));

        dup_p = dup_p->next;
        p = p->next;
        assert((p == NULL) == (dup_p == NULL));
    }
    cout << "\nfour-element bloblist successfully duplicated.\n\n";

    cout << "freeing bloblists...\n";
    free_bloblist(new_bl);
    free_bloblist(duplist);
    new_bl = NULL;
    duplist = NULL;
    free(text1);
    free(text2);
    free(text3);
    free(text4);    
    cout << "done.\n";
        
    
    return 0;
}
