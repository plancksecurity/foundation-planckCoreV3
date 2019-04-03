// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>
#include <cpptest.h>

#include "bloblist.h"
#include "TestConstants.h"

#include "EngineTestSuite.h"
#include "BloblistTests.h"

using namespace std;

BloblistTests::BloblistTests(string suitename, string test_home_dir) : 
    EngineTestSuite::EngineTestSuite(suitename, test_home_dir) {            
    TEST_ADD(BloblistTests::check_bloblists);
}

bool BloblistTests::test_blob_equals(size_t size1, char* blob1, size_t size2, char* blob2) {
    if (size1 != size2)
        return false;
    size_t i;
    for (i = 0; i < size1; i++) {
        if (blob1[i] != blob2[i])
            return false;
    }
    return true;
}

bool BloblistTests::test_bloblist_node_equals(bloblist_t* val1, bloblist_t* val2) {
    assert(val1);
    assert(val2);
    assert(val1->size == val2->size);
    assert(test_blob_equals(val1->size, val1->value, val2->size, val2->value));
    return( ((!val1->mime_type && !val2->mime_type) || (strcmp(val1->mime_type, val2->mime_type) == 0))
        && ((!val1->filename && !val2->filename) || (strcmp(val1->filename, val2->filename) == 0)));
}

void BloblistTests::check_bloblists() {
    cout << "\n*** data structures: bloblist_test ***\n\n";
    char* text1 = strdup("This is just some text.");
    char* text2 = strdup("More text.");
    char* text3 = strdup("Unpleasant news and witty one-liners.");
    char* text4 = strdup("I AM URDNOT WREX AND THIS IS MY PLANET!");
    bloblist_t* bl1 = new_bloblist(text1, strlen(text1) + 1, "text/plain", NULL);
    bloblist_t* bl2 = new_bloblist(text2, strlen(text2) + 1, "text/richtext", "bob.rtf");
    bloblist_t* bl3 = new_bloblist(text3, strlen(text3) + 1, NULL, "dummy.bin");
    bloblist_t* bl4 = new_bloblist(text4, strlen(text4) + 1, NULL, NULL);
    
    bloblist_t* bl_arr[4] = {bl1, bl2, bl3, bl4};
        
    int i;
        
    cout << "duping one-element bloblist...\n";
    
    bloblist_t* new_bl = bloblist_dup(bl1);
    TEST_ASSERT_MSG((new_bl), "new_bl");
    TEST_ASSERT_MSG((test_bloblist_node_equals(bl1, new_bl)), "test_bloblist_node_equals(bl1, new_bl)");
    TEST_ASSERT_MSG((new_bl->next == NULL), "new_bl->next == NULL");
    TEST_ASSERT_MSG((bl1->value != new_bl->value), "bl1->value != new_bl->value");
    TEST_ASSERT_MSG((bl1->mime_type != new_bl->mime_type || !(bl1->mime_type || new_bl->mime_type)), "bl1->mime_type != new_bl->mime_type || !(bl1->mime_type || new_bl->mime_type)");
    TEST_ASSERT_MSG((bl1->filename != new_bl->filename || !(bl1->filename || new_bl->filename)), "bl1->filename != new_bl->filename || !(bl1->filename || new_bl->filename)");
    cout << "one-element bloblist duplicated.\n\n";
    
    cout << "freeing bloblist...\n";
    free_bloblist(new_bl);
    new_bl = NULL;
    
    bloblist_t* p;
    cout << "\ncreating four-element list...\n";
    bloblist_t* to_copy = bl_arr[0];
    new_bl = bloblist_add(new_bl, strdup(to_copy->value), to_copy->size, to_copy->mime_type, to_copy->filename);
    for (i = 1; i < 4; i++) {
        to_copy = bl_arr[i];
        p = bloblist_add(new_bl, strdup(to_copy->value), to_copy->size, to_copy->mime_type, to_copy->filename);

        TEST_ASSERT_MSG((p), "p");
    }
    
    p = new_bl;
    
    for (i = 0; i < 4; i++) {
        TEST_ASSERT_MSG((p), "p");
        
        TEST_ASSERT_MSG((test_bloblist_node_equals(p, bl_arr[i])), "test_bloblist_node_equals(p, bl_arr[i])");
        TEST_ASSERT_MSG((p->value != bl_arr[i]->value), "p->value != bl_arr[i]->value");
        TEST_ASSERT_MSG((p->mime_type != bl_arr[i]->mime_type || !(p->mime_type || bl_arr[i]->mime_type)), "p->mime_type != bl_arr[i]->mime_type || !(p->mime_type || bl_arr[i]->mime_type)");
        TEST_ASSERT_MSG((p->filename != bl_arr[i]->filename || !(p->filename || bl_arr[i]->filename)), "p->filename != bl_arr[i]->filename || !(p->filename || bl_arr[i]->filename)");
        
        p = p->next;
    }
    TEST_ASSERT_MSG((p == NULL), "p == NULL");
    
    cout << "\nduplicating four-element list...\n\n";
    bloblist_t* duplist = bloblist_dup(new_bl);
    
    p = new_bl;
    bloblist_t* dup_p = duplist;
    
    while (dup_p) {
        TEST_ASSERT_MSG((test_bloblist_node_equals(p, dup_p)), "test_bloblist_node_equals(p, dup_p)");
        TEST_ASSERT_MSG((p != dup_p), "p != dup_p");
        TEST_ASSERT_MSG((p->value != dup_p->value), "p->value != dup_p->value");
        TEST_ASSERT_MSG((p->mime_type != dup_p->mime_type || !(p->mime_type || dup_p->mime_type)), "p->mime_type != dup_p->mime_type || !(p->mime_type || dup_p->mime_type)");
        TEST_ASSERT_MSG((p->filename != dup_p->filename || !(p->filename || dup_p->filename)), "p->filename != dup_p->filename || !(p->filename || dup_p->filename)");

        dup_p = dup_p->next;
        p = p->next;
        TEST_ASSERT_MSG(((p == NULL) == (dup_p == NULL)), "(p == NULL) == (dup_p == NULL)");
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
}
