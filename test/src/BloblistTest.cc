// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>

#include "bloblist.h"
#include "TestConstants.h"

#include "TestUtilities.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for BloblistTest
    class BloblistTest : public ::testing::Test { 
        protected:
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
    };

}  // namespace



TEST_F(BloblistTest, check_bloblists) {
    output_stream << "\n*** data structures: bloblist_test ***\n\n";
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

    output_stream << "duping one-element bloblist...\n";

    bloblist_t* new_bl = bloblist_dup(bl1);
    ASSERT_NOTNULL(new_bl);
    ASSERT_TRUE(test_bloblist_node_equals(bl1, new_bl));
    ASSERT_NULL(new_bl->next );
    ASSERT_NE(bl1->value , new_bl->value);
    ASSERT_TRUE(bl1->mime_type != new_bl->mime_type || !(bl1->mime_type || new_bl->mime_type));
    ASSERT_TRUE(bl1->filename != new_bl->filename || !(bl1->filename || new_bl->filename));
    output_stream << "one-element bloblist duplicated.\n\n";

    output_stream << "freeing bloblist...\n";
    free_bloblist(new_bl);
    new_bl = NULL;

    bloblist_t* p;
    output_stream << "\ncreating four-element list...\n";
    bloblist_t* to_copy = bl_arr[0];
    new_bl = bloblist_add(new_bl, strdup(to_copy->value), to_copy->size, to_copy->mime_type, to_copy->filename);
    for (i = 1; i < 4; i++) {
        to_copy = bl_arr[i];
        p = bloblist_add(new_bl, strdup(to_copy->value), to_copy->size, to_copy->mime_type, to_copy->filename);

        ASSERT_NOTNULL((p));
    }

    p = new_bl;

    for (i = 0; i < 4; i++) {
        ASSERT_NOTNULL(p);

        ASSERT_TRUE(test_bloblist_node_equals(p, bl_arr[i]));
        ASSERT_TRUE(p->value != bl_arr[i]->value);
        ASSERT_TRUE(p->mime_type != bl_arr[i]->mime_type || !(p->mime_type || bl_arr[i]->mime_type));
        ASSERT_TRUE(p->filename != bl_arr[i]->filename || !(p->filename || bl_arr[i]->filename));

        p = p->next;
    }
    ASSERT_NULL(p );

    output_stream << "\nduplicating four-element list...\n\n";
    bloblist_t* duplist = bloblist_dup(new_bl);

    p = new_bl;
    bloblist_t* dup_p = duplist;

    while (dup_p) {
        ASSERT_TRUE(test_bloblist_node_equals(p, dup_p));
        ASSERT_NE(p , dup_p);
        ASSERT_TRUE(p->value != dup_p->value);
        ASSERT_TRUE(p->mime_type != dup_p->mime_type || !(p->mime_type || dup_p->mime_type));
        ASSERT_TRUE(p->filename != dup_p->filename || !(p->filename || dup_p->filename));

        dup_p = dup_p->next;
        p = p->next;
        ASSERT_TRUE((p == NULL) == (dup_p == NULL));
    }
    output_stream << "\nfour-element bloblist successfully duplicated.\n\n";

    output_stream << "freeing bloblists...\n";
    free_bloblist(new_bl);
    free_bloblist(duplist);
    new_bl = NULL;
    duplist = NULL;
    free(text1);
    free(text2);
    free(text3);
    free(text4);
    output_stream << "done.\n";
}
