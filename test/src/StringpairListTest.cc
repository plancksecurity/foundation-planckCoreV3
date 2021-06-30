// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>

#include "stringpair.h"

#include "TestUtilities.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for StringpairListTest
    class StringpairListTest : public ::testing::Test {
        protected:
            bool test_stringpair_equals(stringpair_t* val1, stringpair_t* val2) {
                assert(val1);
                assert(val2);
                assert(val1->key);
                assert(val2->key);
                assert(val1->value);
                assert(val2->value);
                return((strcmp(val1->key, val2->key) == 0) && (strcmp(val1->value, val2->value) == 0));
            }
    };

}  // namespace



TEST_F(StringpairListTest, check_stringpair_lists) {
    output_stream << "\n*** data structures: stringpair_list_test ***\n\n";

    const char* val_1_arr[4] = {"I am your father, Luke",
                                "These are not the droids you're looking for",
                                "Swooping is bad",
                                "I should go."};
    const char* val_2_arr[4] = {"Had to be me.",
                                "Someone else might have gotten it wrong",
                                "Na via lerno victoria",
                                "I was told that there would be cake."};

//    const stringpair_t* stringpair_arr[4];

    int i;

//    for (i = 0; i < 4; i++) {
//        stringpair_arr[i] = new stringpair(val_1_arr[i], val_2_arr[i]);
//    }

    output_stream << "creating one-element stringpair_list...\n";

    stringpair_t* strpair = new_stringpair(val_1_arr[0], val_2_arr[0]);
    ASSERT_NOTNULL(strpair);
    stringpair_list_t* pairlist = new_stringpair_list(strpair);
    ASSERT_NOTNULL(pairlist->value);
    ASSERT_TRUE(test_stringpair_equals(strpair, pairlist->value));
    ASSERT_NULL(pairlist->next );
    output_stream << "one-element stringpair_list created, next element is NULL\n\n";

    output_stream << "duplicating one-element list...\n";
    stringpair_list_t* duplist = stringpair_list_dup(pairlist);
    stringpair_t* srcpair = pairlist->value;
    stringpair_t* dstpair = duplist->value;
    ASSERT_NOTNULL(dstpair);
    ASSERT_NOTNULL(dstpair->value);
    ASSERT_TRUE(test_stringpair_equals(srcpair, dstpair));
    ASSERT_NE(srcpair->key , dstpair->key);   // test deep copies (to be fixed in next 2 commits)
    ASSERT_NE(srcpair->value , dstpair->value);
    ASSERT_NULL(duplist->next );
    output_stream << "one-element stringpair_list duplicated.\n\n";

    output_stream << "freeing stringpair_lists...\n";
    free_stringpair_list(pairlist); // will free strpair
    free_stringpair_list(duplist);
    pairlist = NULL;
    duplist = NULL;
    strpair = NULL;

    stringpair_list_t* p;
    output_stream << "\ncreating four-element list...\n";
    pairlist = stringpair_list_add(pairlist, new_stringpair(val_1_arr[0], val_2_arr[0]));
    for (i = 1; i < 4; i++) {
        p = stringpair_list_add(pairlist, new_stringpair(val_1_arr[i], val_2_arr[i]));
        ASSERT_NOTNULL(p);
    }

    p = pairlist;

    for (i = 0; i < 4; i++) {
        ASSERT_NOTNULL(p);

        strpair = p->value;
        ASSERT_NOTNULL(strpair);

        ASSERT_NOTNULL(strpair->key);
        ASSERT_STREQ(val_1_arr[i], strpair->key);

        ASSERT_NOTNULL(strpair->value);
        ASSERT_STREQ(val_2_arr[i], strpair->value);

        ASSERT_NE(val_1_arr[i] , strpair->key);
        ASSERT_NE(val_2_arr[i] , strpair->value);

        p = p->next;
    }
    ASSERT_NULL(p );

    output_stream << "\nduplicating four-element list...\n\n";
    duplist = stringpair_list_dup(pairlist);

    p = pairlist;
    stringpair_list_t* dup_p = duplist;

    while (dup_p) {
        srcpair = p->value;
        dstpair = dup_p->value;

        ASSERT_NOTNULL(dstpair);
        ASSERT_NOTNULL(dstpair->value);

        output_stream << srcpair->key << ":" << srcpair->value << " / " << dstpair->key << ":" << dstpair->value << "\n";
        ASSERT_TRUE(test_stringpair_equals(srcpair, dstpair));

        ASSERT_NE(srcpair->key , dstpair->key);   // test deep copies (to be fixed in next 2 commits)
        ASSERT_NE(srcpair->value , dstpair->value);

        i++;
        p = p->next;

        dup_p = dup_p->next;
        ASSERT_TRUE((p == NULL) == (dup_p == NULL));
    }
    output_stream << "\nfour-element stringpair_list successfully duplicated.\n\n";

    output_stream << "freeing stringpair_lists...\n";
    free_stringpair_list(pairlist); // will free strpair
    free_stringpair_list(duplist);
    pairlist = NULL;
    duplist = NULL;

    output_stream << "done.\n";
}
