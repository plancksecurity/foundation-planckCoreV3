// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>

#include "stringpair.h"

#include "EngineTestSuite.h"
#include "EngineTestIndividualSuite.h"
#include "StringpairListTests.h"

using namespace std;

StringpairListTests::StringpairListTests(string suitename, string test_home_dir) : 
    EngineTestSuite::EngineTestSuite(suitename, test_home_dir) {            
    TEST_ADD(StringpairListTests::check_stringpair_lists);
}

bool StringpairListTests::test_stringpair_equals(stringpair_t* val1, stringpair_t* val2) {
    assert(val1);
    assert(val2);
    assert(val1->key);
    assert(val2->key);
    assert(val1->value);
    assert(val2->value);
    return((strcmp(val1->key, val2->key) == 0) && (strcmp(val1->value, val2->value) == 0));
}

void StringpairListTests::check_stringpair_lists() {
    cout << "\n*** data structures: stringpair_list_test ***\n\n";

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
    
    cout << "creating one-element stringpair_list...\n";
    
    stringpair_t* strpair = new_stringpair(val_1_arr[0], val_2_arr[0]);
    TEST_ASSERT(strpair);
    stringpair_list_t* pairlist = new_stringpair_list(strpair);
    TEST_ASSERT(pairlist->value);
    TEST_ASSERT(test_stringpair_equals(strpair, pairlist->value));
    TEST_ASSERT(pairlist->next == NULL);
    cout << "one-element stringpair_list created, next element is NULL\n\n";
    
    cout << "duplicating one-element list...\n";
    stringpair_list_t* duplist = stringpair_list_dup(pairlist);
    stringpair_t* srcpair = pairlist->value;
    stringpair_t* dstpair = duplist->value;
    TEST_ASSERT(dstpair);
    TEST_ASSERT(dstpair->value);
    TEST_ASSERT(test_stringpair_equals(srcpair, dstpair));
    TEST_ASSERT(srcpair->key != dstpair->key);   // test deep copies (to be fixed in next 2 commits)
    TEST_ASSERT(srcpair->value != dstpair->value);
    TEST_ASSERT(duplist->next == NULL);
    cout << "one-element stringpair_list duplicated.\n\n";
    
    cout << "freeing stringpair_lists...\n";
    free_stringpair_list(pairlist); // will free strpair
    free_stringpair_list(duplist);
    pairlist = NULL;
    duplist = NULL;
    strpair = NULL;
    
    stringpair_list_t* p;
    cout << "\ncreating four-element list...\n";
    pairlist = stringpair_list_add(pairlist, new_stringpair(val_1_arr[0], val_2_arr[0]));
    for (i = 1; i < 4; i++) {
        p = stringpair_list_add(pairlist, new_stringpair(val_1_arr[i], val_2_arr[i]));
        TEST_ASSERT(p);
    }
    
    p = pairlist;
    
    for (i = 0; i < 4; i++) {
        TEST_ASSERT(p);
        
        strpair = p->value;
        TEST_ASSERT(strpair);
        
        TEST_ASSERT(strpair->key);
        TEST_ASSERT(strcmp(val_1_arr[i], strpair->key) == 0);
        
        TEST_ASSERT(strpair->value);
        TEST_ASSERT(strcmp(val_2_arr[i], strpair->value) == 0);
        
        TEST_ASSERT(val_1_arr[i] != strpair->key);
        TEST_ASSERT(val_2_arr[i] != strpair->value);
        
        p = p->next;
    }
    TEST_ASSERT(p == NULL);
    
    cout << "\nduplicating four-element list...\n\n";
    duplist = stringpair_list_dup(pairlist);
    
    p = pairlist;
    stringpair_list_t* dup_p = duplist;
    
    while (dup_p) {
        srcpair = p->value;
        dstpair = dup_p->value;

        TEST_ASSERT(dstpair);
        TEST_ASSERT(dstpair->value);
        
        cout << srcpair->key << ":" << srcpair->value << " / " << dstpair->key << ":" << dstpair->value << "\n";
        TEST_ASSERT(test_stringpair_equals(srcpair, dstpair));

        TEST_ASSERT(srcpair->key != dstpair->key);   // test deep copies (to be fixed in next 2 commits)
        TEST_ASSERT(srcpair->value != dstpair->value);

        i++;
        p = p->next;

        dup_p = dup_p->next;
        TEST_ASSERT((p == NULL) == (dup_p == NULL));
    }
    cout << "\nfour-element stringpair_list successfully duplicated.\n\n";

    cout << "freeing stringpair_lists...\n";
    free_stringpair_list(pairlist); // will free strpair
    free_stringpair_list(duplist);
    pairlist = NULL;
    duplist = NULL;
    
    cout << "done.\n";
}
