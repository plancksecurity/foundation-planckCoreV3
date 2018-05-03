// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>

#include "stringlist.h"

#include "EngineTestSuite.h"
#include "EngineTestIndividualSuite.h"
#include "StringlistTests.h"

using namespace std;

StringlistTests::StringlistTests(string suitename, string test_home_dir) : 
    EngineTestSuite::EngineTestSuite(suitename, test_home_dir) {            
    TEST_ADD(StringlistTests::check_stringlists);
}

void StringlistTests::check_stringlists() {
    cout << "\n*** data structures: stringlist_test ***\n\n";

    const char* str0 = "I am your father, Luke\n";
    
    // new_stringlist test code
    cout << "creating one-element stringlist…\n";
    
    stringlist_t* src = new_stringlist(str0);
    assert(src);
    assert(strcmp(src->value,str0) == 0);
    cout << "Value: " << src->value;
    assert(src->next == NULL);
    cout << "one-element stringlist created, next element is NULL\n";
    
    cout << "freeing stringlist…\n\n";
    free_stringlist(src);
    src = NULL;
    
    // test stringlist_add with four-element list
    cout << "creating four-element stringlist…\n";
    const char* str1 = "String 1";
    const char* str2 = "\tString 2";
    const char* str3 = "\tString 3";
    const char* str4 = "\tString 4\n";
    const char* strarr[4] = {str1, str2, str3, str4};
    cout << "stringlist_add on empty list…\n";
    src = stringlist_add(src, str1); // src is NULL
    assert(src);
    assert(stringlist_add(src, str2)); // returns ptr to new elt
    assert(stringlist_add(src, str3));
    assert(stringlist_add(src, str4));
    
    cout << "checking contents\n";
    stringlist_t* p = src;
    int i = 0;
    while (p) {
        assert(p->value);
        assert(strcmp(p->value, strarr[i++]) == 0);
        assert(p->value != *(strarr + i)); // ensure this is a copy
        cout << p->value;
        p = p->next;
    }
    assert(p == NULL); // list ends properly
    
    cout << "\nduplicating four-element stringlist…\n";
    stringlist_t* dst = stringlist_dup(src);
    assert(dst);
    
    stringlist_t* p_dst = dst;
    p = src;

    cout << "checking contents\n";    
    while (p_dst) {
        assert(p_dst->value);
        assert(strcmp(p->value, p_dst->value) == 0);
        assert(p->value != p_dst->value); // ensure this is a copy
        cout << p_dst->value;
        p = p->next;
        p_dst = p_dst->next;
        assert((p == NULL) == (p_dst == NULL));
    }
    assert(p_dst == NULL);
        
    cout << "freeing stringlists…\n\n";
    free_stringlist(src);
    free_stringlist(dst);
    src = NULL;
    dst = NULL;

    cout << "duplicating one-element stringlist…\n";    
    src = new_stringlist(str0);
    assert(src);
    dst = stringlist_dup(src);
    assert(strcmp(dst->value, str0) == 0);
    cout << "Value: " << src->value;
    assert(dst->next == NULL);
    cout << "one-element stringlist duped, next element is NULL\n";
    
    cout << "\nAdd to empty stringlist (node exists, but no value…)\n";
    if (src->value)
        free(src->value);
    src->value = NULL;
    stringlist_add(src, str2);
    assert(src->value);
    assert(strcmp(src->value, str2) == 0);
    assert(src->value != str2); // ensure this is a copy
    cout << src->value;

    cout << "\nfreeing stringlists…\n\n";
    free_stringlist(src);
    free_stringlist(dst);
    
    src = NULL;
    dst = NULL;
    
    cout << "done.\n";
}
