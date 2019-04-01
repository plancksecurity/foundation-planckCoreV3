// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>

#include "stringlist.h"

#include "EngineTestSuite.h"
#include "StringlistTests.h"

using namespace std;

StringlistTests::StringlistTests(string suitename, string test_home_dir) : 
    EngineTestSuite::EngineTestSuite(suitename, test_home_dir) {            
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StringlistTests::check_stringlists"),
                                                                      static_cast<Func>(&StringlistTests::check_stringlists)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StringlistTests::check_dedup_stringlist"),
                                                                      static_cast<Func>(&StringlistTests::check_dedup_stringlist)));
}

void StringlistTests::check_stringlists() {
    cout << "\n*** data structures: stringlist_test ***\n\n";

    const char* str0 = "I am your father, Luke\n";
    
    // new_stringlist test code
    cout << "creating one-element stringlist…\n";
    
    stringlist_t* src = new_stringlist(str0);
    TEST_ASSERT_MSG((src), "src");
    TEST_ASSERT_MSG((strcmp(src->value,str0) == 0), "strcmp(src->value,str0) == 0");
    cout << "Value: " << src->value;
    TEST_ASSERT_MSG((src->next == NULL), "src->next == NULL");
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
    TEST_ASSERT_MSG((src), "src");
    TEST_ASSERT_MSG((stringlist_add(src, str2)), "stringlist_add(src, str2)"); // returns ptr to new elt
    TEST_ASSERT_MSG((stringlist_add(src, str3)), "stringlist_add(src, str3)");
    TEST_ASSERT_MSG((stringlist_add(src, str4)), "stringlist_add(src, str4)");
    
    cout << "checking contents\n";
    stringlist_t* p = src;
    int i = 0;
    while (p) {
        TEST_ASSERT_MSG((p->value), "p->value");
        TEST_ASSERT_MSG((strcmp(p->value, strarr[i]) == 0), "strcmp(p->value, strarr[i]) == 0");
        TEST_ASSERT_MSG((p->value != strarr[i]), "p->value != strarr[i]"); // ensure this is a copy
        p = p->next;
        i++;
    }
    TEST_ASSERT_MSG((p == NULL), "p == NULL"); // list ends properly
    
    cout << "\nduplicating four-element stringlist…\n";
    stringlist_t* dst = stringlist_dup(src);
    TEST_ASSERT_MSG((dst), "dst");
    
    stringlist_t* p_dst = dst;
    p = src;

    cout << "checking contents\n";    
    while (p_dst) {
        TEST_ASSERT_MSG((p_dst->value), "p_dst->value");
        TEST_ASSERT_MSG((strcmp(p->value, p_dst->value) == 0), "strcmp(p->value, p_dst->value) == 0");
        TEST_ASSERT_MSG((p->value != p_dst->value), "p->value != p_dst->value"); // ensure this is a copy
        cout << p_dst->value;
        p = p->next;
        p_dst = p_dst->next;
        TEST_ASSERT_MSG(((p == NULL) == (p_dst == NULL)), "(p == NULL) == (p_dst == NULL)");
    }
    TEST_ASSERT_MSG((p_dst == NULL), "p_dst == NULL");
        
    cout << "freeing stringlists…\n\n";
    free_stringlist(src);
    free_stringlist(dst);
    src = NULL;
    dst = NULL;

    cout << "duplicating one-element stringlist…\n";    
    src = new_stringlist(str0);
    TEST_ASSERT_MSG((src), "src");
    dst = stringlist_dup(src);
    TEST_ASSERT_MSG((strcmp(dst->value, str0) == 0), "strcmp(dst->value, str0) == 0");
    cout << "Value: " << src->value;
    TEST_ASSERT_MSG((dst->next == NULL), "dst->next == NULL");
    cout << "one-element stringlist duped, next element is NULL\n";
    
    cout << "\nAdd to empty stringlist (node exists, but no value…)\n";
    if (src->value)
        free(src->value);
    src->value = NULL;
    stringlist_add(src, str2);
    TEST_ASSERT_MSG((src->value), "src->value");
    TEST_ASSERT_MSG((strcmp(src->value, str2) == 0), "strcmp(src->value, str2) == 0");
    TEST_ASSERT_MSG((src->value != str2), "src->value != str2"); // ensure this is a copy
    cout << src->value;

    cout << "\nfreeing stringlists…\n\n";
    free_stringlist(src);
    free_stringlist(dst);
    
    src = NULL;
    dst = NULL;
    
    cout << "done.\n";
}

void StringlistTests::check_dedup_stringlist() {
    const char* str1 = "Your Mama";
    const char* str2 = "And your Papa";
    const char* str3 = "And your little dog too!";
    const char* str4 = "Meh";
    
    stringlist_t* s_list = NULL;
    dedup_stringlist(s_list);
    TEST_ASSERT(s_list == NULL);
    
    s_list = new_stringlist(NULL);
    dedup_stringlist(s_list);    
    TEST_ASSERT(s_list->value == NULL);
    
    stringlist_add(s_list, str1);
    dedup_stringlist(s_list);
    TEST_ASSERT(s_list->value);
    TEST_ASSERT(strcmp(s_list->value, str1) == 0);
    TEST_ASSERT(!s_list->next);

    // Add same value
    stringlist_add(s_list, str1);
    dedup_stringlist(s_list);
    TEST_ASSERT(s_list->value);
    TEST_ASSERT(strcmp(s_list->value, str1) == 0);
    TEST_ASSERT(!s_list->next);

    stringlist_add(s_list, str1);
    stringlist_add(s_list, str2);
    dedup_stringlist(s_list);
    TEST_ASSERT(s_list->value);
    TEST_ASSERT(strcmp(s_list->value, str1) == 0);
    TEST_ASSERT(s_list->next);
    TEST_ASSERT(!s_list->next->next);
    TEST_ASSERT(s_list->next->value);
    TEST_ASSERT(strcmp(s_list->next->value, str2) == 0);    

    free_stringlist(s_list);
    s_list = new_stringlist(str1);
    
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    dedup_stringlist(s_list);
    TEST_ASSERT(s_list->value);
    TEST_ASSERT(strcmp(s_list->value, str1) == 0);
    TEST_ASSERT(!s_list->next);

    free_stringlist(s_list);
    s_list = new_stringlist(str1);

    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str2);
    stringlist_add(s_list, str1);
    dedup_stringlist(s_list);
    TEST_ASSERT(s_list->value);
    TEST_ASSERT(strcmp(s_list->value, str1) == 0);
    TEST_ASSERT(s_list->next);
    TEST_ASSERT(!s_list->next->next);
    TEST_ASSERT(s_list->next->value);
    TEST_ASSERT(strcmp(s_list->next->value, str2) == 0);    

    free_stringlist(s_list);
    s_list = new_stringlist(str3);

    stringlist_add(s_list, str2);
    stringlist_add(s_list, str3);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str3);
    stringlist_add(s_list, str2);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str4);
    stringlist_add(s_list, str3);

    dedup_stringlist(s_list);
    TEST_ASSERT(s_list->next);
    TEST_ASSERT(s_list->next->next);
    TEST_ASSERT(s_list->next->next->next);
    TEST_ASSERT(!s_list->next->next->next->next);
    TEST_ASSERT(s_list->value);
    TEST_ASSERT(strcmp(s_list->value, str3) == 0);    
    TEST_ASSERT(s_list->next->value);
    TEST_ASSERT(strcmp(s_list->next->value, str2) == 0);    
    TEST_ASSERT(s_list->next->next->value);
    TEST_ASSERT(strcmp(s_list->next->next->value, str1) == 0);    
    TEST_ASSERT(s_list->next->next->next->value);
    TEST_ASSERT(strcmp(s_list->next->next->next->value, str4) == 0);    
}
