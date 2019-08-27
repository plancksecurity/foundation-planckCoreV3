// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>

#include "stringlist.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for StringlistTest
    class StringlistTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            StringlistTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~StringlistTest() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

                // Get a new test Engine.
                engine = new Engine(test_path);
                ASSERT_NE(engine, nullptr);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NE(engine->session, nullptr);
                session = engine->session;

                // Engine is up. Keep on truckin'
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the StringlistTest suite.

    };

}  // namespace


TEST_F(StringlistTest, check_stringlists) {
    cout << "\n*** data structures: stringlist_test ***\n\n";

    const char* str0 = "I am your father, Luke\n";

    // new_stringlist test code
    cout << "creating one-element stringlist…\n";

    stringlist_t* src = new_stringlist(str0);
    ASSERT_NE((src), nullptr);
    ASSERT_STREQ(src->value, str0);
    cout << "Value: " << src->value;
    ASSERT_EQ(src->next , NULL);
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
    ASSERT_NE(src, nullptr);
    ASSERT_NE(stringlist_add(src, str2), nullptr); // returns ptr to new elt
    ASSERT_NE(stringlist_add(src, str3), nullptr);
    ASSERT_NE(stringlist_add(src, str4), nullptr);

    cout << "checking contents\n";
    stringlist_t* p = src;
    int i = 0;
    while (p) {
        ASSERT_NE((p->value), nullptr);
        ASSERT_STREQ(p->value, strarr[i]);
        ASSERT_NE(p->value , strarr[i]); // ensure this is a copy
        p = p->next;
        i++;
    }
    ASSERT_EQ(p , NULL); // list ends properly

    cout << "\nduplicating four-element stringlist…\n";
    stringlist_t* dst = stringlist_dup(src);
    ASSERT_NE(dst, nullptr);

    stringlist_t* p_dst = dst;
    p = src;

    cout << "checking contents\n";
    while (p_dst) {
        ASSERT_NE(p_dst->value, nullptr);
        ASSERT_STREQ(p->value, p_dst->value);
        ASSERT_NE(p->value , p_dst->value); // ensure this is a copy
        cout << p_dst->value;
        p = p->next;
        p_dst = p_dst->next;
        ASSERT_TRUE((p == NULL) == (p_dst == NULL));
    }
    ASSERT_EQ(p_dst , NULL);

    cout << "freeing stringlists…\n\n";
    free_stringlist(src);
    free_stringlist(dst);
    src = NULL;
    dst = NULL;

    cout << "duplicating one-element stringlist…\n";
    src = new_stringlist(str0);
    ASSERT_NE(src, nullptr);
    dst = stringlist_dup(src);
    ASSERT_STREQ(dst->value, str0);
    cout << "Value: " << src->value;
    ASSERT_EQ(dst->next , nullptr);
    cout << "one-element stringlist duped, next element is NULL\n";

    cout << "\nAdd to empty stringlist (node exists, but no value…)\n";
    if (src->value)
        free(src->value);
    src->value = NULL;
    stringlist_add(src, str2);
    ASSERT_NE(src->value, nullptr);
    ASSERT_STREQ(src->value, str2);
    ASSERT_NE(src->value , str2); // ensure this is a copy
    cout << src->value;

    cout << "\nfreeing stringlists…\n\n";
    free_stringlist(src);
    free_stringlist(dst);

    src = NULL;
    dst = NULL;

    cout << "done.\n";
}

TEST_F(StringlistTest, check_dedup_stringlist) {
    const char* str1 = "Your Mama";
    const char* str2 = "And your Papa";
    const char* str3 = "And your little dog too!";
    const char* str4 = "Meh";

    stringlist_t* s_list = NULL;
    dedup_stringlist(s_list);
    ASSERT_EQ(s_list , nullptr);

    s_list = new_stringlist(NULL);
    dedup_stringlist(s_list);
    ASSERT_EQ(s_list->value , nullptr);

    stringlist_add(s_list, str1);
    dedup_stringlist(s_list);
    ASSERT_NE(s_list->value, nullptr);
    ASSERT_STREQ(s_list->value, str1);
    ASSERT_NE(s_list->next, nullptr);

    // Add same value
    stringlist_add(s_list, str1);
    dedup_stringlist(s_list);
    ASSERT_NE(s_list->value, nullptr);
    ASSERT_STREQ(s_list->value, str1);
    ASSERT_NE(s_list->next, nullptr);

    stringlist_add(s_list, str1);
    stringlist_add(s_list, str2);
    dedup_stringlist(s_list);
    ASSERT_NE(s_list->value, nullptr);
    ASSERT_STREQ(s_list->value, str1);
    ASSERT_NE(s_list->next, nullptr);
    ASSERT_NE(s_list->next->next, nullptr);
    ASSERT_NE(s_list->next->value, nullptr);
    ASSERT_STREQ(s_list->next->value, str2);

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
    ASSERT_NE(s_list->value, nullptr);
    ASSERT_STREQ(s_list->value, str1);
    ASSERT_NE(s_list->next, nullptr);

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
    ASSERT_NE(s_list->value, nullptr);
    ASSERT_STREQ(s_list->value, str1);
    ASSERT_NE(s_list->next, nullptr);
    ASSERT_NE(s_list->next->next, nullptr);
    ASSERT_NE(s_list->next->value, nullptr);
    ASSERT_STREQ(s_list->next->value, str2);

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
    ASSERT_NE(s_list->next, nullptr);
    ASSERT_NE(s_list->next->next, nullptr);
    ASSERT_NE(s_list->next->next->next, nullptr);
    ASSERT_NE(s_list->next->next->next->next, nullptr);
    ASSERT_NE(s_list->value, nullptr);
    ASSERT_STREQ(s_list->value, str3);
    ASSERT_NE(s_list->next->value, nullptr);
    ASSERT_STREQ(s_list->next->value, str2);
    ASSERT_NE(s_list->next->next->value, nullptr);
    ASSERT_STREQ(s_list->next->next->value, str1);
    ASSERT_NE(s_list->next->next->next->value, nullptr);
    ASSERT_STREQ(s_list->next->next->next->value, str4);
}
