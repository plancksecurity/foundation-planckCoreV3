// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include <cpptest.h>
#include "test_util.h"

#include "pEpEngine.h"
#include "platform_unix.h"

#include "EngineTestIndividualSuite.h"
#include "StrnstrTests.h"

using namespace std;

StrnstrTests::StrnstrTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_equal"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_equal)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_first_empty"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_first_empty)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_second_empty"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_second_empty)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_both_empty"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_both_empty)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_first_letter_only"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_first_letter_only)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_first_two_only"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_first_two_only)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_all_but_last"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_all_but_last)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_same_len_all_but_last"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_same_len_all_but_last)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_same_len_none"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_same_len_none)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_same_big_smaller"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_same_big_smaller)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_shift_one_no_match"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_shift_one_no_match)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_shift_to_end"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_shift_to_end)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_match_after_end"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_match_after_end)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("StrnstrTests::check_strnstr_equal_but_size_too_small"),
                                                                      static_cast<Func>(&StrnstrTests::check_strnstr_equal_but_size_too_small)));
}

void StrnstrTests::check_strnstr_equal() {
    const char* big = "Bob123";
    const char* little = "Bob123";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    TEST_ASSERT_MSG(result == big, result);
}

void StrnstrTests::check_strnstr_first_empty() {
    const char* big = "";
    const char* little = "Bob123";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    TEST_ASSERT_MSG(result == NULL, result);
}
void StrnstrTests::check_strnstr_second_empty() {
    const char* big = "YerMama";
    const char* little = "";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    TEST_ASSERT_MSG(result == big, result);
    TEST_ASSERT(true);
}

void StrnstrTests::check_strnstr_both_empty() {
    const char* big = "";
    const char* little = "";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    TEST_ASSERT_MSG(result == big, result);
    TEST_ASSERT(true);
}

void StrnstrTests::check_strnstr_first_letter_only() {
    const char* big = "Bob123";
    const char* little = "Beef";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    TEST_ASSERT_MSG(result == NULL, result);    
}
void StrnstrTests::check_strnstr_first_two_only() {
    const char* big = "Bob123";
    const char* little = "Boof";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    TEST_ASSERT_MSG(result == NULL, result);    
}
void StrnstrTests::check_strnstr_all_but_last() {
    const char* big = "BeesBeesBees";
    const char* little = "Beef";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    TEST_ASSERT_MSG(result == NULL, result);    
}
void StrnstrTests::check_strnstr_same_len_all_but_last() {
    const char* big = "Bees";
    const char* little = "Beef";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    TEST_ASSERT_MSG(result == NULL, result);    
}
void StrnstrTests::check_strnstr_same_len_none() {
    const char* big = "1234";
    const char* little = "Beef";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    TEST_ASSERT_MSG(result == NULL, result);    
}
void StrnstrTests::check_strnstr_same_big_smaller() {
    const char* big = "Bee";
    const char* little = "Bees";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    TEST_ASSERT_MSG(result == NULL, result);    
}
void StrnstrTests::check_strnstr_shift_one_no_match() {
    const char* big = "1Bee";
    const char* little = "Bees";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    TEST_ASSERT_MSG(result == NULL, result);    
}
void StrnstrTests::check_strnstr_shift_to_end() {
    const char* big = "BigBeeWithExtraBeef";
    const char* little = "Beef";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    TEST_ASSERT_MSG(result == big + 15, result);    
    TEST_ASSERT(true);
}
void StrnstrTests::check_strnstr_match_after_end() {
    const char* big = "EatMoreBeef";
    const char* little = "Beef";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size - 1);
    TEST_ASSERT_MSG(result == NULL, result);
}
void StrnstrTests::check_strnstr_equal_but_size_too_small() {
    const char* big = "Bob123";
    const char* little = "Bob123";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size - 1);
    TEST_ASSERT_MSG(result == NULL, result);
}
