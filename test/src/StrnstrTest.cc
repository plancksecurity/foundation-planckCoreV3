// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include "TestUtilities.h"
#include "TestConstants.h"
    
#include "pEpEngine.h"
#include "pEp_internal.h"
#include "platform_unix.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for StrnstrTest
    class StrnstrTest : public ::testing::Test { };

}  // namespace


TEST_F(StrnstrTest, check_strnstr_equal) {
    const char* big = "Bob123";
    const char* little = "Bob123";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    ASSERT_EQ(result , big);
}

TEST_F(StrnstrTest, check_strnstr_first_empty) {
    const char* big = "";
    const char* little = "Bob123";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    ASSERT_NULL(result );
}
TEST_F(StrnstrTest, check_strnstr_second_empty) {
    const char* big = "YerMama";
    const char* little = "";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    ASSERT_EQ(result , big);
}

TEST_F(StrnstrTest, check_strnstr_both_empty) {
    const char* big = "";
    const char* little = "";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    ASSERT_EQ(result , big);
}

TEST_F(StrnstrTest, check_strnstr_first_letter_only) {
    const char* big = "Bob123";
    const char* little = "Beef";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    ASSERT_NULL(result );
}
TEST_F(StrnstrTest, check_strnstr_first_two_only) {
    const char* big = "Bob123";
    const char* little = "Boof";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    ASSERT_NULL(result );
}
TEST_F(StrnstrTest, check_strnstr_all_but_last) {
    const char* big = "BeesBeesBees";
    const char* little = "Beef";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    ASSERT_NULL(result );
}
TEST_F(StrnstrTest, check_strnstr_same_len_all_but_last) {
    const char* big = "Bees";
    const char* little = "Beef";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    ASSERT_NULL(result );
}
TEST_F(StrnstrTest, check_strnstr_same_len_none) {
    const char* big = "1234";
    const char* little = "Beef";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    ASSERT_NULL(result );
}
TEST_F(StrnstrTest, check_strnstr_same_big_smaller) {
    const char* big = "Bee";
    const char* little = "Bees";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    ASSERT_NULL(result );
}
TEST_F(StrnstrTest, check_strnstr_shift_one_no_match) {
    const char* big = "1Bee";
    const char* little = "Bees";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    ASSERT_NULL(result );
}
TEST_F(StrnstrTest, check_strnstr_shift_to_end) {
    const char* big = "BigBeeWithExtraBeef";
    const char* little = "Beef";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size);
    ASSERT_EQ(result , big + 15);
}
TEST_F(StrnstrTest, check_strnstr_match_after_end) {
    const char* big = "EatMoreBeef";
    const char* little = "Beef";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size - 1);
    ASSERT_NULL(result );
}
TEST_F(StrnstrTest, check_strnstr_equal_but_size_too_small) {
    const char* big = "Bob123";
    const char* little = "Bob123";
    size_t size = strlen(big);
    const char* result = strnstr(big, little, size - 1);
    ASSERT_NULL(result );
}
