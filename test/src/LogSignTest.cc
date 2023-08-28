// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <iostream>

#include "Engine.h"
#include "TestUtilities.h"

#include "keymanagement.h"
#include "platform.h"
#include "log_sign.h"

#include <gtest/gtest.h>

namespace
{

    // The fixture for LogSignTest
    class LogSignTest : public ::testing::Test
    {
    public:
        Engine *engine;
        PEP_SESSION session;

    protected:
        // You can remove any or all of the following functions if its body
        // is empty.
        LogSignTest()
        {
            // You can do set-up work for each test here.
            test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
            test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
            test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
        }

        ~LogSignTest() override
        {
            // You can do clean-up work that doesn't throw exceptions here.
        }

        // If the constructor and destructor are not enough for setting up
        // and cleaning up each test, you can define the following methods:

        void SetUp() override
        {
            // Code here will be called immediately after the constructor (right
            // before each test).

            // Leave this empty if there are no files to copy to the home directory path
            std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

            // Get a new test Engine.
            engine = new Engine(test_path);
            ASSERT_NOTNULL(engine);

            // Ok, let's initialize test directories etc.
            engine->prep(NULL, NULL, NULL, init_files);

            // Ok, try to start this bugger.
            engine->start();
            ASSERT_NOTNULL(engine->session);
            session = engine->session;

            // Engine is up. Keep on truckin'
        }

        void TearDown() override
        {
            // Code here will be called immediately after each test (right
            // before the destructor).
            engine->shut_down();
            delete engine;
            engine = NULL;
            session = NULL;
        }

    private:
        const char *test_suite_name;
        const char *test_name;
        string test_path;
        // Objects declared here can be used by all tests in the LogSignTest suite.
    };

} // namespace

TEST_F(LogSignTest, roundtrip)
{
    char *signed_text = NULL;
    size_t signed_size = 0;

    PEP_STATUS status = log_sign(session, "", 0, &signed_text, &signed_size);
    EXPECT_EQ(status, PEP_CANNOT_FIND_IDENTITY); // no own identity yet

    pEp_identity *test_identity = new_identity("test1@example.com",
                                               NULL,
                                               "test1",
                                               "Test 1");
    ASSERT_NOTNULL(test_identity);
    myself(session, test_identity);
    ASSERT_NOTNULL(test_identity->fpr);

    const char *text_to_sign = "Some data to sign";
    const size_t text_to_sign_size = strlen(text_to_sign) + 1;
    status = log_sign(session, text_to_sign, text_to_sign_size, &signed_text, &signed_size);
    EXPECT_EQ(status, PEP_STATUS_OK);

    status = log_verify(session, text_to_sign, text_to_sign_size, signed_text, signed_size);
    EXPECT_EQ(status, PEP_VERIFIED);
}