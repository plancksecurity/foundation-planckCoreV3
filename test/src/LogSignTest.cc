// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <iostream>

#include <gtest/gtest.h>

#include "Engine.h"
#include "TestUtilities.h"

#include "keymanagement.h"
#include "platform.h"
#include "key_reset.h"

#include "log_sign.h"

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

    // Own identity data
    const char *user_address = "test1@example.com";
    const char *user_id = "test1";
    const char *user_name = "Test 1";

    // First own identity with which we will sign and verify
    pEp_identity *test_identity = new_identity(user_address,
                                               NULL,
                                               user_id,
                                               user_name);
    ASSERT_NOTNULL(test_identity);
    myself(session, test_identity);
    ASSERT_NOTNULL(test_identity->fpr);

    const char *fpr1 = strdup(test_identity->fpr);

    const char *text_to_sign1 = "Some data to sign";
    const size_t text_to_sign_size1 = strlen(text_to_sign1);
    status = log_sign(session, text_to_sign1, text_to_sign_size1, &signed_text, &signed_size);
    EXPECT_EQ(status, PEP_STATUS_OK);
    EXPECT_EQ(strlen(signed_text), signed_size);

    status = log_verify(session, text_to_sign1, text_to_sign_size1, signed_text, signed_size);
    EXPECT_EQ(status, PEP_VERIFIED);

    // Reset our keys, so our own identity #2 will have a different one,
    // but the old one should still be availabe for verifying.
    status = key_reset_all_own_keys_ignoring_device_group(session);
    EXPECT_EQ(status, PEP_STATUS_OK);

    pEp_identity *test_identity2 = new_identity(user_address,
                                               NULL,
                                               user_id,
                                               user_name);
    ASSERT_NOTNULL(test_identity2);
    myself(session, test_identity2);
    ASSERT_NOTNULL(test_identity2->fpr);

    ASSERT_STRNE(fpr1, test_identity2->fpr);

    free((void *) fpr1);

    // Note that the key we originally used to sign this has been reset, that is
    // exchanged with a new own key. Still, verification should work forever.
    // But note the changed status.
    status = log_verify(session, text_to_sign1, text_to_sign_size1, signed_text, signed_size);
    EXPECT_EQ(status, PEP_VERIFY_SIGNER_KEY_REVOKED);

    // Try to verify a different text that should not match the signature.
    const char *text_to_sign2 = "Other text, not signed";
    const size_t text_to_sign_size2 = strlen(text_to_sign2);
    status = log_verify(session, text_to_sign2, text_to_sign_size2, signed_text, signed_size);

    // This is bad, and makes it unusable.
    EXPECT_EQ(status, PEP_VERIFY_SIGNER_KEY_REVOKED);
}