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
    // Some data
    size_t signed_size = 0;
    char *signed_text = NULL;
    const char *text_to_sign1 = "Some data to sign";
    const size_t text_to_sign_size1 = strlen(text_to_sign1);

    // Most basic signing. Should work out of the box.
    PEP_STATUS status = log_sign(session, text_to_sign1, text_to_sign_size1, &signed_text, &signed_size);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // Verify.
    status = log_verify(session, text_to_sign1, text_to_sign_size1, signed_text, signed_size);
    ASSERT_EQ(status, PEP_VERIFIED);

    status = key_reset_all_own_keys_ignoring_device_group(session);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // Verify after all own keys have been reset (which should skip the identity used for signing).
    status = log_verify(session, text_to_sign1, text_to_sign_size1, signed_text, signed_size);
    ASSERT_EQ(status, PEP_VERIFIED);

    // Try to verify a different text that should not match the signature.
    const char *text_to_sign2 = "Other text, not signed";
    const size_t text_to_sign_size2 = strlen(text_to_sign2);
    status = log_verify(session, text_to_sign2, text_to_sign_size2, signed_text, signed_size);
    ASSERT_EQ(status, PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH);

    // Get the default user id.
    char *default_user_id = NULL;
    status = get_default_own_userid(session, &default_user_id);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // Try to directly reset the identity used for signing.
    pEp_identity *audit_ident = new_identity(SIGNING_IDENTITY_USER_ADDRESS, NULL, default_user_id, SIGNING_IDENTITY_USER_NAME);
    status = myself(session, audit_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = key_reset_identity(session, audit_ident, audit_ident->fpr);

    // And verify the signature again.
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = log_verify(session, text_to_sign1, text_to_sign_size1, signed_text, signed_size);
    ASSERT_EQ(status, PEP_VERIFIED);

    // No one should be able to list the signing identity as own identity.
    identity_list *all_own_identities;
    status = own_identities_retrieve(session, &all_own_identities);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(all_own_identities);
    ASSERT_NULL(all_own_identities->ident);
    ASSERT_NULL(all_own_identities->next);
}