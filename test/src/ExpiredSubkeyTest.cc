// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include "test_util.h"

#include "pEpEngine.h"
#include "pEp_internal.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for ExpiredSubkeyTest
    class ExpiredSubkeyTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            ExpiredSubkeyTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~ExpiredSubkeyTest() override {
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
                engine->prep(NULL, NULL, NULL, init_files);

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
            // Objects declared here can be used by all tests in the ExpiredSubkeyTest suite.

    };

}  // namespace


TEST_F(ExpiredSubkeyTest, check_expired_subkey_with_valid_subkeys_and_main_key) {
    slurp_and_import_key(session,"test_keys/pub/eb_0_valid_pub.asc");
    pEp_identity* expired_0 = new_identity("expired_in_bits_0@darthmama.org",
                                           NULL, NULL, "Expired 0");
    PEP_STATUS status = _update_identity(session, expired_0, true);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(expired_0->fpr, nullptr);
    PEP_rating rating;
    status = identity_rating(session, expired_0, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating , PEP_rating_reliable);
}

TEST_F(ExpiredSubkeyTest, check_expired_subkey_with_valid_subkeys_expired_main) {
    slurp_and_import_key(session,"test_keys/pub/master_key_test_sign_and_encrypt_added.asc");
    pEp_identity* expired_0 = new_identity("master_key_test@darthmama.org",
                                           NULL, NULL, "Master Key Test");
    PEP_STATUS status = _update_identity(session, expired_0, true);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(expired_0->fpr, nullptr);
    PEP_rating rating;
    status = identity_rating(session, expired_0, &rating);
    ASSERT_EQ(status , PEP_KEY_UNSUITABLE);
    ASSERT_EQ(rating , PEP_rating_undefined);
}

TEST_F(ExpiredSubkeyTest, check_all_valid_with_leftover_expired_subkeys) {
    slurp_and_import_key(session,"test_keys/pub/master_key_test_certify_extended_pub.asc");
    pEp_identity* expired_0 = new_identity("master_key_test@darthmama.org",
                                           NULL, NULL, "Master Key Test");
    PEP_STATUS status = _update_identity(session, expired_0, true);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(expired_0->fpr, nullptr);
    PEP_rating rating;
    status = identity_rating(session, expired_0, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating , PEP_rating_reliable);
}

TEST_F(ExpiredSubkeyTest, check_no_valid_encryption_subkey) {
    slurp_and_import_key(session,"test_keys/pub/master_key_test_deleted_valid_enc_key_pub.asc");
    pEp_identity* expired_0 = new_identity("master_key_test@darthmama.org",
                                           NULL, NULL, "Master Key Test");
    PEP_STATUS status = _update_identity(session, expired_0, true);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(expired_0->fpr, nullptr);
    PEP_rating rating;
    status = identity_rating(session, expired_0, &rating);
    ASSERT_EQ(status , PEP_KEY_UNSUITABLE);
    ASSERT_EQ(rating , PEP_rating_undefined);
}
