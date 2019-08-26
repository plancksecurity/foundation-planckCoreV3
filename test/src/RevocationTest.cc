// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring> // for strcmp()
#include "TestConstants.h"

#include "pEpEngine.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for RevocationTest
    class RevocationTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            RevocationTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~RevocationTest() override {
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
            // Objects declared here can be used by all tests in the RevocationTest suite.

    };

}  // namespace


TEST_F(RevocationTest, check_revocation) {
    // I have no idea how this should behave outside of Sequoia. Neal, please fix.
#ifdef USE_SEQUOIA
    // Read the key.
    const string key = slurp("test_keys/priv/pep-test-linda-0xDCD555B6055ADE22_priv.asc");

    PEP_STATUS status = import_key(session, key.c_str(), key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);

    pEp_identity* pre = new_identity("linda@example.org", NULL, NULL, NULL);
    status = update_identity(session, pre);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(pre->comm_type , PEP_ct_OpenPGP_unconfirmed);

    // Read in the revocation certificate.
    const string rev = slurp("test_keys/priv/pep-test-linda-0xDCD555B6055ADE22.rev");

    status = import_key(session, rev.c_str(), rev.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);

    pEp_identity* post = new_identity("linda@example.org", NULL, NULL, NULL);

//    string save_fpr = post->fpr;

    stringlist_t* keylist = NULL;

    status = find_keys(session, "linda@example.org", &keylist);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = update_identity(session, post);
    // PEP_KEY_UNSUITABLE => revoked (or something similar).
    ASSERT_EQ(status , PEP_KEY_UNSUITABLE);
    ASSERT_EQ(post->comm_type , PEP_ct_key_not_found);
    free(post->fpr);
    post->fpr = strdup(keylist->value);
    status = get_trust(session, post);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(post->comm_type , PEP_ct_key_revoked);
    free_identity(pre);
    free_identity(post);
    free_stringlist(keylist);
#endif
}
