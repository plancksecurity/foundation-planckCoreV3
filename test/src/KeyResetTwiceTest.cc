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
#include "key_reset.h"
#include "test_util.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for KeyResetTwiceTest
    class KeyResetTwiceTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            KeyResetTwiceTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~KeyResetTwiceTest() override {
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
            // Objects declared here can be used by all tests in the KeyResetTwiceTest suite.

    };

}  // namespace

enum kind_of_reset {
    key_reset_identity_kind,
    key_reset_all_own_identities_kind
};
static void work(PEP_SESSION session, bool own, kind_of_reset kind,
                 bool update_after_each_reset) {
    std::string userid = PEP_OWN_USERID;
    std::string user_name = "Gabrielle";
    const char *key
        = (own
           ? "test_keys/priv/pep-test-gabrielle-0xE203586C_priv.asc"
           : "test_keys/pub/pep-test-gabrielle-0xE203586C_pub.asc");
    pEp_identity *identity = NULL;
    PEP_STATUS status
        = set_up_ident_from_scratch(session, key,
                                    "pep-test-gabrielle@pep-project.org", NULL,
                                    userid.c_str(),
                                    user_name.c_str(), & identity, own);
    ASSERT_EQ(status, PEP_STATUS_OK);
    if (own)
        status = myself(session, identity);
    else
        status = update_identity(session, identity);
    ASSERT_EQ(status, PEP_STATUS_OK);

    PEP_STATUS expected_statuses[] = { PEP_STATUS_OK, PEP_STATUS_OK };
    if (! own)
        expected_statuses [1] = PEP_KEY_NOT_FOUND;
    for (int i = 0; i < 2; i ++) {
        status = key_reset_identity(session, identity, NULL);
        ASSERT_EQ(status, expected_statuses [i]);

        status = PEP_STATUS_OK;
        if (update_after_each_reset) {
            if (own)
                status = myself(session, identity);
            else
                status = update_identity(session, identity);
            ASSERT_EQ(status, PEP_STATUS_OK);
        }
    }
    free_identity(identity);
}

TEST_F(KeyResetTwiceTest, key_reset_twice_own) {
    work(session, true, key_reset_identity_kind, false);
}
TEST_F(KeyResetTwiceTest, key_reset_and_myself_twice_own) {
    work(session, true, key_reset_identity_kind, true);
}
TEST_F(KeyResetTwiceTest, key_reset_all_own_keys_twice_own) {
    work(session, true, key_reset_all_own_identities_kind, false);
}
TEST_F(KeyResetTwiceTest, key_reset_all_own_keys_and_myself_twice_own) {
    work(session, true, key_reset_all_own_identities_kind, true);
}

TEST_F(KeyResetTwiceTest, key_reset_twice_nonown) {
    work(session, false, key_reset_identity_kind, false);
}
TEST_F(KeyResetTwiceTest, key_reset_and_update_twice_nonown) {
    work(session, false, key_reset_identity_kind, true);
}
