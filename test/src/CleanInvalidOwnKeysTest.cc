#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for CleanInvalidOwnKeysTest
    class CleanInvalidOwnKeysTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            CleanInvalidOwnKeysTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~CleanInvalidOwnKeysTest() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();
                string keyfile = string("test_files/ENGINE-750_") + test_name + "_keys.db";
                string mgmtfile = string("test_files/ENGINE-750_") + test_name + "_mgmt.db";
                init_files.push_back(std::pair<std::string, std::string>(keyfile, std::string("keys.db")));                
                init_files.push_back(std::pair<std::string, std::string>(mgmtfile, std::string("management.db")));
                
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
            // Objects declared here can be used by all tests in the CleanInvalidOwnKeysTest suite.

    };

}  // namespace


TEST_F(CleanInvalidOwnKeysTest, check_clean_invalid_own_keys_no_alts_revoked) {
    PEP_STATUS status = clean_own_key_defaults(session);
    ASSERT_EQ(status, PEP_STATUS_OK);    

    pEp_identity* alice = NULL;
    status = get_identity(session, "pep.test.alice@pep-project.org", "ALICE", &alice);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(alice->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    char* fpr = NULL;
    status = get_user_default_key(session, "ALICE", &fpr);
    ASSERT_STREQ(fpr, alice->fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);    
}

TEST_F(CleanInvalidOwnKeysTest, check_clean_invalid_own_keys_no_alts_mistrusted) {
    PEP_STATUS status = clean_own_key_defaults(session);
    ASSERT_EQ(status, PEP_STATUS_OK);    

    pEp_identity* alice = NULL;
    status = get_identity(session, "pep.test.alice@pep-project.org", "ALICE", &alice);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(alice->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    char* fpr = NULL;
    status = get_user_default_key(session, "ALICE", &fpr);
    ASSERT_STREQ(fpr, alice->fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);    
}

TEST_F(CleanInvalidOwnKeysTest, check_clean_invalid_own_keys_no_alts_expired) {
    PEP_STATUS status = clean_own_key_defaults(session);
    ASSERT_EQ(status, PEP_STATUS_OK);    

    pEp_identity* bob = NULL;
    status = get_identity(session, "expired_bob_0@darthmama.org", "BOB", &bob);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(bob->fpr, "E4A8CD51C25D0ED5BAD0834BD2FDE305A35FE3F5");
    char* fpr = NULL;
    status = get_user_default_key(session, "BOB", &fpr);
    ASSERT_STREQ(fpr, "E4A8CD51C25D0ED5BAD0834BD2FDE305A35FE3F5");
    ASSERT_EQ(status, PEP_STATUS_OK);    
    bool expired = true;
    status = key_expired(session, bob->fpr, time(NULL), &expired);
    ASSERT_FALSE(expired);
}
