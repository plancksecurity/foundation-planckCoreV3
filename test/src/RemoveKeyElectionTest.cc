#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "TestUtilities.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for RemoveKeyElectionTest
    class RemoveKeyElectionTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            RemoveKeyElectionTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~RemoveKeyElectionTest() override {
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

            const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
            const char* alice_key_filename = "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc";
            const char* alice_addr = "pep.test.alice@pep-project.org";
            const char* alice_TOFU = "TOFU_pep.test.alice@pep-project.org";
            const char* alice_name = "Alice";
            const char* alice_userid = "ALICE";

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the RemoveKeyElectionTest suite.

    };

}  // namespace

// These tests will seem a little weird, but they exercise the update_identity paths corresponding to the
// Volker (tm) algorithm
TEST_F(RemoveKeyElectionTest, check_remove_key_election_simple_unstored_not_found) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_key_filename));
    pEp_identity* alice = new_identity(alice_addr, NULL, alice_userid, alice_name);

    PEP_STATUS status = update_identity(session, alice);
    ASSERT_OK;
    ASSERT_NULL(alice->fpr);
    ASSERT_EQ(alice->comm_type, PEP_ct_key_not_found); // This is desired. The DB, however, must have "unknown"
}

TEST_F(RemoveKeyElectionTest, check_remove_key_election_simple_stored_not_found) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_key_filename));
    pEp_identity* alice = new_identity(alice_addr, NULL, alice_userid, alice_name);
    PEP_STATUS status = set_identity(session, alice);
    ASSERT_OK;

    status = update_identity(session, alice);
    ASSERT_OK;
    ASSERT_NULL(alice->fpr);
    ASSERT_EQ(alice->comm_type, PEP_ct_key_not_found); // This is desired. The DB, however, must have "unknown"
}

TEST_F(RemoveKeyElectionTest, check_remove_key_election_simple_stored_found) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_key_filename));
    pEp_identity* alice = new_identity(alice_addr, alice_fpr, alice_userid, alice_name);
    PEP_STATUS status = set_identity(session, alice);
    ASSERT_OK;

    free(alice->fpr);
    alice->fpr = NULL;

    status = update_identity(session, alice);
    ASSERT_OK;
    ASSERT_NOTNULL(alice->fpr);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    ASSERT_EQ(alice->comm_type, PEP_ct_OpenPGP_unconfirmed);
}

TEST_F(RemoveKeyElectionTest, check_remove_key_election_simple_stored_found_no_input_username) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_key_filename));
    pEp_identity* alice = new_identity(alice_addr, alice_fpr, alice_userid, alice_name);
    PEP_STATUS status = set_identity(session, alice);
    ASSERT_OK;

    free(alice->fpr);
    alice->fpr = NULL;
    free(alice->username);
    alice->username = NULL;

    status = update_identity(session, alice);
    ASSERT_OK;
    ASSERT_NOTNULL(alice->fpr);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    ASSERT_EQ(alice->comm_type, PEP_ct_OpenPGP_unconfirmed);
    ASSERT_STREQ(alice_name, alice->username);
}

TEST_F(RemoveKeyElectionTest, check_remove_key_election_simple_stored_found_stored_temp_username) {
    PEP_STATUS status = PEP_STATUS_OK;
    ASSERT_TRUE(slurp_and_import_key(session, alice_key_filename));
    pEp_identity* alice = new_identity(alice_addr, NULL, alice_userid, NULL);
    status = update_identity(session, alice);
    ASSERT_OK;
    ASSERT_STREQ(alice->username, alice_addr);
    pEp_identity* alice2 = NULL;
    status = get_identity(session, alice_addr, alice_userid, &alice2);
    ASSERT_OK;
    ASSERT_STREQ(alice2->username, alice_addr);
    alice2->fpr = strdup(alice_fpr);
    status = set_identity(session, alice2);
    ASSERT_OK;

    free(alice->fpr);
    alice->fpr = NULL;
    free(alice->username);
    alice->username = strdup(alice_name);

    status = update_identity(session, alice);
    ASSERT_OK;
    ASSERT_NOTNULL(alice->fpr);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    ASSERT_EQ(alice->comm_type, PEP_ct_OpenPGP_unconfirmed);
    ASSERT_STREQ(alice_name, alice->username);
    free_identity(alice2);
    alice2 = NULL;
    status = get_identity(session, alice_addr, alice_userid, &alice2);
    ASSERT_OK;
    ASSERT_STREQ(alice->username, alice_name);
}

TEST_F(RemoveKeyElectionTest, check_remove_key_election_simple_stored_found_no_userid) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_key_filename));
    pEp_identity* alice = new_identity(alice_addr, alice_fpr, alice_userid, alice_name);
    PEP_STATUS status = set_identity(session, alice);
    ASSERT_OK;

    free(alice->fpr);
    alice->fpr = NULL;
    free(alice->user_id);
    alice->user_id = NULL;

    status = update_identity(session, alice);
    ASSERT_OK;
    ASSERT_NOTNULL(alice->fpr);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    ASSERT_EQ(alice->comm_type, PEP_ct_OpenPGP_unconfirmed);
}

TEST_F(RemoveKeyElectionTest, check_remove_key_election_simple_stored_found_no_userid_no_uname) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_key_filename));
    pEp_identity* alice = new_identity(alice_addr, alice_fpr, alice_userid, alice_name);
    PEP_STATUS status = set_identity(session, alice);
    ASSERT_OK;

    free(alice->fpr);
    alice->fpr = NULL;
    free(alice->user_id);
    alice->user_id = NULL;
    free(alice->username);
    alice->username = NULL;
    
    status = update_identity(session, alice);
    ASSERT_OK;
    ASSERT_NOTNULL(alice->fpr);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    ASSERT_EQ(alice->comm_type, PEP_ct_OpenPGP_unconfirmed);
}

TEST_F(RemoveKeyElectionTest, check_remove_key_election_simple_stored_found_stored_TOFU_input_TOFU_names_match) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_key_filename));
    pEp_identity* alice = new_identity(alice_addr, alice_fpr, alice_TOFU, alice_name);
    PEP_STATUS status = set_identity(session, alice);
    ASSERT_OK;

    free(alice->fpr);
    alice->fpr = NULL;

    status = update_identity(session, alice);
    ASSERT_OK;
    ASSERT_NOTNULL(alice->fpr);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    ASSERT_EQ(alice->comm_type, PEP_ct_OpenPGP_unconfirmed);
}

TEST_F(RemoveKeyElectionTest, check_remove_key_election_simple_stored_found_stored_TOFU_input_TOFU_names_no_match) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_key_filename));
    pEp_identity* alice = new_identity(alice_addr, alice_fpr, alice_TOFU, alice_name);
    PEP_STATUS status = set_identity(session, alice);
    ASSERT_OK;

    free(alice->fpr);
    alice->fpr = NULL;
    free(alice->username);
    alice->username = strdup("Cheese");

    status = update_identity(session, alice);
    ASSERT_OK;
    ASSERT_NOTNULL(alice->fpr);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    ASSERT_EQ(alice->comm_type, PEP_ct_OpenPGP_unconfirmed);
}

TEST_F(RemoveKeyElectionTest, check_remove_key_election_simple_stored_found_stored_TOFU_input_no_userid_names_no_match) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_key_filename));
    pEp_identity* alice = new_identity(alice_addr, alice_fpr, alice_TOFU, alice_name);
    PEP_STATUS status = set_identity(session, alice);
    ASSERT_OK;

    free(alice->fpr);
    alice->fpr = NULL;
    free(alice->user_id);
    alice->user_id = NULL;
    free(alice->username);
    alice->username = strdup("Cheese");
    
    status = update_identity(session, alice);
    ASSERT_OK;
    ASSERT_NOTNULL(alice->fpr);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    ASSERT_EQ(alice->comm_type, PEP_ct_OpenPGP_unconfirmed);
    ASSERT_STREQ(alice->username, "Cheese");
    pEp_identity* alice2 = NULL;
    status = get_identity(session, alice_addr, alice_TOFU, &alice2);
    ASSERT_OK;
    ASSERT_STREQ(alice2->username, alice_name);
    ASSERT_STREQ(alice2->fpr, alice_fpr);
}