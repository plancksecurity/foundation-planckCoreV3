#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEpEngine_internal.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for TestSetDefaultFPRTest
    class TestSetDefaultFPRTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;
            const char* carol_fpr = "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42";
            const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
            const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            TestSetDefaultFPRTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~TestSetDefaultFPRTest() override {
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
                slurp_and_import_key(session, "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc");
                slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
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
    };

}  // namespace


TEST_F(TestSetDefaultFPRTest, check_test_set_default_fpr) {
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL,
                                      true, false, true, false, false, false, &carol);
    ASSERT_EQ(carol->fpr, nullptr);
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_EQ(carol->fpr, nullptr);
    status = set_default_identity_fpr(session, carol->user_id, carol->address, carol_fpr);
    ASSERT_OK;
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_STREQ(carol->fpr, carol_fpr);
    status = set_default_identity_fpr(session, carol->user_id, carol->address, bob_fpr);
    ASSERT_OK;
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_STREQ(carol->fpr, bob_fpr);
    // Now let's set one that we don't have.
    status = set_default_identity_fpr(session, carol->user_id, carol->address, alice_fpr);
    ASSERT_OK;
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_STREQ(carol->fpr, carol_fpr); // Should be the user default, we don't have alice_fpr's key
    ASSERT_EQ(carol->comm_type, PEP_ct_pEp_unconfirmed);
    free_identity(carol);
}

TEST_F(TestSetDefaultFPRTest, check_test_set_comm_partner_key) {
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL,
                                       true, false, true, false, false, false, &carol);
    status = set_comm_partner_key(session, carol, carol_fpr);
    ASSERT_OK;
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_STREQ(carol->fpr, carol_fpr);
    status = set_comm_partner_key(session, carol, bob_fpr);
    ASSERT_OK;
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_STREQ(carol->fpr, bob_fpr);
    // Now let's set one that we don't have.
    status = set_comm_partner_key(session, carol, alice_fpr);
    ASSERT_OK;
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_STREQ(carol->fpr, carol_fpr); // Should be the user default, we don't have alice_fpr's key
    ASSERT_EQ(carol->comm_type, PEP_ct_pEp_unconfirmed);
    free_identity(carol);
}

TEST_F(TestSetDefaultFPRTest, check_test_set_default_no_identity) {
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL,
                                      true, false, true, false, false, false, &carol);
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_EQ(carol->fpr, nullptr);
    status = set_default_identity_fpr(session, carol->user_id, carol->address, carol_fpr);
    ASSERT_OK;
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_STREQ(carol->fpr, carol_fpr);

    pEp_identity* carol_bob = new_identity(carol->address, NULL, "BOB", "Carol is Bob, but not really");
    status = set_default_identity_fpr(session, carol_bob->user_id, carol_bob->address, carol_fpr);
    ASSERT_OK;
    status = update_identity(session, carol_bob);
    ASSERT_OK;
    ASSERT_EQ(carol_bob->fpr, nullptr);
    status = set_default_identity_fpr(session, carol_bob->user_id, carol_bob->address, carol_fpr);
    ASSERT_OK;
    status = update_identity(session, carol_bob);
    ASSERT_OK;
    ASSERT_STREQ(carol_bob->fpr, carol_fpr);
    free_identity(carol);
    free_identity(carol_bob);
}

TEST_F(TestSetDefaultFPRTest, check_test_set_comm_partner_key_no_set_identity) {
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL,
                                      false, false, false, false, false, false, &carol);
    string user_id_cache = carol->user_id;
    status = set_comm_partner_key(session, carol, carol_fpr);
    ASSERT_OK;
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_STREQ(carol->fpr, carol_fpr);
    ASSERT_STREQ(user_id_cache.c_str(), carol->user_id);
    status = set_comm_partner_key(session, carol, bob_fpr);
    ASSERT_OK;
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_STREQ(carol->fpr, bob_fpr);
    // Now let's set one that we don't have.
    status = set_comm_partner_key(session, carol, alice_fpr);
    ASSERT_OK;
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_STREQ(carol->fpr, carol_fpr); // Should be the user default, we don't have alice_fpr's key
    ASSERT_EQ(carol->comm_type, PEP_ct_OpenPGP_unconfirmed);

    pEp_identity* carol_bob = new_identity(carol->address, NULL, "BOB", "Carol is Bob, but not really");
    status = set_comm_partner_key(session, carol_bob, carol_fpr);
    ASSERT_OK;
    status = update_identity(session, carol_bob);
    ASSERT_OK;
    ASSERT_STREQ(carol_bob->fpr, carol_fpr); // differs from above case because of internal update_identity call
    free_identity(carol);
    free_identity(carol_bob);
}
