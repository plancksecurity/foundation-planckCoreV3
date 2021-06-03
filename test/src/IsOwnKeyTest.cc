#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "TestUtilities.h"
#include "TestConstants.h"
#include "Engine.h"
#include "key_reset.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for IsOwnKeyTest
    class IsOwnKeyTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            IsOwnKeyTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~IsOwnKeyTest() override {
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
            // Objects declared here can be used by all tests in the IsOwnKeyTest suite.

    };

}  // namespace

/*
PEP_STATUS set_up_preset(PEP_SESSION session,
                         ident_preset preset_name,
                         bool set_ident,
                         bool set_pep,
                         bool trust,
                         bool set_own,
                         bool setup_private,
                         pEp_identity** ident) {
 */
TEST_F(IsOwnKeyTest, check_is_own_key_normal) {
    pEp_identity* alice = NULL;
    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::ALICE, true, true, true, true, true, true, &alice);
    ASSERT_OK;
    bool is_own = false;
    status = is_own_key(session, alice->fpr, &is_own);
    ASSERT_OK;
    ASSERT_TRUE(is_own);
}

TEST_F(IsOwnKeyTest, check_is_own_key_OpenPGP) {    
}

TEST_F(IsOwnKeyTest, check_is_own_key_external_revoked) {
    pEp_identity* alice = NULL;
    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::ALICE, true, true, true, true, true, true, &alice);
    ASSERT_OK;
    bool is_own = false;
    status = is_own_key(session, alice->fpr, &is_own);
    ASSERT_OK;
    ASSERT_TRUE(is_own);
    status = revoke_key(session, alice->fpr, "Because I wanna");
    ASSERT_OK;
    is_own = false;
    status = is_own_key(session, alice->fpr, &is_own);
    ASSERT_OK;
    ASSERT_TRUE(is_own); // Probably not wanted
}

TEST_F(IsOwnKeyTest, check_is_own_key_external_marked_revoked) {
    pEp_identity* alice = NULL;
    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::ALICE, true, true, true, true, true, true, &alice);
    ASSERT_OK;
    bool is_own = false;
    status = is_own_key(session, alice->fpr, &is_own);
    ASSERT_OK;
    ASSERT_TRUE(is_own);
    char* alicefpr = strdup(alice->fpr);
    status = revoke_key(session, alice->fpr, "Because I wanna");
    ASSERT_OK;
    if (alice->fpr == NULL) {
        alice->fpr = alicefpr;
    }
    alice->comm_type = PEP_ct_key_revoked;
    status = set_identity(session, alice);
    ASSERT_OK;
    is_own = false;
    status = is_own_key(session, alice->fpr, &is_own);
    ASSERT_OK;
    ASSERT_FALSE(is_own);        
}

TEST_F(IsOwnKeyTest, check_is_own_key_revoked_through_reset) { // Probably mistrusted case...
    pEp_identity* alice = NULL;
    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::ALICE, true, true, true, true, true, true, &alice);
    ASSERT_OK;
    bool is_own = false;
    status = is_own_key(session, alice->fpr, &is_own);
    ASSERT_OK;
    ASSERT_TRUE(is_own);
    status = key_reset_identity(session, alice, alice->fpr);
    ASSERT_OK;
    is_own = false;
    status = is_own_key(session, alice->fpr, &is_own);
    ASSERT_OK;
    ASSERT_FALSE(is_own);        
}

TEST_F(IsOwnKeyTest, check_is_own_key_mistrusted) {
    pEp_identity* alice = NULL;
    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::ALICE, true, true, true, true, true, true, &alice);
    ASSERT_OK;
    bool is_own = false;
    status = is_own_key(session, alice->fpr, &is_own);
    ASSERT_OK;
    ASSERT_TRUE(is_own);
    const char* alicefpr = strdup(alice->fpr);
    status = key_mistrusted(session, alice);
    ASSERT_OK;
    is_own = false;
    status = is_own_key(session, alicefpr, &is_own);
    ASSERT_OK;
    ASSERT_FALSE(is_own);            
}

TEST_F(IsOwnKeyTest, check_is_own_key_expired) {
    const char* testy_fpr = "D1AEA592B78BEF2BE8D93C78DD835B271075DA7E";
    bool imported = slurp_and_import_key(session, "test_keys/testy_expired.pgp");
    pEp_identity* testy = new_identity("testy@darthmama.org", testy_fpr, PEP_OWN_USERID, "Testy McExpiredson");
    testy->comm_type = PEP_ct_key_expired_but_confirmed;
    PEP_STATUS status = set_identity(session, testy);
    ASSERT_OK;
    bool is_own = false;
    status = is_own_key(session, testy_fpr, &is_own);
    ASSERT_OK;
    ASSERT_FALSE(is_own);        
}

TEST_F(IsOwnKeyTest, check_is_key_someone_elses_pubkey) {
    pEp_identity* alice = NULL;
    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::ALICE, true, true, true, true, true, true, &alice);
    ASSERT_OK;

    // Dave == NOT OWN
    pEp_identity* dave = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::DAVE, true, true, true, true, false, false, &dave);
    // import the private part also
    const char* dave_fpr = "E8AC9779A2D13A15D8D55C84B049F489BB5BCCF6";

    bool is_own = false;
    status = is_own_key(session, dave_fpr, &is_own);
    ASSERT_OK;
    ASSERT_FALSE(is_own);                
}

TEST_F(IsOwnKeyTest, check_is_non_own_priv_key) {
    pEp_identity* alice = NULL;
    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::ALICE, true, true, true, true, true, true, &alice);
    ASSERT_OK;

    // Dave == NOT OWN
    pEp_identity* dave = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::DAVE, true, true, true, true, false, false, &dave);
    // import the private part also
    bool imported = slurp_and_import_key(session, "test_keys/priv/pep-test-dave-0xBB5BCCF6_priv.asc");
    ASSERT_TRUE(imported);
    const char* dave_fpr = "E8AC9779A2D13A15D8D55C84B049F489BB5BCCF6";

    bool is_own = false;
    status = is_own_key(session, dave_fpr, &is_own);
    ASSERT_OK;
    ASSERT_FALSE(is_own);            
}
