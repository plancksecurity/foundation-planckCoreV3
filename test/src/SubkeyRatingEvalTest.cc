// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "test_util.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for SubkeyRatingEvalTest
    class SubkeyRatingEvalTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            SubkeyRatingEvalTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~SubkeyRatingEvalTest() override {
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

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the SubkeyRatingEvalTest suite.

    };

}  // namespace


// pub   rsa2048 2019-01-21 [CA]
//       F0D03C842C0770C2C2A9FEAF2A1ED9814929DC45
// uid           [ unknown] Subkey Check 0 <subkey_select_0@darthmama.cool>
//
TEST_F(SubkeyRatingEvalTest, check_subkey_rating_eval_no_es) {
    slurp_and_import_key(session, "test_keys/pub/subkey_select_0-0x4929DC45_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "F0D03C842C0770C2C2A9FEAF2A1ED9814929DC45", &ct);
    ASSERT_OK;
    bool expired = false;
    status = key_expired(session, "F0D03C842C0770C2C2A9FEAF2A1ED9814929DC45", time(NULL), &expired);
    ASSERT_FALSE(expired);
    ASSERT_EQ(ct , PEP_ct_key_b0rken);
}

// pub   rsa2048 2019-01-21 [CEA]
//       918AF6E986F39B630541E10DF5F7FA35F2BFF59E
// uid           [ unknown] Subkey Check 1 <subkey_select_1@darthmama.cool>
// sub   rsa1024 2019-01-21 [S]
//
TEST_F(SubkeyRatingEvalTest, check_subkey_rating_eval_weak_s) {
    slurp_and_import_key(session, "test_keys/pub/subkey_select_1-0xF2BFF59E_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "918AF6E986F39B630541E10DF5F7FA35F2BFF59E", &ct);
    ASSERT_OK;
    ASSERT_EQ(ct , PEP_ct_OpenPGP_weak_unconfirmed);
}

// pub   rsa2048 2019-01-21 [CEA]
//       8894202E3D791C95560058BD77676BACBAD7800C
// uid           [ unknown] Subkey Check 2 <subkey_select_2@darthmama.cool>
// sub   ed25519 2019-01-21 [S]
//
TEST_F(SubkeyRatingEvalTest, check_subkey_rating_eval_ecc_s) {
    slurp_and_import_key(session, "test_keys/pub/subkey_select_2-0xBAD7800C_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "8894202E3D791C95560058BD77676BACBAD7800C", &ct);
    ASSERT_OK;
    ASSERT_EQ(ct , PEP_ct_OpenPGP_unconfirmed);
}

// pub   rsa2048 2019-01-21 [CA]
//       5EA5F7F71BB39B4F7924D1E8D11C676134F44C02
// uid           [ unknown] Subkey Check 3 <subkey_select_3@darthmama.cool>
// sub   ed25519 2019-01-21 [S]
// sub   cv25519 2019-01-21 [E]
// sub   rsa1024 2019-01-21 [E]
//
TEST_F(SubkeyRatingEvalTest, check_subkey_rating_eval_weak_e_strong_ecc_se) {
    slurp_and_import_key(session, "test_keys/pub/subkey_select_3-0x34F44C02_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "5EA5F7F71BB39B4F7924D1E8D11C676134F44C02", &ct);
    ASSERT_OK;
    ASSERT_EQ(ct , PEP_ct_OpenPGP_weak_unconfirmed);
}

// pub   rsa512 2019-01-22 [SC]
//       70376BC88DE2DAB4BEF831B65FD6F65326F88D0B
// uid           [ unknown] Weak RSA Key <crappykey_0@darthmama.cool>
// sub   rsa512 2019-01-22 [E]
//
TEST_F(SubkeyRatingEvalTest, check_subkey_rating_eval_bad_es) {
    slurp_and_import_key(session, "test_keys/pub/crappykey_0-26F88D0B_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "70376BC88DE2DAB4BEF831B65FD6F65326F88D0B", &ct);
    ASSERT_OK;
    ASSERT_EQ(ct , PEP_ct_key_too_short);
}

// pub   rsa512 2019-01-22 [C]
//       F712B88AF525E4E32A2A24BCD1B86137C508F2B1
// uid           [ unknown] Weak RSA Key <crappykey_1@darthmama.cool>
// sub   rsa512 2019-01-22 [E]
// sub   rsa2048 2019-01-22 [S]
//
TEST_F(SubkeyRatingEvalTest, check_subkey_rating_eval_bad_e) {
    slurp_and_import_key(session, "test_keys/pub/crappykey_1-0xC508F2B1_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "F712B88AF525E4E32A2A24BCD1B86137C508F2B1", &ct);
    ASSERT_OK;
    ASSERT_EQ(ct , PEP_ct_key_too_short);
}

// pub   rsa512 2019-01-22 [SC]
//       18544492055207B2936BB215325776FBC027262F
// uid           [ unknown] Weak RSA Key <crappykey_2@darthmama.cool>
// sub   cv25519 2019-01-22 [E]
//
TEST_F(SubkeyRatingEvalTest, check_subkey_rating_eval_bad_s_ecc_e) {
    slurp_and_import_key(session, "test_keys/pub/crappykey_2-0xC027262F_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "18544492055207B2936BB215325776FBC027262F", &ct);
    ASSERT_OK;
    ASSERT_EQ(ct , PEP_ct_key_too_short);
}

// pub   rsa2048 2019-01-21 [CEA]
//       1E0D278644E2E293A9E953D9AC97F67F6E6C7B8A
// uid           [ unknown] Subkey Check 4 <subkey_select_4@darthmama.cool>
// The following key was revoked on 2019-01-22 by RSA key AC97F67F6E6C7B8A Subkey Check 4 <subkey_select_4@darthmama.cool>
// ssb  ed25519/7A03BDF88893985F
//      created: 2019-01-22  revoked: 2019-01-22  usage: S
// [ unknown] (1). Subkey Check 4 <subkey_select_4@darthmama.cool>
//
TEST_F(SubkeyRatingEvalTest, check_subkey_rating_eval_revoked_sign_no_alt) {
    slurp_and_import_key(session, "test_keys/pub/subkey_select_4-0x6E6C7B8A_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "1E0D278644E2E293A9E953D9AC97F67F6E6C7B8A", &ct);
    ASSERT_OK;
    ASSERT_EQ(ct , PEP_ct_key_revoked);
}

// pub   rsa2048 2019-01-21 [SCA]
//       A2C00B12660CCB5759E6BF1854315D29D106E693
// uid           [ unknown] Subkey Check 5 <subkey_select_5@darthmama.cool>
// sub   cv25519 2019-01-22 [E]
//
// sec  rsa2048/54315D29D106E693
//      created: 2019-01-21  expires: never       usage: SCA
//      trust: unknown       validity: unknown
// The following key was revoked on 2019-01-22 by RSA key 54315D29D106E693 Subkey Check 5 <subkey_select_5@darthmama.cool>
// ssb  rsa2048/B16DED0A115801B4
//      created: 2019-01-22  revoked: 2019-01-22  usage: E
// ssb  cv25519/01B398B420DC3B57
//      created: 2019-01-22  expires: never       usage: E
// [ unknown] (1). Subkey Check 5 <subkey_select_5@darthmama.cool>
//
TEST_F(SubkeyRatingEvalTest, check_subkey_rating_eval_revoked_e_with_alt) {
    slurp_and_import_key(session, "test_keys/pub/subkey_select_5-0xD106E693_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "A2C00B12660CCB5759E6BF1854315D29D106E693", &ct);
    ASSERT_OK;
    ASSERT_EQ(ct , PEP_ct_OpenPGP_unconfirmed);
}
