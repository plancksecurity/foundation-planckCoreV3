// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include "pEpEngine.h"

#include <cpptest.h>
#include "test_util.h"

#include "EngineTestIndividualSuite.h"
#include "SubkeyRatingEvalTests.h"

using namespace std;

SubkeyRatingEvalTests::SubkeyRatingEvalTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {

    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SubkeyRatingEvalTests::check_subkey_rating_eval_no_es"),
        static_cast<Func>(&SubkeyRatingEvalTests::check_subkey_rating_eval_no_es)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SubkeyRatingEvalTests::check_subkey_rating_eval_weak_s"),
        static_cast<Func>(&SubkeyRatingEvalTests::check_subkey_rating_eval_weak_s)));    
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SubkeyRatingEvalTests::check_subkey_rating_eval_ecc_s"),
        static_cast<Func>(&SubkeyRatingEvalTests::check_subkey_rating_eval_ecc_s)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SubkeyRatingEvalTests::check_subkey_rating_eval_weak_e_strong_ecc_se"),
        static_cast<Func>(&SubkeyRatingEvalTests::check_subkey_rating_eval_weak_e_strong_ecc_se)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SubkeyRatingEvalTests::check_subkey_rating_eval_bad_es"),
        static_cast<Func>(&SubkeyRatingEvalTests::check_subkey_rating_eval_bad_es)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SubkeyRatingEvalTests::check_subkey_rating_eval_bad_e"),
        static_cast<Func>(&SubkeyRatingEvalTests::check_subkey_rating_eval_bad_e)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SubkeyRatingEvalTests::check_subkey_rating_eval_bad_s_ecc_e"),
        static_cast<Func>(&SubkeyRatingEvalTests::check_subkey_rating_eval_bad_s_ecc_e)));    
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SubkeyRatingEvalTests::check_subkey_rating_eval_revoked_sign_no_alt"),
        static_cast<Func>(&SubkeyRatingEvalTests::check_subkey_rating_eval_revoked_sign_no_alt)));    
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SubkeyRatingEvalTests::check_subkey_rating_eval_revoked_e_with_alt"),
        static_cast<Func>(&SubkeyRatingEvalTests::check_subkey_rating_eval_revoked_e_with_alt)));            
}

// pub   rsa2048 2019-01-21 [CA]
//       F0D03C842C0770C2C2A9FEAF2A1ED9814929DC45
// uid           [ unknown] Subkey Check 0 <subkey_select_0@darthmama.cool>
// 
void SubkeyRatingEvalTests::check_subkey_rating_eval_no_es() {
    slurp_and_import_key(session, "test_keys/pub/subkey_select_0-0x4929DC45_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "F0D03C842C0770C2C2A9FEAF2A1ED9814929DC45", &ct);
    TEST_ASSERT_MSG(status == PEP_KEY_UNSUITABLE, tl_status_string(status));
    TEST_ASSERT_MSG(ct = PEP_ct_key_b0rken, tl_ct_string(ct));
    TEST_ASSERT(true);
}

// pub   rsa2048 2019-01-21 [CEA]
//       918AF6E986F39B630541E10DF5F7FA35F2BFF59E
// uid           [ unknown] Subkey Check 1 <subkey_select_1@darthmama.cool>
// sub   rsa1024 2019-01-21 [S]
// 
void SubkeyRatingEvalTests::check_subkey_rating_eval_weak_s() {
    slurp_and_import_key(session, "test_keys/pub/subkey_select_1-0xF2BFF59E_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "918AF6E986F39B630541E10DF5F7FA35F2BFF59E", &ct);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(ct = PEP_ct_OpenPGP_weak_unconfirmed, tl_ct_string(ct));
    TEST_ASSERT(true);
}    

// pub   rsa2048 2019-01-21 [CEA]
//       8894202E3D791C95560058BD77676BACBAD7800C
// uid           [ unknown] Subkey Check 2 <subkey_select_2@darthmama.cool>
// sub   ed25519 2019-01-21 [S]
// 
void SubkeyRatingEvalTests::check_subkey_rating_eval_ecc_s() {
    slurp_and_import_key(session, "test_keys/pub/subkey_select_2-0xBAD7800C_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "8894202E3D791C95560058BD77676BACBAD7800C", &ct);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(ct = PEP_ct_OpenPGP_unconfirmed, tl_ct_string(ct));
    TEST_ASSERT(true);
}

// pub   rsa2048 2019-01-21 [CA]
//       5EA5F7F71BB39B4F7924D1E8D11C676134F44C02
// uid           [ unknown] Subkey Check 3 <subkey_select_3@darthmama.cool>
// sub   ed25519 2019-01-21 [S]
// sub   cv25519 2019-01-21 [E]
// sub   rsa1024 2019-01-21 [E]
//
void SubkeyRatingEvalTests::check_subkey_rating_eval_weak_e_strong_ecc_se() {
    slurp_and_import_key(session, "test_keys/pub/subkey_select_3-0x34F44C02_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "5EA5F7F71BB39B4F7924D1E8D11C676134F44C02", &ct);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(ct = PEP_ct_OpenPGP_weak_unconfirmed, tl_ct_string(ct));
    TEST_ASSERT(true);
}

// pub   rsa512 2019-01-22 [SC]
//       70376BC88DE2DAB4BEF831B65FD6F65326F88D0B
// uid           [ unknown] Weak RSA Key <crappykey_0@darthmama.cool>
// sub   rsa512 2019-01-22 [E]
// 
void SubkeyRatingEvalTests::check_subkey_rating_eval_bad_es() {
    slurp_and_import_key(session, "test_keys/pub/crappykey_0-26F88D0B_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "70376BC88DE2DAB4BEF831B65FD6F65326F88D0B", &ct);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(ct = PEP_ct_key_too_short, tl_ct_string(ct));
    TEST_ASSERT(true);
}

// pub   rsa512 2019-01-22 [C]
//       F712B88AF525E4E32A2A24BCD1B86137C508F2B1
// uid           [ unknown] Weak RSA Key <crappykey_1@darthmama.cool>
// sub   rsa512 2019-01-22 [E]
// sub   rsa2048 2019-01-22 [S]
// 
void SubkeyRatingEvalTests::check_subkey_rating_eval_bad_e() {
    slurp_and_import_key(session, "test_keys/pub/crappykey_1-0xC508F2B1_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "F712B88AF525E4E32A2A24BCD1B86137C508F2B1", &ct);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(ct = PEP_ct_key_too_short, tl_ct_string(ct));
    TEST_ASSERT(true);
}

// pub   rsa512 2019-01-22 [SC]
//       18544492055207B2936BB215325776FBC027262F
// uid           [ unknown] Weak RSA Key <crappykey_2@darthmama.cool>
// sub   cv25519 2019-01-22 [E]
//
void SubkeyRatingEvalTests::check_subkey_rating_eval_bad_s_ecc_e() {
    slurp_and_import_key(session, "test_keys/pub/crappykey_2-0xC027262F_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "18544492055207B2936BB215325776FBC027262F", &ct);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(ct = PEP_ct_key_too_short, tl_ct_string(ct));
    TEST_ASSERT(true);
}    

// pub   rsa2048 2019-01-21 [CEA]
//       1E0D278644E2E293A9E953D9AC97F67F6E6C7B8A
// uid           [ unknown] Subkey Check 4 <subkey_select_4@darthmama.cool>
// The following key was revoked on 2019-01-22 by RSA key AC97F67F6E6C7B8A Subkey Check 4 <subkey_select_4@darthmama.cool>
// ssb  ed25519/7A03BDF88893985F
//      created: 2019-01-22  revoked: 2019-01-22  usage: S   
// [ unknown] (1). Subkey Check 4 <subkey_select_4@darthmama.cool>
//
void SubkeyRatingEvalTests::check_subkey_rating_eval_revoked_sign_no_alt() {
    slurp_and_import_key(session, "test_keys/pub/subkey_select_4-0x6E6C7B8A_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "1E0D278644E2E293A9E953D9AC97F67F6E6C7B8A", &ct);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(ct = PEP_ct_key_revoked, tl_ct_string(ct));
    TEST_ASSERT(true);
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
void SubkeyRatingEvalTests::check_subkey_rating_eval_revoked_e_with_alt() {
    slurp_and_import_key(session, "test_keys/pub/subkey_select_5-0xD106E693_pub.asc");
    PEP_comm_type ct = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, "A2C00B12660CCB5759E6BF1854315D29D106E693", &ct);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(ct = PEP_ct_OpenPGP_unconfirmed, tl_ct_string(ct));
    TEST_ASSERT(true);
}    
