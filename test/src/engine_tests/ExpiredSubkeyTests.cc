// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cpptest.h>
#include "TestUtils.h"

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "ExpiredSubkeyTests.h"

using namespace std;

ExpiredSubkeyTests::ExpiredSubkeyTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("ExpiredSubkeyTests::expired_subkey_with_valid_subkeys_and_main_key"),
                                                                      static_cast<Func>(&ExpiredSubkeyTests::expired_subkey_with_valid_subkeys_and_main_key)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("ExpiredSubkeyTests::expired_subkey_with_valid_subkeys_expired_main"),
                                                                      static_cast<Func>(&ExpiredSubkeyTests::expired_subkey_with_valid_subkeys_expired_main)));                                                                      
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("ExpiredSubkeyTests::all_valid_with_leftover_expired_subkeys"),
                                                                      static_cast<Func>(&ExpiredSubkeyTests::all_valid_with_leftover_expired_subkeys)));                                                                                                                                            
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("ExpiredSubkeyTests::no_valid_encryption_subkey"),
                                                                      static_cast<Func>(&ExpiredSubkeyTests::no_valid_encryption_subkey)));                                                                                                                                            
}

void ExpiredSubkeyTests::expired_subkey_with_valid_subkeys_and_main_key() {
    slurp_and_import_key(session,"test_keys/pub/eb_0_valid_pub.asc");
    pEp_identity* expired_0 = new_identity("expired_in_bits_0@darthmama.org",
                                           NULL, NULL, "Expired 0");
    PEP_STATUS status = update_identity(session, expired_0);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(expired_0->fpr);
    PEP_rating rating;
    status = identity_rating(session, expired_0, &rating);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(rating == PEP_rating_reliable);    
}

void ExpiredSubkeyTests::expired_subkey_with_valid_subkeys_expired_main() {
    slurp_and_import_key(session,"test_keys/pub/master_key_test_sign_and_encrypt_added.asc");
    pEp_identity* expired_0 = new_identity("master_key_test@darthmama.org",
                                           NULL, NULL, "Master Key Test");
    PEP_STATUS status = update_identity(session, expired_0);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(expired_0->fpr);
    PEP_rating rating;
    status = identity_rating(session, expired_0, &rating);
    TEST_ASSERT_MSG(status == PEP_KEY_UNSUITABLE, tl_status_string(status));
    TEST_ASSERT(rating == PEP_rating_undefined);        
}

void ExpiredSubkeyTests::all_valid_with_leftover_expired_subkeys() {
    slurp_and_import_key(session,"test_keys/pub/master_key_test_certify_extended_pub.asc");
    pEp_identity* expired_0 = new_identity("master_key_test@darthmama.org",
                                           NULL, NULL, "Master Key Test");
    PEP_STATUS status = update_identity(session, expired_0);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(expired_0->fpr);
    PEP_rating rating;
    status = identity_rating(session, expired_0, &rating);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(rating == PEP_rating_reliable);        
}

void ExpiredSubkeyTests::no_valid_encryption_subkey() {
    slurp_and_import_key(session,"test_keys/pub/master_key_test_deleted_valid_enc_key_pub.asc");
    pEp_identity* expired_0 = new_identity("master_key_test@darthmama.org",
                                           NULL, NULL, "Master Key Test");
    PEP_STATUS status = update_identity(session, expired_0);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(expired_0->fpr);
    PEP_rating rating;
    status = identity_rating(session, expired_0, &rating);
    TEST_ASSERT_MSG(status == PEP_KEY_UNSUITABLE, tl_status_string(status));
    TEST_ASSERT_MSG(rating == PEP_rating_undefined, tl_rating_string(rating));        
}

