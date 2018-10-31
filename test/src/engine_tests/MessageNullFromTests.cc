// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include <assert.h>

#include "pEpEngine.h"
#include "test_util.h"

#include "EngineTestIndividualSuite.h"
#include "MessageNullFromTests.h"

using namespace std;

MessageNullFromTests::MessageNullFromTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("MessageNullFromTests::check_message_null_from_no_header_key_unencrypted"),
                                                                      static_cast<Func>(&MessageNullFromTests::check_message_null_from_header_key_unencrypted)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("MessageNullFromTests::check_message_null_from_no_header_key_unencrypted"),
                                                                          static_cast<Func>(&MessageNullFromTests::check_message_null_from_header_key_unencrypted)));                                                                  
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("MessageNullFromTests::check_message_null_from_encrypted_not_signed"),
                                                                          static_cast<Func>(&MessageNullFromTests::check_message_null_from_encrypted_not_signed)));                                                                  
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("MessageNullFromTests::check_message_null_from_encrypted_and_signed"),
                                                                          static_cast<Func>(&MessageNullFromTests::check_message_null_from_encrypted_and_signed)));                                                                                                                                            
}

void MessageNullFromTests::import_alice_pub() {
    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    PEP_STATUS status = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    assert(status == PEP_STATUS_OK);
}

void MessageNullFromTests::import_bob_pair_and_set_own() {
    const string bob_pub_key = slurp("test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
    const string bob_priv_key = slurp("test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc");
    PEP_STATUS status = import_key(session, bob_pub_key.c_str(), bob_pub_key.length(), NULL);
    assert(status == PEP_STATUS_OK);
    status = import_key(session, bob_priv_key.c_str(), bob_priv_key.length(), NULL);
    assert(status == PEP_STATUS_OK);
}

void MessageNullFromTests::setup() {
    EngineTestIndividualSuite::setup();
    import_bob_pair_and_set_own();
}

void MessageNullFromTests::check_message_null_from_no_header_key_unencrypted() {
    string null_from_msg = slurp("test_files/432_no_from_2.eml");
    cout << null_from_msg << endl;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;
    PEP_rating rating;
    char* mime_plaintext = NULL;
    char* modified_src = NULL;
    PEP_STATUS status = MIME_decrypt_message(session, null_from_msg.c_str(),
                                             null_from_msg.size(),
                                             &mime_plaintext,
                                             &keylist,
                                             &rating,
                                             &flags,
                                             &modified_src);
    TEST_ASSERT_MSG(status == PEP_UNENCRYPTED, tl_status_string(status));                                         
}

void MessageNullFromTests::check_message_null_from_header_key_unencrypted() {
    string null_from_msg = slurp("test_files/432_no_from.eml");
    cout << null_from_msg << endl;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;
    PEP_rating rating;
    char* mime_plaintext = NULL;
    char* modified_src = NULL;
    PEP_STATUS status = MIME_decrypt_message(session, null_from_msg.c_str(),
                                             null_from_msg.size(),
                                             &mime_plaintext,
                                             &keylist,
                                             &rating,
                                             &flags,
                                             &modified_src);
    TEST_ASSERT_MSG(status == PEP_UNENCRYPTED, tl_status_string(status));                                         
}

void MessageNullFromTests::check_message_null_from_encrypted_not_signed() {
    import_alice_pub();
    string null_from_msg = slurp("test_files/432_no_from_encrypted_not_signed.eml");
    cout << null_from_msg << endl;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;
    PEP_rating rating;
    char* mime_plaintext = NULL;
    char* modified_src = NULL;
    PEP_STATUS status = MIME_decrypt_message(session, null_from_msg.c_str(),
                                             null_from_msg.size(),
                                             &mime_plaintext,
                                             &keylist,
                                             &rating,
                                             &flags,
                                             &modified_src);
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));                                         
    TEST_ASSERT(mime_plaintext);
}

void MessageNullFromTests::check_message_null_from_encrypted_and_signed() {
    import_alice_pub();    
    string null_from_msg = slurp("test_files/432_no_from_encrypted_and_signed.eml");
    cout << null_from_msg << endl;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;
    PEP_rating rating;
    char* mime_plaintext = NULL;
    char* modified_src = NULL;
    PEP_STATUS status = MIME_decrypt_message(session, null_from_msg.c_str(),
                                             null_from_msg.size(),
                                             &mime_plaintext,
                                             &keylist,
                                             &rating,
                                             &flags,
                                             &modified_src);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));                                         
    TEST_ASSERT(mime_plaintext);
}

