// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <cpptest.h>

#include "pEpEngine.h"

#include "mime.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"

#include "EngineTestSessionSuite.h"
#include "EncryptAttachPrivateKeyTests.h"

using namespace std;

EncryptAttachPrivateKeyTests::EncryptAttachPrivateKeyTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EncryptAttachPrivateKeyTests::check_encrypt_attach_private_key"),
                                                                      static_cast<Func>(&EncryptAttachPrivateKeyTests::check_encrypt_attach_private_key)));
}

void EncryptAttachPrivateKeyTests::check_encrypt_attach_private_key() {

    const char* own_uid = PEP_OWN_USERID;
    const char* diff_uid_0 = "TASTY_TEST_UID_0";
    const char* diff_uid_1 = "TASTY_TEST_UID_1";

    cout << "Importing keys..." << endl;
    
    string input_key;
    const char* main_addr = "priv-key-import-test-main@darthmama.cool";
    pEp_identity* main_me = NULL;
    const char* fpr_main_me = "8AB616A3BD51DEF714B5E688EFFB540C3276D2E5";
    pEp_identity* same_addr_same_uid = NULL;
    const char* fpr_same_addr_same_uid = "359DD8AC87D1F5E4304D08338D7185F180C8CD87";
    
    pEp_identity* same_addr_diff_uid = NULL;
    const char* fpr_same_addr_diff_uid = "B044B83639E292283A3F6E14C2E64B520B74809C";

    const char* diff_addr_0 = "priv-key-import-test-other_0@darthmama.cool";
    pEp_identity* diff_addr_same_uid = NULL;
    const char* fpr_diff_addr_same_uid = "C52911EBA0D34B0F549594A15A7A363BD11252C9";
    
    const char* diff_addr_1 = "priv-key-import-test-other_1@darthmama.cool";
    pEp_identity* diff_addr_diff_uid = NULL;
    const char* fpr_diff_addr_diff_uid = "567212EFB8A3A76B1D32B9565F45BEA9C785F20A";
    
    PEP_STATUS status = PEP_STATUS_OK;

    // key for main own user
    // 8AB616A3BD51DEF714B5E688EFFB540C3276D2E5
    input_key = slurp("test_keys/pub/priv-key-import-test-main_0-0x3276D2E5_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    TEST_ASSERT(status == PEP_STATUS_OK);

    input_key = slurp("test_keys/priv/priv-key-import-test-main_0-0x3276D2E5_priv.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    TEST_ASSERT(status == PEP_STATUS_OK);
        
    // key with same address and user_id (initially untrusted, then trusted)
    // 359DD8AC87D1F5E4304D08338D7185F180C8CD87
    input_key = slurp("test_keys/pub/priv-key-import-test-main_1-0x80C8CD87_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    TEST_ASSERT(status == PEP_STATUS_OK);

    // key with same address and to have different (non-aliased) user_id (initially untrusted, then trusted)
    // B044B83639E292283A3F6E14C2E64B520B74809C
    input_key = slurp("test_keys/pub/priv-key-import-test-main_2-0x0B74809C_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    TEST_ASSERT(status == PEP_STATUS_OK);

    // key with different address to have same user_id (initially untrusted, then trusted)
    // C52911EBA0D34B0F549594A15A7A363BD11252C9
    input_key = slurp("test_keys/pub/priv-key-import-test-other_0-0xD11252C9_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    TEST_ASSERT(status == PEP_STATUS_OK);
        
    // key with different address to have different user_id (initially untrusted, then trusted)
    // 567212EFB8A3A76B1D32B9565F45BEA9C785F20A
    input_key = slurp("test_keys/pub/priv-key-import-test-other_1-0xC785F20A_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    TEST_ASSERT(status == PEP_STATUS_OK);
    cout << "Done!" << endl << endl;
    
    cout << "Setting up own identity with default key " << fpr_main_me << endl;
    // Own identity with default key etc
    main_me = new_identity(main_addr, fpr_main_me, own_uid, "PrivateKey Import Test");
    status = set_own_key(session, main_me, fpr_main_me);
    TEST_ASSERT(status == PEP_STATUS_OK);

    TEST_ASSERT(strcmp(main_me->fpr, fpr_main_me) == 0);
    cout << "Done!" << endl << endl;
    
    cout << "Setting up recipient identities and resetting key trust." << endl;
    cout << "#1: same address, same user_id - address: " << main_addr << ", user_id: " << own_uid << ", fpr: " << fpr_same_addr_same_uid << endl;  
    // Identity with same address and user_id - the fpr here will be ignored in update_identity and friends.
    same_addr_same_uid = new_identity(main_addr, fpr_same_addr_same_uid, own_uid, "PrivateKey Import Test");
    status = key_reset_trust(session, same_addr_same_uid);
    TEST_ASSERT(status == PEP_STATUS_OK || status == PEP_CANNOT_FIND_IDENTITY);
    TEST_ASSERT(strcmp(same_addr_same_uid->fpr, fpr_same_addr_same_uid) == 0);
    
    // Identity with same address and different user_id
    cout << "#2: same address, different user_id - address: " << main_addr << ", user_id: " << diff_uid_0 << ", fpr: " << fpr_same_addr_diff_uid << endl;  
    same_addr_diff_uid = new_identity(main_addr, fpr_same_addr_diff_uid, diff_uid_0, "PrivateKey Import Test");
    TEST_ASSERT(same_addr_diff_uid);
    status = key_reset_trust(session, same_addr_diff_uid);
    TEST_ASSERT(status == PEP_STATUS_OK || status == PEP_CANNOT_FIND_IDENTITY);
    TEST_ASSERT(strcmp(same_addr_diff_uid->fpr, fpr_same_addr_diff_uid) == 0);
    
    // Identity with diff address and same user_id
    cout << "#3: different address, same user_id - address: " << diff_addr_0 << ", user_id: " << own_uid << ", fpr: " << fpr_diff_addr_same_uid << endl;      
    diff_addr_same_uid = new_identity(diff_addr_0, fpr_diff_addr_same_uid, own_uid, "PrivateKey Import Test");
    TEST_ASSERT(diff_addr_same_uid);
    status = key_reset_trust(session, diff_addr_same_uid);
    TEST_ASSERT(status == PEP_STATUS_OK || status == PEP_CANNOT_FIND_IDENTITY);
    TEST_ASSERT(strcmp(diff_addr_same_uid->fpr, fpr_diff_addr_same_uid) == 0);

    // Identity with different address and different user_id
    cout << "#4: different address, different user_id - address: " << diff_addr_1 << ", user_id: " << diff_uid_1 << ", fpr: " << fpr_diff_addr_diff_uid << endl;      
    diff_addr_diff_uid = new_identity(diff_addr_1, fpr_diff_addr_diff_uid, diff_uid_1, "PrivateKey Import Test");
    TEST_ASSERT(diff_addr_diff_uid);
    status = key_reset_trust(session, diff_addr_diff_uid);
    TEST_ASSERT(status == PEP_STATUS_OK || status == PEP_CANNOT_FIND_IDENTITY);
    TEST_ASSERT(strcmp(diff_addr_diff_uid->fpr, fpr_diff_addr_diff_uid) == 0);
    cout << "Done!" << endl << endl;

    message* msg_same_addr_same_uid = new_message(PEP_dir_outgoing);
    msg_same_addr_same_uid->from = main_me;
    msg_same_addr_same_uid->shortmsg = strdup("Greetings, humans!");
    msg_same_addr_same_uid->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    msg_same_addr_same_uid->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    message* msg_same_addr_diff_uid = message_dup(msg_same_addr_same_uid);
    message* msg_diff_addr_same_uid = message_dup(msg_same_addr_same_uid);       
    message* msg_diff_addr_diff_uid = message_dup(msg_same_addr_same_uid);       

    cout << "Starting tests..." << endl;
    // Case 1:
    // Same address, same user_id, untrusted
    cout << "Case 1: Same address, same user_id, untrusted" << endl;
    TEST_ASSERT(msg_same_addr_same_uid);        
    identity_list* to_list = new_identity_list(same_addr_same_uid);
    msg_same_addr_same_uid->to = to_list;
    message* enc_same_addr_same_uid_untrusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_same_addr_same_uid,
                                              &enc_same_addr_same_uid_untrusted,
                                              fpr_same_addr_same_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    cout << "Case 1 Status: " << tl_status_string(status) << endl;
    TEST_ASSERT(status == PEP_ILLEGAL_VALUE);
    cout << "PASS!" << endl;
    
    // Case 2:
    // Same address, same_user_id, trusted
    cout << "Case 2: Same address, same user_id, trusted" << endl;
    status = trust_personal_key(session, same_addr_same_uid);
    cout << "Trust personal key for " << same_addr_same_uid << " gives status " << tl_status_string(status) << " (" << status << ")" << endl;
    TEST_ASSERT(status == PEP_STATUS_OK);
    message* enc_same_addr_same_uid_trusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_same_addr_same_uid,
                                              &enc_same_addr_same_uid_trusted,
                                              fpr_same_addr_same_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    cout << "Case 2 Status: " << tl_status_string(status) << endl;
    TEST_ASSERT(status == PEP_STATUS_OK);
    cout << "PASS!" << endl;

    // Case 3:
    // Different address, same user_id, untrusted
    cout << "Case 3: Different address, same user_id, untrusted" << endl;
    TEST_ASSERT(msg_diff_addr_same_uid);        
    identity_list* to_list_1 = new_identity_list(diff_addr_same_uid);
    msg_diff_addr_same_uid->to = to_list_1;
    message* enc_diff_addr_same_uid_untrusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_diff_addr_same_uid,
                                              &enc_diff_addr_same_uid_untrusted,
                                              fpr_diff_addr_same_uid,
                                              PEP_enc_PGP_MIME,
                                              0);
    
    cout << "Case 3 Status: " << tl_status_string(status) << endl;
    TEST_ASSERT(status == PEP_ILLEGAL_VALUE);
    cout << "PASS!" << endl;

    // Case 4:
    // Different address, same user_id, trusted
    cout << "Case 4: Different address, same user_id, trusted" << endl;
    status = trust_personal_key(session, diff_addr_same_uid);
    TEST_ASSERT(status == PEP_STATUS_OK);
    message* enc_diff_addr_same_uid_trusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_diff_addr_same_uid,
                                              &enc_diff_addr_same_uid_trusted,
                                              fpr_diff_addr_same_uid,
                                              PEP_enc_PGP_MIME,
                                              0);
                                              
    cout << "Case 4 Status: " << tl_status_string(status) << endl;
    TEST_ASSERT(status == PEP_ILLEGAL_VALUE);
    cout << "PASS!" << endl;

    // Case 5:
    // Same address, different user_id, untrusted
    cout << "Case 5: Same address, different user_id, untrusted" << endl;    
    TEST_ASSERT(msg_same_addr_diff_uid);        
    identity_list* to_list_2 = new_identity_list(same_addr_diff_uid);
    msg_same_addr_diff_uid->to = to_list_2;
    message* enc_same_addr_diff_uid_untrusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_same_addr_diff_uid,
                                              &enc_same_addr_diff_uid_untrusted,
                                              fpr_same_addr_diff_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    cout << "Case 5 Status: " << tl_status_string(status) << endl;
    TEST_ASSERT(status == PEP_ILLEGAL_VALUE);    
    cout << "PASS!" << endl;
    
    // Case 6:
    // Same address, different user_id, trusted
    cout << "Case 6: Same address, different user_id, trusted" << endl;        
    status = trust_personal_key(session, same_addr_diff_uid);
    TEST_ASSERT(status == PEP_STATUS_OK);
    message* enc_same_addr_diff_uid_trusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_same_addr_diff_uid,
                                              &enc_same_addr_diff_uid_untrusted,
                                              fpr_same_addr_diff_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    cout << "Case 6 Status: " << tl_status_string(status) << endl;
    TEST_ASSERT(status == PEP_ILLEGAL_VALUE);    
    cout << "PASS!" << endl;

    // Case 7:
    // Different address, different user_id, untrusted
    cout << "Case 7: Different address, different user_id, untrusted" << endl;    
    TEST_ASSERT(msg_diff_addr_diff_uid);        
    identity_list* to_list_3 = new_identity_list(diff_addr_diff_uid);
    msg_diff_addr_diff_uid->to = to_list_3;
    message* enc_diff_addr_diff_uid_untrusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_diff_addr_diff_uid,
                                              &enc_diff_addr_diff_uid_untrusted,
                                              fpr_diff_addr_diff_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    cout << "Case 7 Status: " << tl_status_string(status) << endl;
    TEST_ASSERT(status == PEP_ILLEGAL_VALUE);
    cout << "PASS!" << endl;

    // Case 8:
    // Different address, different user_id, trusted
    cout << "Case 8: Different address, different user_id, trusted" << endl;    
    status = trust_personal_key(session, diff_addr_diff_uid);
    TEST_ASSERT(status == PEP_STATUS_OK);
    message* enc_diff_addr_diff_uid_trusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_diff_addr_diff_uid,
                                              &enc_diff_addr_diff_uid_trusted,
                                              fpr_diff_addr_diff_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    cout << "Case 8 Status: " << tl_status_string(status) << endl;
    TEST_ASSERT(status == PEP_ILLEGAL_VALUE);
    cout << "PASS!" << endl;
    
    cout << "Correctly encrypted message:" << endl << endl;                
    char* encrypted_msg_text = NULL;
    mime_encode_message(enc_same_addr_same_uid_trusted, false, &encrypted_msg_text);                                    
    cout << encrypted_msg_text << endl << endl;
    
    // FIXME: Free all the damned things
}
