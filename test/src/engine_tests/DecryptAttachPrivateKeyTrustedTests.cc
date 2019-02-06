// This file is under GNU General Public License 3.0
// see LICENSE.txt

// FIXME: the private key tests should be combined

#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"

#include "mime.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"

#include "EngineTestSessionSuite.h"
#include "DecryptAttachPrivateKeyTrustedTests.h"

using namespace std;

DecryptAttachPrivateKeyTrustedTests::DecryptAttachPrivateKeyTrustedTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DecryptAttachPrivateKeyTrustedTests::check_decrypt_attach_private_key_trusted"),
                                                                      static_cast<Func>(&DecryptAttachPrivateKeyTrustedTests::check_decrypt_attach_private_key_trusted)));
}

void DecryptAttachPrivateKeyTrustedTests::check_decrypt_attach_private_key_trusted() {

    const char* own_uid = PEP_OWN_USERID;

    cout << "Importing keys..." << endl;
    
    string input_key;
    const char* main_addr = "priv-key-import-test-main@darthmama.cool";
    pEp_identity* main_me = NULL;
    const char* fpr_main_me = "13A9F97964A2B52520CAA40E51BCA783C065A213";    
    pEp_identity* same_addr_same_uid = NULL;
    const char* fpr_same_addr_same_uid = "8AB616A3BD51DEF714B5E688EFFB540C3276D2E5";
        
    PEP_STATUS status = PEP_STATUS_OK;

    // key for main own user
    // 
    // 13A9F97964A2B52520CAA40E51BCA783C065A213    
    input_key = slurp("test_keys/pub/priv-key-import-test-main_0-0xC065A213_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    TEST_ASSERT_MSG((status == PEP_KEY_IMPORTED), tl_status_string(status));

    input_key = slurp("test_keys/priv/priv-key-import-test-main_0-0xC065A213_priv.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    TEST_ASSERT_MSG((status == PEP_KEY_IMPORTED), tl_status_string(status));

    // ensure there's no private key - doesn't work in automated tests, sadly. Uncommon when running script manually.
    bool has_priv = false;
        
    // key with same address and user_id
    // 8AB616A3BD51DEF714B5E688EFFB540C3276D2E5
    input_key = slurp("test_keys/pub/priv-key-import-test-main_0-0x3276D2E5_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    TEST_ASSERT_MSG((status == PEP_KEY_IMPORTED), tl_status_string(status));

    
    cout << "Setting up own identity with default key " << fpr_main_me << endl;
    // Own identity with default key etc
    main_me = new_identity(main_addr, fpr_main_me, own_uid, "PrivateKey Import Test");
    status = set_own_key(session, main_me, fpr_main_me);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));

    TEST_ASSERT_MSG((strcmp(main_me->fpr, fpr_main_me) == 0), "strcmp(main_me->fpr, fpr_main_me) == 0");
    cout << "Done!" << endl << endl;
    
    cout << "Setting up sender identities and resetting key trust." << endl;
    cout << "Same address, same user_id - address: " << main_addr << ", user_id: " << own_uid << ", fpr: " << fpr_same_addr_same_uid << endl;  
    same_addr_same_uid = new_identity(main_addr, fpr_same_addr_same_uid, own_uid, "PrivateKey Import Test");
    TEST_ASSERT_MSG((status == PEP_STATUS_OK || status == PEP_CANNOT_FIND_IDENTITY), tl_status_string(status));
    TEST_ASSERT_MSG(((same_addr_same_uid->comm_type & PEP_ct_confirmed) != PEP_ct_confirmed), tl_ct_string(same_addr_same_uid->comm_type));

    status = key_reset_trust(session, same_addr_same_uid);
    
    cout << "Done!" << endl << endl;

    cout << "Reading in message..." << endl;
    
    string encoded_text = slurp("test_mails/priv_key_attach.eml");

    cout << "Starting test..." << endl;
    // Case 1:
    // Same address, same user_id, untrusted
    cout << "decrypt with attached private key: Same address, same user_id, trusted" << endl;
    char* decrypted_text = NULL;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    char* modified_src = NULL;
    
    cout << "Trusting own key for " << same_addr_same_uid->user_id << " and " << same_addr_same_uid->fpr << endl;
    status = trust_own_key(session, same_addr_same_uid);
    cout << "Status is " << tl_status_string(status) << endl;  
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    free(decrypted_text);
    decrypted_text = NULL;

    status = get_trust(session, same_addr_same_uid);
    cout << tl_ct_string(same_addr_same_uid->comm_type) << endl;
    
    TEST_ASSERT_MSG((same_addr_same_uid->comm_type == PEP_ct_pEp), "same_addr_same_uid->comm_type == PEP_ct_pEp");
    
    flags = 0;
    status = MIME_decrypt_message(session, encoded_text.c_str(), 
                                  encoded_text.size(), &decrypted_text, 
                                  &keylist_used, &rating, &flags,
                                  &modified_src);

    status = get_trust(session, same_addr_same_uid);
    TEST_ASSERT_MSG((same_addr_same_uid->comm_type == PEP_ct_pEp), "same_addr_same_uid->comm_type == PEP_ct_pEp");
    
    flags = 0;
    status = MIME_decrypt_message(session, encoded_text.c_str(), 
                                  encoded_text.size(), &decrypted_text, 
                                  &keylist_used, &rating, &flags,
                                  &modified_src);
    
    cout << "Status: " << tl_status_string(status) << endl;
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));

    cout << decrypted_text << endl;
    
    has_priv = false;
    status = contains_priv_key(session, fpr_same_addr_same_uid, &has_priv);
    TEST_ASSERT_MSG((has_priv == true), "has_priv == true");
    cout << "Private key was also imported." << endl;
    
    cout << "PASS!" << endl;
    
    // FIXME: rework this in new framework
    status = key_reset_trust(session, main_me);      
    status = key_reset_trust(session, same_addr_same_uid);      
}
