// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>
#include "mime.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"

using namespace std;

int main() {
    cout << "\n*** decrypt_attach_private_key_untrusted_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

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
    assert(status == PEP_STATUS_OK);

    input_key = slurp("test_keys/priv/priv-key-import-test-main_0-0xC065A213_priv.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    assert(status == PEP_STATUS_OK);

    // ensure there's no private key - doesn't work in automated tests, sadly. Uncommon when running script manually.
    bool has_priv = false;
    // status = contains_priv_key(session, fpr_same_addr_same_uid, &has_priv);
    // if (status == PEP_STATUS_OK && has_priv) {
    //     cout << "SORRY, have to delete keys here to run test correctly..." << endl;
    //     status = delete_keypair(session, fpr_same_addr_same_uid);
    //     if (status == PEP_STATUS_OK)
    //         cout << "Successfully deleted keypair for " << fpr_same_addr_same_uid << " - will now import the public key only" << endl;
    // }
        
    // key with same address and user_id
    // 8AB616A3BD51DEF714B5E688EFFB540C3276D2E5
    input_key = slurp("test_keys/pub/priv-key-import-test-main_0-0x3276D2E5_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    assert(status == PEP_STATUS_OK);

    
    cout << "Setting up own identity with default key " << fpr_main_me << endl;
    // Own identity with default key etc
    main_me = new_identity(main_addr, fpr_main_me, own_uid, "PrivateKey Import Test");
    status = set_own_key(session, main_me, fpr_main_me);
    assert(status == PEP_STATUS_OK);

    assert(strcmp(main_me->fpr, fpr_main_me) == 0);
    cout << "Done!" << endl << endl;
    
    cout << "Setting up sender identities and resetting key trust." << endl;
    cout << "Same address, same user_id - address: " << main_addr << ", user_id: " << own_uid << ", fpr: " << fpr_same_addr_same_uid << endl;  
    same_addr_same_uid = new_identity(main_addr, fpr_same_addr_same_uid, own_uid, "PrivateKey Import Test");
    assert(status == PEP_STATUS_OK || status == PEP_CANNOT_FIND_IDENTITY);
    assert((same_addr_same_uid->comm_type & PEP_ct_confirmed) != PEP_ct_confirmed);

    status = key_reset_trust(session, same_addr_same_uid);
    
    cout << "Done!" << endl << endl;

    cout << "Reading in message..." << endl;
    
    string encoded_text = slurp("test_mails/priv_key_attach.eml");

    cout << "Starting tests..." << endl;
    // Case 1:
    // Same address, same user_id, untrusted
    cout << "Same address, same user_id, untrusted" << endl;
    char* decrypted_text = NULL;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    char* modified_src = NULL;
    
    status = get_trust(session, same_addr_same_uid);
    cout << tl_ct_string(same_addr_same_uid->comm_type) << endl;
    
    assert((same_addr_same_uid->comm_type & PEP_ct_confirmed) != PEP_ct_confirmed);
    
    flags = 0;
    status = MIME_decrypt_message(session, encoded_text.c_str(), 
                                  encoded_text.size(), &decrypted_text, 
                                  &keylist_used, &rating, &flags,
				  &modified_src);

    status = get_trust(session, same_addr_same_uid);
    assert(same_addr_same_uid->comm_type == PEP_ct_pEp_unconfirmed);

    cout << "Case 1 Status: " << tl_status_string(status) << endl; 
    cout << "Private key is not trusted for " << same_addr_same_uid->fpr << ", as desired, as the public key was not trusted." << endl;
    cout << "PASS!" << endl;

    // Case 2:
    cout << decrypted_text << endl;
    
    status = key_reset_trust(session, main_me);      
    status = key_reset_trust(session, same_addr_same_uid);      
    release(session);
    
    return 0;
}
