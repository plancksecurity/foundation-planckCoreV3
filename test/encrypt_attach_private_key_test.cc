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
    cout << "\n*** encrypt_attach_private_key_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    const char* own_uid = PEP_OWN_USERID;
    const char* diff_uid_0 = "TASTY_TEST_UID_0";
    const char* diff_uid_1 = "TASTY_TEST_UID_1";

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
    assert(status == PEP_STATUS_OK);

    input_key = slurp("test_keys/priv/priv-key-import-test-main_0-0x3276D2E5_priv.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    assert(status == PEP_STATUS_OK);
        
    // key with same address and user_id (initially untrusted, then trusted)
    // 359DD8AC87D1F5E4304D08338D7185F180C8CD87
    input_key = slurp("test_keys/pub/priv-key-import-test-main_1-0x80C8CD87_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    assert(status == PEP_STATUS_OK);

    // key with same address and to have different (non-aliased) user_id (initially untrusted, then trusted)
    // B044B83639E292283A3F6E14C2E64B520B74809C
    input_key = slurp("test_keys/pub/priv-key-import-test-main_2-0x0B74809C_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    assert(status == PEP_STATUS_OK);

    // key with different address to have same user_id (initially untrusted, then trusted)
    // C52911EBA0D34B0F549594A15A7A363BD11252C9
    input_key = slurp("test_keys/pub/priv-key-import-test-other_0-0xD11252C9_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    assert(status == PEP_STATUS_OK);
        
    // key with different address to have different user_id (initially untrusted, then trusted)
    // 567212EFB8A3A76B1D32B9565F45BEA9C785F20A
    input_key = slurp("test_keys/pub/priv-key-import-test-other_1-0xC785F20A_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    assert(status == PEP_STATUS_OK);
    
    // Own identity with default key etc
    main_me = new_identity(main_addr, fpr_main_me, own_uid, "PrivateKey Import Test");
    status = set_own_key(session, main_me, fpr_main_me);
    assert(status == PEP_STATUS_OK);

    assert(strcmp(main_me->fpr, fpr_main_me) == 0);
    
    // Identity with same address and user_id - the fpr here will be ignored in update_identity and friends.
    same_addr_same_uid = new_identity(main_addr, fpr_same_addr_same_uid, own_uid, "PrivateKey Import Test");
    // Might be problematic with myself()?
    
    // Identity with same address and different user_id
    same_addr_diff_uid = new_identity(main_addr, fpr_same_addr_diff_uid, diff_uid_0, "PrivateKey Import Test");
    assert(same_addr_diff_uid);
    
    // Identity with diff address and same user_id
    diff_addr_same_uid = new_identity(diff_addr_0, fpr_diff_addr_same_uid, own_uid, "PrivateKey Import Test");
    assert(diff_addr_same_uid);

    // Identity with different address and different user_id
    diff_addr_diff_uid = new_identity(diff_addr_1, fpr_diff_addr_diff_uid, diff_uid_1, "PrivateKey Import Test");
    assert(diff_addr_diff_uid);

    message* msg_same_addr_same_uid = new_message(PEP_dir_outgoing);
    msg_same_addr_same_uid->from = main_me;
    msg_same_addr_same_uid->shortmsg = strdup("Greetings, humans!");
    msg_same_addr_same_uid->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    msg_same_addr_same_uid->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    message* msg_same_addr_diff_uid = message_dup(msg_same_addr_same_uid);
    message* msg_diff_addr_same_uid = message_dup(msg_same_addr_same_uid);       
    message* msg_diff_addr_diff_uid = message_dup(msg_same_addr_same_uid);       

    // Case 1:
    // Same address, same user_id, untrusted
    assert(msg_same_addr_same_uid);        
    identity_list* to_list = new_identity_list(same_addr_same_uid);
    message* enc_same_addr_same_uid_untrusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_same_addr_same_uid,
                                              &enc_same_addr_same_uid_untrusted,
                                              fpr_same_addr_same_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    // Case 2:
    // Same address, same_user_id, trusted
    status = trust_personal_key(session, same_addr_same_uid);
    assert(status == PEP_STATUS_OK);
    message* enc_same_addr_same_uid_trusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_same_addr_same_uid,
                                              &enc_same_addr_same_uid_trusted,
                                              fpr_same_addr_same_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    // Case 3:
    // Different address, same user_id, untrusted
    assert(msg_diff_addr_same_uid);        
    identity_list* to_list_1 = new_identity_list(diff_addr_same_uid);
    message* enc_diff_addr_same_uid_untrusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_diff_addr_same_uid,
                                              &enc_diff_addr_same_uid_untrusted,
                                              fpr_diff_addr_same_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    // Case 4:
    // Different address, same user_id, trusted
    status = trust_personal_key(session, diff_addr_same_uid);
    assert(status == PEP_STATUS_OK);
    message* enc_diff_addr_same_uid_trusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_diff_addr_same_uid,
                                              &enc_diff_addr_same_uid_trusted,
                                              fpr_diff_addr_same_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    // Case 5:
    // Same address, different user_id, untrusted
    assert(msg_same_addr_diff_uid);        
    identity_list* to_list_2 = new_identity_list(same_addr_diff_uid);
    message* enc_same_addr_diff_uid_untrusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_same_addr_diff_uid,
                                              &enc_same_addr_diff_uid_untrusted,
                                              fpr_same_addr_diff_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    // Case 6:
    // Same address, different user_id, trusted
    status = trust_personal_key(session, same_addr_diff_uid);
    assert(status == PEP_STATUS_OK);
    message* enc_same_addr_diff_uid_trusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_same_addr_diff_uid,
                                              &enc_same_addr_diff_uid_untrusted,
                                              fpr_same_addr_diff_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    // Case 7:
    // Different address, different user_id, untrusted
    assert(msg_diff_addr_diff_uid);        
    identity_list* to_list_3 = new_identity_list(diff_addr_diff_uid);
    message* enc_diff_addr_diff_uid_untrusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_diff_addr_diff_uid,
                                              &enc_diff_addr_diff_uid_untrusted,
                                              fpr_diff_addr_diff_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    // Case 8:
    // Different address, different user_id, trusted
    status = trust_personal_key(session, diff_addr_diff_uid);
    assert(status == PEP_STATUS_OK);
    message* enc_diff_addr_diff_uid_trusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_diff_addr_diff_uid,
                                              &enc_diff_addr_diff_uid_trusted,
                                              fpr_diff_addr_diff_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    release(session);
    
    return 0;
}
