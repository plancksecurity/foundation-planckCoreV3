// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"

#include <cpptest.h>
#include "test_util.h"
#include "EngineTestIndividualSuite.h"
#include "CheckRenewedExpiredKeyTrustStatusTests.h"

using namespace std;

CheckRenewedExpiredKeyTrustStatusTests::CheckRenewedExpiredKeyTrustStatusTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("CheckRenewedExpiredKeyTrustStatusTests::check_renewed_expired_key_trust_status"),
                                                                      static_cast<Func>(&CheckRenewedExpiredKeyTrustStatusTests::check_renewed_expired_key_trust_status)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("CheckRenewedExpiredKeyTrustStatusTests::check_renewed_expired_key_trust_status_trusted_user"),
                                                                      static_cast<Func>(&CheckRenewedExpiredKeyTrustStatusTests::check_renewed_expired_key_trust_status_trusted_user)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("CheckRenewedExpiredKeyTrustStatusTests::check_renewed_expired_key_trust_status_pEp_user"),
                                                                      static_cast<Func>(&CheckRenewedExpiredKeyTrustStatusTests::check_renewed_expired_key_trust_status_pEp_user)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("CheckRenewedExpiredKeyTrustStatusTests::check_renewed_expired_key_trust_status_trusted_pEp_user"),
                                                                      static_cast<Func>(&CheckRenewedExpiredKeyTrustStatusTests::check_renewed_expired_key_trust_status_trusted_pEp_user)));                                                                  
}

void CheckRenewedExpiredKeyTrustStatusTests::check_renewed_expired_key_trust_status() {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    TEST_ASSERT(ok);    
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");    
    TEST_ASSERT(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");    
    TEST_ASSERT(ok);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    pEp_identity* alice_from = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Cooper");

    PEP_STATUS status = set_own_key(session, alice_from, alice_fpr); 
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));

    // Ok, so I want to make sure we make an entry, so I'll try to decrypt the message WITH
    // the expired key:
    const string msg = slurp("test_mails/ENGINE-463-attempt-numero-dos.eml");
    
    char* decrypted_msg = NULL;
    stringlist_t* keylist_used = nullptr;
    char* modified_src = NULL;
    
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
     
    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    TEST_ASSERT_MSG((status == PEP_DECRYPTED), tl_status_string(status));

    free(decrypted_msg);
    decrypted_msg = NULL;
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");    
    TEST_ASSERT(ok);    

    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", NULL, NULL, "Lady Claire Trevelyan");
    message* msg2 = new_message(PEP_dir_outgoing);    

    msg2->from = alice_from;
    msg2->to = new_identity_list(expired_inquisitor);
    msg2->shortmsg = strdup("Blah!");
    msg2->longmsg = strdup("Blahblahblah!");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    status = outgoing_message_rating(session, msg2, &rating);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((rating == PEP_rating_reliable), tl_rating_string(rating));    

    status = get_trust(session, expired_inquisitor);
    TEST_ASSERT_MSG(expired_inquisitor->comm_type == PEP_ct_OpenPGP_unconfirmed, tl_ct_string(expired_inquisitor->comm_type));
    free_message(msg2);
}

void CheckRenewedExpiredKeyTrustStatusTests::check_renewed_expired_key_trust_status_trusted_user() {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    TEST_ASSERT(ok);    
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");    
    TEST_ASSERT(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");    
    TEST_ASSERT(ok);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    pEp_identity* alice_from = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Cooper");

    PEP_STATUS status = set_own_key(session, alice_from, alice_fpr); 
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));

    const char* inquisitor_fpr = "8E8D2381AE066ABE1FEE509821BA977CA4728718";
    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", "8E8D2381AE066ABE1FEE509821BA977CA4728718", "TOFU_inquisitor@darthmama.org", "Lady Claire Trevelyan");
    status = set_identity(session, expired_inquisitor);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    expired_inquisitor->comm_type = PEP_ct_OpenPGP; // confirmed 
    status = set_trust(session, expired_inquisitor);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    status = get_trust(session, expired_inquisitor);
    TEST_ASSERT_MSG(expired_inquisitor->comm_type == PEP_ct_OpenPGP, tl_ct_string(expired_inquisitor->comm_type));
    
    // Ok, now update_identity - we'll discover it's expired
    status = update_identity(session, expired_inquisitor);
    TEST_ASSERT_MSG((status == PEP_KEY_UNSUITABLE), tl_status_string(status));
    PEP_comm_type ct = expired_inquisitor->comm_type;    
    TEST_ASSERT_MSG(ct == PEP_ct_key_expired_but_confirmed, tl_ct_string(ct));
    
    // Ok, so I want to make sure we make an entry, so I'll try to decrypt the message WITH
    // the expired key:
    const string msg = slurp("test_mails/ENGINE-463-attempt-numero-dos.eml");
    
    char* decrypted_msg = NULL;
    stringlist_t* keylist_used = nullptr;
    char* modified_src = NULL;
    
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
     
    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    TEST_ASSERT_MSG((status == PEP_DECRYPTED), tl_status_string(status));

    free(decrypted_msg);
    decrypted_msg = NULL;
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");    
    TEST_ASSERT(ok);    

    pEp_identity* expired_inquisitor1 = new_identity("inquisitor@darthmama.org", NULL, NULL, "Lady Claire Trevelyan");
    
    status = update_identity(session, expired_inquisitor1);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    status = get_trust(session, expired_inquisitor1);
    TEST_ASSERT_MSG(expired_inquisitor1->comm_type == PEP_ct_OpenPGP, tl_ct_string(expired_inquisitor1->comm_type));

    message* msg2 = new_message(PEP_dir_outgoing);    

    msg2->from = alice_from;
    msg2->to = new_identity_list(expired_inquisitor1);
    msg2->shortmsg = strdup("Blah!");
    msg2->longmsg = strdup("Blahblahblah!");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    status = outgoing_message_rating(session, msg2, &rating);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((rating >= PEP_rating_trusted), tl_rating_string(rating));    

    free_message(msg2);
}

void CheckRenewedExpiredKeyTrustStatusTests::check_renewed_expired_key_trust_status_pEp_user() {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    TEST_ASSERT(ok);    
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");    
    TEST_ASSERT(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");    
    TEST_ASSERT(ok);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    pEp_identity* alice_from = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Cooper");

    PEP_STATUS status = set_own_key(session, alice_from, alice_fpr); 
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));

    const char* inquisitor_fpr = "8E8D2381AE066ABE1FEE509821BA977CA4728718";
    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", "8E8D2381AE066ABE1FEE509821BA977CA4728718", "TOFU_inquisitor@darthmama.org", "Lady Claire Trevelyan");
    status = set_identity(session, expired_inquisitor);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    expired_inquisitor->comm_type = PEP_ct_pEp_unconfirmed;  
    status = set_trust(session, expired_inquisitor);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    
    bool pEp_user = false;
    status = is_pEp_user(session, expired_inquisitor, &pEp_user);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT(pEp_user);

    // Ok, so I want to make sure we make an entry, so I'll try to decrypt the message WITH
    // the expired key:
    const string msg = slurp("test_mails/ENGINE-463-attempt-numero-dos.eml");

    char* decrypted_msg = NULL;
    stringlist_t* keylist_used = nullptr;
    char* modified_src = NULL;

    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    TEST_ASSERT_MSG((status == PEP_DECRYPTED), tl_status_string(status));

    free(decrypted_msg);
    decrypted_msg = NULL;
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");    
    TEST_ASSERT(ok);    

    pEp_identity* expired_inquisitor1 = new_identity("inquisitor@darthmama.org", NULL, NULL, "Lady Claire Trevelyan");
    message* msg2 = new_message(PEP_dir_outgoing);    

    msg2->from = alice_from;
    msg2->to = new_identity_list(expired_inquisitor1);
    msg2->shortmsg = strdup("Blah!");
    msg2->longmsg = strdup("Blahblahblah!");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    status = outgoing_message_rating(session, msg2, &rating);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((rating == PEP_rating_reliable), tl_rating_string(rating));    

    status = get_trust(session, expired_inquisitor);
    TEST_ASSERT_MSG(expired_inquisitor1->comm_type == PEP_ct_pEp_unconfirmed, tl_ct_string(expired_inquisitor1->comm_type));
    free_message(msg2);
}

void CheckRenewedExpiredKeyTrustStatusTests::check_renewed_expired_key_trust_status_trusted_pEp_user() {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    TEST_ASSERT(ok);    
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");    
    TEST_ASSERT(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");    
    TEST_ASSERT(ok);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    pEp_identity* alice_from = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Cooper");

    PEP_STATUS status = set_own_key(session, alice_from, alice_fpr); 
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));

    const char* inquisitor_fpr = "8E8D2381AE066ABE1FEE509821BA977CA4728718";
    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", "8E8D2381AE066ABE1FEE509821BA977CA4728718", "TOFU_inquisitor@darthmama.org", "Lady Claire Trevelyan");
    status = set_identity(session, expired_inquisitor);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    expired_inquisitor->comm_type = PEP_ct_pEp; // confirmed 
    status = set_trust(session, expired_inquisitor);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    status = get_trust(session, expired_inquisitor);
    TEST_ASSERT_MSG(expired_inquisitor->comm_type == PEP_ct_pEp, tl_ct_string(expired_inquisitor->comm_type));

    bool pEp_user = false;
    status = is_pEp_user(session, expired_inquisitor, &pEp_user);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT(pEp_user);
    
    // Ok, now update_identity - we'll discover it's expired
    status = update_identity(session, expired_inquisitor);
    TEST_ASSERT_MSG((status == PEP_KEY_UNSUITABLE), tl_status_string(status));
    PEP_comm_type ct = expired_inquisitor->comm_type;    
    TEST_ASSERT_MSG(ct == PEP_ct_key_expired_but_confirmed, tl_ct_string(ct));
    
    // Ok, so I want to make sure we make an entry, so I'll try to decrypt the message WITH
    // the expired key:
    const string msg = slurp("test_mails/ENGINE-463-attempt-numero-dos.eml");
    
    char* decrypted_msg = NULL;
    stringlist_t* keylist_used = nullptr;
    char* modified_src = NULL;
    
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
     
    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    TEST_ASSERT_MSG((status == PEP_DECRYPTED), tl_status_string(status));

    free(decrypted_msg);
    decrypted_msg = NULL;
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");    
    TEST_ASSERT(ok);    

    pEp_identity* expired_inquisitor1 = new_identity("inquisitor@darthmama.org", NULL, NULL, "Lady Claire Trevelyan");
    
    status = update_identity(session, expired_inquisitor1);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    status = get_trust(session, expired_inquisitor1);
    TEST_ASSERT_MSG(expired_inquisitor1->comm_type == PEP_ct_pEp, tl_ct_string(expired_inquisitor1->comm_type));

    message* msg2 = new_message(PEP_dir_outgoing);    

    msg2->from = alice_from;
    msg2->to = new_identity_list(expired_inquisitor1);
    msg2->shortmsg = strdup("Blah!");
    msg2->longmsg = strdup("Blahblahblah!");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    status = outgoing_message_rating(session, msg2, &rating);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((rating >= PEP_rating_trusted), tl_rating_string(rating));    

    free_message(msg2);
}
