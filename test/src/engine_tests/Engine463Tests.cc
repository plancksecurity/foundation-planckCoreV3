// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "test_util.h"
#include "message.h"

#include "EngineTestIndividualSuite.h"
#include "Engine463Tests.h"

using namespace std;

Engine463Tests::Engine463Tests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Engine463Tests::check_engine_463_no_own_key"),
                                                                      static_cast<Func>(&Engine463Tests::check_engine_463_no_own_key)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Engine463Tests::check_engine_463_own_key"),
                                                                      static_cast<Func>(&Engine463Tests::check_engine_463_own_key)));                                                                  
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Engine463Tests::check_engine_463_sender_expired_and_renewed"),
                                                                      static_cast<Func>(&Engine463Tests::check_engine_463_sender_expired_and_renewed)));                                                                                                                                    
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Engine463Tests::check_engine_463_reply_recip_expired_and_renewed"),
                                                                      static_cast<Func>(&Engine463Tests::check_engine_463_reply_recip_expired_and_renewed)));                                                                                                                                    
}

void Engine463Tests::check_engine_463_no_own_key() {
    const string claudio_keys = slurp("test_keys/priv/notfound-alt-pub_and_private.asc");
    const string fake_schleuder_key = slurp("test_keys/pub/fake-schleuder.asc");
    
    PEP_STATUS status = import_key(session, claudio_keys.c_str(), claudio_keys.length(), NULL);
    TEST_ASSERT_MSG((status == PEP_TEST_KEY_IMPORT_SUCCESS), tl_status_string(status));    
    status = import_key(session, fake_schleuder_key.c_str(), fake_schleuder_key.length(), NULL);
    TEST_ASSERT_MSG((status == PEP_TEST_KEY_IMPORT_SUCCESS), tl_status_string(status));    

    // Ok, bring in message, decrypt, and see what happens.
    const string msg = slurp("test_mails/notfound-alt.msg");

    char* decrypted_msg = NULL;
    stringlist_t* keylist_used = nullptr;
    char* modified_src = NULL;
    
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
     
    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
}

void Engine463Tests::check_engine_463_own_key() {
    const string claudio_keys = slurp("test_keys/priv/notfound-alt-pub_and_private.asc");
    const string fake_schleuder_key = slurp("test_keys/pub/fake-schleuder.asc");
    
    PEP_STATUS status = import_key(session, claudio_keys.c_str(), claudio_keys.length(), NULL);
    TEST_ASSERT_MSG((status == PEP_TEST_KEY_IMPORT_SUCCESS), tl_status_string(status));    
    status = import_key(session, fake_schleuder_key.c_str(), fake_schleuder_key.length(), NULL);
    TEST_ASSERT_MSG((status == PEP_TEST_KEY_IMPORT_SUCCESS), tl_status_string(status));    

    pEp_identity* own_ident = new_identity("claudio+engine-463@pep.foundation", "A039BC60E43E0DFDDC9DE8663B48C38325210C88", PEP_OWN_USERID, "Not Actually Claudio");
    status = set_own_key(session, own_ident, "A039BC60E43E0DFDDC9DE8663B48C38325210C88");
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));    

    // Ok, bring in message, decrypt, and see what happens.
    const string msg = slurp("test_mails/notfound-alt.msg");

    char* decrypted_msg = NULL;
    stringlist_t* keylist_used = nullptr;
    char* modified_src = NULL;
    
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
     
    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
}

void Engine463Tests::check_engine_463_sender_expired_and_renewed() {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    TEST_ASSERT(ok);    
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");    
    TEST_ASSERT(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");    
    TEST_ASSERT(ok);

    // Ok, so I want to make sure we make an entry, so I'll try to decrypt the message WITH
    // the expired key:
    const string msg = slurp("test_mails/ENGINE-463-attempt-numero-dos.eml");
    
    char* decrypted_msg = NULL;
    stringlist_t* keylist_used = nullptr;
    char* modified_src = NULL;
    
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
     
    PEP_STATUS status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    TEST_ASSERT_MSG((status == PEP_DECRYPTED), tl_status_string(status));

    free(decrypted_msg);
    decrypted_msg = NULL;
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");    
    TEST_ASSERT(ok);    

    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", NULL, NULL, "Lady Claire Trevelyan");
    
    status = identity_rating(session, expired_inquisitor, &rating);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((rating == PEP_rating_reliable), tl_rating_string(rating));
        
    flags = 0;
    
    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);    
    TEST_ASSERT(decrypted_msg);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((rating == PEP_rating_reliable), tl_rating_string(rating));

    free_identity(expired_inquisitor);

}

 void Engine463Tests::check_engine_463_reply_recip_expired_and_renewed() {
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

    free_message(msg2);
}
