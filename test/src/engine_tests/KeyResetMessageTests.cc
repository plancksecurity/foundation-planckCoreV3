// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <assert.h>

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "test_util.h"
#include "EngineTestIndividualSuite.h"
#include "KeyResetMessageTests.h"

using namespace std;

KeyResetMessageTests::KeyResetMessageTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_key_reset_message"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_key_reset_message)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_key_and_notify"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_key_and_notify)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_receive_revoked"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_receive_revoked)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_receive_key_reset_private"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_receive_key_reset_private)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_receive_key_reset_wrong_signer"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_receive_key_reset_wrong_signer)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_receive_key_reset_unsigned"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_receive_key_reset_unsigned)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_receive_message_to_revoked_key"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_receive_message_to_revoked_key)));
}

PEP_STATUS KeyResetMessageTests::message_send_callback(void* obj, message* msg) {
    ((KeyResetMessageTests*)obj)->m_queue.push_back(msg);
    return PEP_STATUS_OK;    
}

void KeyResetMessageTests::setup() {
    EngineTestIndividualSuite::setup();
    session->sync_obj = this;
    session->messageToSend = &KeyResetMessageTests::message_send_callback;
}

void KeyResetMessageTests::send_setup() {
    // Setup own identity
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    assert(status == PEP_STATUS_OK);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                "pep.test.alice@pep-project.org", alice_fpr, 
                PEP_OWN_USERID, "Alice in Wonderland", NULL, true
            );
    assert(status == PEP_STATUS_OK);
    
    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                "pep.test.bob@pep-project.org", NULL, "BobId", "Bob's Burgers",
                NULL, false
            );
    assert(status == PEP_STATUS_OK);
            
    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc",
                "pep-test-carol@pep-project.org", NULL, "carolId", "Carol Burnett",
                NULL, false
            );
    assert(status == PEP_STATUS_OK);
    
    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-dave-0xBB5BCCF6_pub.asc",
                "pep-test-dave@pep-project.org", NULL, "DaveId", 
                "David Hasselhoff (Germans Love Me)", NULL, false
            );
    assert(status == PEP_STATUS_OK);

    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-erin-0x9F8D7CBA_pub.asc",
                "pep-test-erin@pep-project.org", NULL, "ErinErinErin", 
                "Éirinn go Brách", NULL, false
            );
    assert(status == PEP_STATUS_OK);

    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep.test.fenris-0x4F3D2900_pub.asc",
                "pep.test.fenris@thisstilldoesntwork.lu", NULL, "BadWolf", 
                "Fenris Leto Hawke", NULL, false
            );
    assert(status == PEP_STATUS_OK);
}

void KeyResetMessageTests::receive_setup() {
    
}

void KeyResetMessageTests::check_key_reset_message() {
    TEST_ASSERT(true);
}

void KeyResetMessageTests::check_reset_key_and_notify() {
    send_setup();
    
    pEp_identity* from_ident = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    PEP_STATUS status = myself(session, from_ident); 
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(from_ident->fpr && strcasecmp(from_ident->fpr, alice_fpr) == 0,
                    from_ident->fpr);
    TEST_ASSERT(from_ident->me);
    
    // "send" some messages to update the social graph entries
    identity_list* send_idents = 
        new_identity_list(
            new_identity("pep.test.bob@pep-project.org", 
                         NULL, "BobId", "Bob's Burgers"));
                         
    identity_list_add(send_idents, new_identity("pep-test-carol@pep-project.org", NULL, NULL, NULL));    
    identity_list_add(send_idents, new_identity("pep-test-dave@pep-project.org", NULL, NULL, NULL)); 
    identity_list_add(send_idents, new_identity("pep-test-erin@pep-project.org", NULL, NULL, NULL)); 
    identity_list_add(send_idents, new_identity("pep.test.fenris@thisstilldoesntwork.lu", NULL, NULL, NULL)); 
    
    cout << "Creating outgoing message to update DB" << endl;
    message* outgoing_msg = new_message(PEP_dir_outgoing);
    TEST_ASSERT(outgoing_msg);
    outgoing_msg->from = from_ident;
    outgoing_msg->to = send_idents;
    outgoing_msg->shortmsg = strdup("Well isn't THIS a useless message...");
    outgoing_msg->longmsg = strdup("Hi Mom...\n");
    outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "Message created.\n\n";
    cout << "Encrypting message as MIME multipart…\n";
    message* enc_outgoing_msg = nullptr;
    cout << "Calling encrypt_message()\n";
    status = encrypt_message(session, outgoing_msg, NULL, &enc_outgoing_msg, PEP_enc_PGP_MIME, 0);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT(enc_outgoing_msg);
    cout << "Message encrypted.\n";
        
    // If this all worked, we should have a list of recent guys in our DB which, when we reset Alice's 
    // key, will get sent some nice key reset messages.
    // But... we need to have one look like an older message. So. Time to mess with the DB.
    // Dave is our victim. Because friend called Dave, who is actually a nice dude, but it amuses me.
    // (Note: said friend is NOT David Hasselhoff. To my knowledge. Hi Dave!)
    //
    // update identity
    //      set timestamp = 661008730
    //      where address = "pep-test-dave@pep-project.org"
    int int_result = sqlite3_exec(
        session->db,
        "update identity "
        "   set timestamp = 661008730 "
        "   where address = 'pep-test-dave@pep-project.org' ;",
        NULL,
        NULL,
        NULL
    );
    TEST_ASSERT(int_result == SQLITE_OK);
    
    status = key_reset(session, alice_fpr, from_ident);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT(m_queue.size() > 0);
    
    TEST_ASSERT(true);
}

void KeyResetMessageTests::check_receive_revoked() {
    TEST_ASSERT(true);
}

void KeyResetMessageTests::check_receive_key_reset_private() {
    TEST_ASSERT(true);
}

void KeyResetMessageTests::check_receive_key_reset_wrong_signer() {
    TEST_ASSERT(true);
}

void KeyResetMessageTests::check_receive_key_reset_unsigned() {
    TEST_ASSERT(true);
}

void KeyResetMessageTests::check_receive_message_to_revoked_key() {
    TEST_ASSERT(true);
}
