// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <assert.h>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "mime.h"
#include "keymanagement.h"

#include "test_util.h"
#include "EngineTestIndividualSuite.h"
#include "KeyResetMessageTests.h"

using namespace std;

const string KeyResetMessageTests::alice_user_id = PEP_OWN_USERID;
const string KeyResetMessageTests::bob_user_id = "BobId";    
const string KeyResetMessageTests::carol_user_id = "carolId";
const string KeyResetMessageTests::dave_user_id = "DaveId";
const string KeyResetMessageTests::erin_user_id = "ErinErinErin";
const string KeyResetMessageTests::fenris_user_id = "BadWolf";

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
                alice_user_id.c_str(), "Alice in Wonderland", NULL, true
            );
    assert(status == PEP_STATUS_OK);
    
    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                "pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), "Bob's Burgers",
                NULL, false
            );
    assert(status == PEP_STATUS_OK);
            
    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc",
                "pep-test-carol@pep-project.org", NULL, carol_user_id.c_str(), "Carol Burnett",
                NULL, false
            );
    assert(status == PEP_STATUS_OK);
    
    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-dave-0xBB5BCCF6_pub.asc",
                "pep-test-dave@pep-project.org", NULL, dave_user_id.c_str(), 
                "David Hasselhoff (Germans Love Me)", NULL, false
            );
    assert(status == PEP_STATUS_OK);

    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-erin-0x9F8D7CBA_pub.asc",
                "pep-test-erin@pep-project.org", NULL, erin_user_id.c_str(), 
                "Éirinn go Brách", NULL, false
            );
    assert(status == PEP_STATUS_OK);

    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep.test.fenris-0x4F3D2900_pub.asc",
                "pep.test.fenris@thisstilldoesntwork.lu", NULL, fenris_user_id.c_str(), 
                "Fenris Leto Hawke", NULL, false
            );
    assert(status == PEP_STATUS_OK);
}

void KeyResetMessageTests::receive_setup() {
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");  
    assert(status == PEP_STATUS_OK);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc",  
                "pep.test.bob@pep-project.org", bob_fpr, 
                bob_user_id.c_str(), "Robert Redford", NULL, true
            );
    assert(status == PEP_STATUS_OK);
    
    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc",
                "pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), "Alice is tired of Bob",
                NULL, false
            );
    assert(status == PEP_STATUS_OK);    
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
    // Dave is our victim. Because I have a friend called Dave, who is actually a nice dude, but it amuses me.
    // (Note: said friend is NOT David Hasselhoff. To my knowledge. Hi Dave! (Addendum: Dave confirms he is
    // not Hasselhoff. But he wishes he were, sort of.))
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
    
    unordered_map<string, bool> hashmap;
    hashmap[alice_user_id] = false;
    hashmap[bob_user_id] = false;
    hashmap[carol_user_id] = false;
    hashmap[dave_user_id] = false;
    hashmap[erin_user_id] = false;
    hashmap[fenris_user_id] = false;
    
    // Number of messages we SHOULD be sending.
    TEST_ASSERT(m_queue.size() == 4);
    
    for (vector<message*>::iterator it = m_queue.begin(); it != m_queue.end(); it++) {
        message* curr_sent_msg = *it;
        TEST_ASSERT(curr_sent_msg);
        TEST_ASSERT(curr_sent_msg->to);
        TEST_ASSERT(curr_sent_msg->to->ident);
        TEST_ASSERT(!(curr_sent_msg->to->next));
        pEp_identity* to = curr_sent_msg->to->ident;
        TEST_ASSERT(to);
        TEST_ASSERT(to->user_id);
        
        unordered_map<string, bool>::iterator jt = hashmap.find(to->user_id);
        
        TEST_ASSERT(jt != hashmap.end());
        hashmap[jt->first] = true;   
        
        message* decrypted_msg = NULL;
        stringlist_t* keylist = NULL;
        PEP_rating rating;
        PEP_decrypt_flags_t flags;
        
        status = decrypt_message(session, curr_sent_msg, 
                                 &decrypted_msg, &keylist, 
                                 &rating, &flags);
                                 
        TEST_ASSERT_MSG((status == PEP_DECRYPTED_AND_VERIFIED), tl_status_string(status));
        free_message(curr_sent_msg); // DO NOT USE AFTER THIS
    }
    
    // MESSAGE LIST NOW INVALID.
    m_queue.clear();
    
    // Make sure we have messages only to desired recips
    TEST_ASSERT(hashmap[alice_user_id] == false);
    TEST_ASSERT(hashmap[bob_user_id] == true);
    TEST_ASSERT(hashmap[carol_user_id] == true);
    TEST_ASSERT(hashmap[dave_user_id] == false);
    TEST_ASSERT(hashmap[erin_user_id] == true);
    TEST_ASSERT(hashmap[fenris_user_id] == true);
}

void KeyResetMessageTests::check_receive_revoked() {
    receive_setup();
    pEp_identity* alice_ident = new_identity("pep.test.alice@pep-project.org", NULL,
                                            alice_user_id.c_str(), NULL);
                                            
    PEP_STATUS status = update_identity(session, alice_ident);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(strcmp(alice_fpr, alice_ident->fpr) == 0);
    
    string received_mail = slurp("test_files/398_reset_from_alice_to_bob.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);
                                  
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));
    TEST_ASSERT(keylist);
    if (keylist) // there's a test option to continue when asserts fail, so...
        TEST_ASSERT_MSG(strcmp(keylist->value, alice_receive_reset_fpr) == 0,
                        keylist->value);
    
    status = update_identity(session, alice_ident);
    TEST_ASSERT(alice_ident->fpr);
    TEST_ASSERT_MSG(strcmp(alice_receive_reset_fpr, alice_ident->fpr) == 0,
                    alice_ident->fpr);
    
    keylist = NULL;
    status = find_keys(session, alice_fpr, &keylist);

    TEST_ASSERT(status == PEP_KEY_NOT_FOUND);
    free(keylist);
    
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
