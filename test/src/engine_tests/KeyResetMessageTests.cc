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
#include "key_reset.h"

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

KeyResetMessageTests* KeyResetMessageTests::fake_this = NULL;

KeyResetMessageTests::KeyResetMessageTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
        
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_key_reset_message"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_key_reset_message)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_key_and_notify"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_key_and_notify)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_non_reset_receive_revoked"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_non_reset_receive_revoked)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_receive_revoked"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_receive_revoked)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_receive_message_to_revoked_key_from_unknown"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_receive_message_to_revoked_key_from_unknown)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_receive_message_to_revoked_key_from_contact"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_receive_message_to_revoked_key_from_contact)));                                                                      
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_multiple_resets_single_key"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_multiple_resets_single_key)));                                                                      
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_ident_uid_only"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_ident_uid_only)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_ident_address_only"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_ident_address_only)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_ident_null_ident"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_ident_null_ident)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_ident_other_pub_fpr"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_ident_other_pub_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_ident_other_priv_fpr"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_ident_other_priv_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_ident_other_pub_no_fpr"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_ident_other_pub_no_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_ident_other_priv_no_fpr"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_ident_other_priv_no_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_ident_own_pub_fpr"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_ident_own_pub_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_ident_own_priv_fpr"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_ident_own_priv_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_ident_own_priv_no_fpr"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_ident_own_priv_no_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_user_other_no_fpr"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_user_other_no_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_user_other_fpr"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_user_other_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_user_own_fpr"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_user_own_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_user_no_fpr"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_user_no_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_all_own_keys"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_all_own_keys)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_reset_all_own_no_own"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_reset_all_own_no_own)));

    fake_this = this;                                                                  
    
    cached_messageToSend = &KeyResetMessageTests::message_send_callback;
}

PEP_STATUS KeyResetMessageTests::message_send_callback(message* msg) {
    fake_this->m_queue.push_back(msg);
    return PEP_STATUS_OK;    
}

void KeyResetMessageTests::setup() {
    EngineTestIndividualSuite::setup();
    m_queue.clear();
}

void KeyResetMessageTests::send_setup() {
    // Setup own identity
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    assert(status == PEP_KEY_IMPORTED);
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
    assert(status == PEP_KEY_IMPORTED);
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
                         NULL, bob_user_id.c_str(), "Bob's Burgers"));
                         
    identity_list_add(send_idents, new_identity("pep-test-carol@pep-project.org", NULL, NULL, NULL));    
    identity_list_add(send_idents, new_identity("pep-test-dave@pep-project.org", NULL, NULL, NULL)); 
    identity_list_add(send_idents, new_identity("pep-test-erin@pep-project.org", NULL, NULL, NULL)); 
    identity_list_add(send_idents, new_identity("pep.test.fenris@thisstilldoesntwork.lu", NULL, NULL, NULL)); 

    identity_list* curr_ident;
    
    for (curr_ident = send_idents; curr_ident && curr_ident->ident; curr_ident = curr_ident->next) {
        status = update_identity(session, curr_ident->ident);
        if (strcmp(curr_ident->ident->user_id, bob_user_id.c_str()) == 0)
            continue;
        
        status = set_as_pEp_user(session, curr_ident->ident);
        TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    }
    
    cout << "Creating outgoing message to update DB" << endl;
    message* outgoing_msg = new_message(PEP_dir_outgoing);
    TEST_ASSERT(outgoing_msg);
    outgoing_msg->from = from_ident;
    outgoing_msg->to = send_idents;
    outgoing_msg->shortmsg = strdup("Well isn't THIS a useless message...");
    outgoing_msg->longmsg = strdup("Hi Mom...\n");
    // outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    // that's illegal - VB.
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
    status = myself(session, from_ident);
    string new_fpr = from_ident->fpr;
    TEST_ASSERT_MSG((strcmp(alice_fpr, new_fpr.c_str()) != 0), new_fpr.c_str());
    
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

        // Uncomment to regenerate received message - remember to update
        // alice_receive_reset_fpr        
        // if (strcmp(curr_sent_msg->to->ident->user_id, bob_user_id.c_str()) == 0) {
        //     char* bob_msg = NULL;
        //     mime_encode_message(curr_sent_msg, false, &bob_msg);
        //     cout << bob_msg;
        // }
        // else if (strcmp(curr_sent_msg->to->ident->user_id, fenris_user_id.c_str()) == 0) {
        //     char* fenris_msg = NULL;
        //     mime_encode_message(curr_sent_msg, false, &fenris_msg);
        //     cout << fenris_msg;
        // }
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

void KeyResetMessageTests::check_non_reset_receive_revoked() {
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
                                  
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(keylist);
    if (keylist) // there's a test option to continue when asserts fail, so...
        TEST_ASSERT_MSG(strcmp(keylist->value, alice_receive_reset_fpr) == 0,
                        keylist->value);
    
    status = update_identity(session, alice_ident);
    TEST_ASSERT(alice_ident->fpr);
    TEST_ASSERT_MSG(strcmp(alice_receive_reset_fpr, alice_ident->fpr) == 0,
                    alice_ident->fpr);
    
    keylist = NULL;

    free(keylist);    
}

void KeyResetMessageTests::check_reset_receive_revoked() {
    PEP_STATUS status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep.test.fenris-0x4F3D2900_pub.asc",
                "pep.test.fenris@thisstilldoesntwork.lu", NULL, fenris_user_id.c_str(), 
                "Fenris Leto Hawke", NULL, false
            );
    assert(status == PEP_STATUS_OK);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.fenris-0x4F3D2900_priv.asc",
                "pep.test.fenris@thisstilldoesntwork.lu", NULL, fenris_user_id.c_str(), 
                "Fenris Leto Hawke", NULL, false
            );
    assert(status == PEP_STATUS_OK);
    
    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc",
                "pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), "Alice is tired of Bob",
                NULL, false
            );
    assert(status == PEP_STATUS_OK);    
    
    pEp_identity* alice_ident = new_identity("pep.test.alice@pep-project.org", NULL,
                                            alice_user_id.c_str(), NULL);
                                            
    status = update_identity(session, alice_ident);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(strcmp(alice_fpr, alice_ident->fpr) == 0);
    
    string received_mail = slurp("test_files/398_reset_from_alice_to_fenris.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);
                                  
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(keylist);
    if (keylist) // there's a test option to continue when asserts fail, so...
        TEST_ASSERT_MSG(strcmp(keylist->value, alice_receive_reset_fpr) == 0,
                        keylist->value);
    
    status = update_identity(session, alice_ident);
    TEST_ASSERT(alice_ident->fpr);
    TEST_ASSERT_MSG(strcmp(alice_receive_reset_fpr, alice_ident->fpr) == 0,
                    alice_ident->fpr);
    
    keylist = NULL;

    free(keylist);    
}

void KeyResetMessageTests::create_msg_for_revoked_key() {
    PEP_STATUS status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-gabrielle-0xE203586C_pub.asc",
                "pep-test-gabrielle@pep-project.org", NULL, PEP_OWN_USERID, 
                "Gabi", NULL, false
            );
    assert(status == PEP_STATUS_OK);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep-test-gabrielle-0xE203586C_priv.asc",
                "pep-test-gabrielle@pep-project.org", NULL, PEP_OWN_USERID, 
                "Gabi", NULL, false
            );
    assert(status == PEP_STATUS_OK);
    
    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc",
                "pep.test.alice@pep-project.org", NULL, "AliceOther", "Alice is tired of Bob",
                NULL, false
            );
    
    pEp_identity* from_ident = new_identity("pep-test-gabrielle@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    status = myself(session, from_ident); 
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(from_ident->fpr && strcasecmp(from_ident->fpr, "906C9B8349954E82C5623C3C8C541BD4E203586C") == 0,
                    from_ident->fpr);
    TEST_ASSERT(from_ident->me);
    
    // "send" some messages to update the social graph entries
    identity_list* send_idents = 
        new_identity_list(
            new_identity("pep.test.alice@pep-project.org", NULL, "AliceOther", NULL));
    status = update_identity(session, send_idents->ident);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));    
    status = set_as_pEp_user(session, send_idents->ident);
                             
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
    char* outstring = NULL;
    mime_encode_message(enc_outgoing_msg, false, &outstring);
    cout << outstring << endl;
    free_message(enc_outgoing_msg);
    free(outstring);
}

void KeyResetMessageTests::check_receive_message_to_revoked_key_from_unknown() {
    // create_msg_for_revoked_key(); // call to recreate msg
    send_setup();
    pEp_identity* from_ident = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    PEP_STATUS status = myself(session, from_ident); 
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(from_ident->fpr && strcasecmp(from_ident->fpr, alice_fpr) == 0,
                    from_ident->fpr);
    TEST_ASSERT(from_ident->me);

    status = key_reset(session, alice_fpr, from_ident);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    m_queue.clear();
    
    string received_mail = slurp("test_files/398_gabrielle_to_alice.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);
    TEST_ASSERT(m_queue.size() == 0);
    free(decrypted_msg);
    free(modified_src);
    free_stringlist(keylist);
    free_identity(from_ident);
}

void KeyResetMessageTests::check_receive_message_to_revoked_key_from_contact() {
    // create_msg_for_revoked_key(); // call to recreate msg
    send_setup();
    pEp_identity* from_ident = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    PEP_STATUS status = myself(session, from_ident); 
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(from_ident->fpr && strcasecmp(from_ident->fpr, alice_fpr) == 0,
                    from_ident->fpr);
    TEST_ASSERT(from_ident->me);

    // Send Gabrielle a message
    identity_list* send_idents = new_identity_list(new_identity("pep-test-gabrielle@pep-project.org", NULL, "Gabi", "Gabi"));
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
    TEST_ASSERT_MSG((status == PEP_UNENCRYPTED), tl_status_string(status));
    //
    cout << "Message created." << endl;
    
    // Make the update have occurred earlier, so we don't notify her
    // (We have no key for her yet anyway!)
    int int_result = sqlite3_exec(
        session->db,
        "update identity "
        "   set timestamp = '2018-04-10 16:48:33' "
        "   where address = 'pep-test-gabrielle@pep-project.org' ;",
        NULL,
        NULL,
        NULL
    );
    TEST_ASSERT(int_result == SQLITE_OK);

    // FIXME: longer term we need to fix the test, but the key attached to the message below has expired, so for now, we give her a new key
    slurp_and_import_key(session, "test_keys/pub/pep-test-gabrielle-0xE203586C_pub.asc");

    status = key_reset(session, alice_fpr, from_ident);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT(m_queue.size() == 0);
    m_queue.clear();

    // Now we get mail from Gabi, who only has our old key AND has become
    // a pEp user in the meantime...
    string received_mail = slurp("test_files/398_gabrielle_to_alice.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);
    
    TEST_ASSERT(m_queue.size() == 1);
    vector<message*>::iterator it = m_queue.begin();
    message* reset_msg = *it;
    TEST_ASSERT(reset_msg);    
    TEST_ASSERT(reset_msg->from);    
    TEST_ASSERT(reset_msg->to);    
    TEST_ASSERT(reset_msg->to->ident);    
    TEST_ASSERT(strcmp(reset_msg->to->ident->address, "pep-test-gabrielle@pep-project.org") == 0);
    TEST_ASSERT(strcmp(reset_msg->to->ident->fpr, "906C9B8349954E82C5623C3C8C541BD4E203586C") == 0);    
    TEST_ASSERT(strcmp(reset_msg->from->fpr, alice_fpr) != 0);
    TEST_ASSERT(keylist);
    TEST_ASSERT(keylist->value);
    TEST_ASSERT(strcmp(keylist->value, alice_fpr) != 0);
    TEST_ASSERT(keylist->next);
    if (strcmp(keylist->next->value, "906C9B8349954E82C5623C3C8C541BD4E203586C") != 0)
        TEST_ASSERT(keylist->next->next && 
                    strcmp(keylist->next->value, 
                           "906C9B8349954E82C5623C3C8C541BD4E203586C") == 0);

}

void KeyResetMessageTests::check_multiple_resets_single_key() {
    send_setup();
    
    pEp_identity* from_ident = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    PEP_STATUS status = myself(session, from_ident); 
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(from_ident->fpr && strcasecmp(from_ident->fpr, alice_fpr) == 0,
                    from_ident->fpr);
    TEST_ASSERT(from_ident->me);

    status = key_reset(session, NULL, NULL);
    TEST_ASSERT(status == PEP_STATUS_OK);
    
    status = key_reset(session, NULL, NULL);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, from_ident);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(from_ident->fpr != NULL && from_ident->fpr[0] != 0);
}

void KeyResetMessageTests::check_reset_ident_uid_only() {
    send_setup(); // lazy
    pEp_identity* bob = new_identity(NULL, NULL, bob_user_id.c_str(), NULL);

    // Ok, let's reset it
    PEP_STATUS status = key_reset_identity(session, bob, NULL);
    TEST_ASSERT_MSG(status == PEP_ILLEGAL_VALUE, tl_status_string(status));    
}

void KeyResetMessageTests::check_reset_ident_address_only() {
    send_setup(); // lazy
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, NULL, NULL);

    PEP_STATUS status = key_reset_identity(session, bob, NULL);
    TEST_ASSERT_MSG(status == PEP_ILLEGAL_VALUE, tl_status_string(status));    
}

void KeyResetMessageTests::check_reset_ident_null_ident() {
    // Ok, let's reset it
    PEP_STATUS status = key_reset_identity(session, NULL, NULL);
    TEST_ASSERT_MSG(status == PEP_ILLEGAL_VALUE, tl_status_string(status));    
}

void KeyResetMessageTests::check_reset_ident_other_pub_fpr() {
    send_setup(); // lazy
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), NULL);
    PEP_STATUS status = update_identity(session, bob);
    
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(bob->fpr && bob->fpr[0]);
    status = set_as_pEp_user(session, bob);
    status = trust_personal_key(session, bob);

    status = update_identity(session, bob);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(bob->comm_type == PEP_ct_pEp, tl_ct_string(bob->comm_type));

    // Ok, let's reset it
    status = key_reset_identity(session, bob, bob->fpr);
    status = update_identity(session, bob);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(bob->comm_type == PEP_ct_key_not_found, tl_ct_string(bob->comm_type));
    TEST_ASSERT_MSG(!(bob->fpr) || !(bob->fpr[0]), bob->fpr);

    // TODO: import key, verify PEP_ct_OpenPGP_unconfirmed
    TEST_ASSERT(true);
}

// Corner case?
void KeyResetMessageTests::check_reset_ident_other_priv_fpr() {
    send_setup(); // lazy
    // Also import Bob's private key, because that dude is a fool.
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc");
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), NULL);
    status = update_identity(session, bob);

    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(bob->fpr && bob->fpr[0]);
    TEST_ASSERT(!bob->me);
    
    status = set_as_pEp_user(session, bob);
    status = trust_personal_key(session, bob);

    status = update_identity(session, bob);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(bob->comm_type == PEP_ct_pEp, tl_ct_string(bob->comm_type));
    TEST_ASSERT(!bob->me);

    // Ok, let's reset it
    status = key_reset_identity(session, bob, bob->fpr);
    status = update_identity(session, bob);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(bob->comm_type == PEP_ct_key_not_found, tl_ct_string(bob->comm_type));
    TEST_ASSERT_MSG(!(bob->fpr) || !(bob->fpr[0]), bob->fpr);

    // TODO: import key, verify PEP_ct_OpenPGP_unconfirmed
    TEST_ASSERT(true);
}

void KeyResetMessageTests::check_reset_ident_other_pub_no_fpr() {
    send_setup(); // lazy
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), NULL);
    PEP_STATUS status = update_identity(session, bob);
    
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(bob->fpr && bob->fpr[0]);
    status = set_as_pEp_user(session, bob);
    status = trust_personal_key(session, bob);

    status = update_identity(session, bob);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(bob->comm_type == PEP_ct_pEp, tl_ct_string(bob->comm_type));
    free(bob->fpr);
    bob->fpr = NULL;

    // Ok, let's reset it
    status = key_reset_identity(session, bob, NULL);
    status = update_identity(session, bob);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(bob->comm_type == PEP_ct_key_not_found, tl_ct_string(bob->comm_type));
    TEST_ASSERT_MSG(!(bob->fpr) || !(bob->fpr[0]), bob->fpr);

    // TODO: import key, verify PEP_ct_OpenPGP_unconfirmed
    TEST_ASSERT(true);
}
//    const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
// TODO: multiplr keys above

void KeyResetMessageTests::check_reset_ident_other_priv_no_fpr() {
    send_setup(); // lazy
    // Also import Bob's private key, because that dude is a fool.
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc");
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), NULL);
    status = update_identity(session, bob);
    
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(bob->fpr && bob->fpr[0]);
    status = set_as_pEp_user(session, bob);
    status = trust_personal_key(session, bob);
    
    status = update_identity(session, bob);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(bob->comm_type == PEP_ct_pEp, tl_ct_string(bob->comm_type));
    TEST_ASSERT(!bob->me);
    free(bob->fpr);
    bob->fpr = NULL;

    // Ok, let's reset it
    status = key_reset_identity(session, bob, NULL);
    status = update_identity(session, bob);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(bob->comm_type == PEP_ct_key_not_found, tl_ct_string(bob->comm_type));
    TEST_ASSERT_MSG(!(bob->fpr) || !(bob->fpr[0]), bob->fpr);
    TEST_ASSERT(!bob->me);

    // TODO: import key, verify PEP_ct_OpenPGP_unconfirmed
    TEST_ASSERT(true);
}

void KeyResetMessageTests::check_reset_ident_own_pub_fpr() {
    send_setup(); // lazy
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), NULL);
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander-0x26B54E4E_pub.asc");
    
    // hacky
    alice->fpr = strdup("3AD9F60FAEB22675DB873A1362D6981326B54E4E");
    status = set_pgp_keypair(session, alice->fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);
    alice->comm_type = PEP_ct_OpenPGP;
    status = set_trust(session, alice);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    // Ok, let's reset it
    status = key_reset_identity(session, alice, alice->fpr);
    status = myself(session, alice);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    TEST_ASSERT(alice->me);
    TEST_ASSERT(alice->fpr);
    TEST_ASSERT_MSG(strcmp(alice->fpr, alice_fpr) == 0, alice->fpr);
    TEST_ASSERT_MSG(alice->comm_type == PEP_ct_pEp, tl_ct_string(alice->comm_type));

    free(alice->fpr);
    alice->fpr = strdup("3AD9F60FAEB22675DB873A1362D6981326B54E4E");
    status = get_trust(session, alice);
    TEST_ASSERT_MSG(status == PEP_CANNOT_FIND_IDENTITY, tl_ct_string(alice->comm_type));    
}

void KeyResetMessageTests::check_reset_ident_own_priv_fpr() {
    send_setup(); // lazy
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), NULL);
    PEP_STATUS status = myself(session, alice);

    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(alice->fpr && alice->fpr[0]);
    TEST_ASSERT(alice->me);
    TEST_ASSERT_MSG(strcmp(alice->fpr, alice_fpr) == 0, alice->fpr);
    
    status = key_reset_identity(session, alice, alice_fpr);
    status = myself(session, alice);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    char* alice_new_fpr = alice->fpr;
    TEST_ASSERT(alice_new_fpr && alice_new_fpr[0]);
    TEST_ASSERT_MSG(strcmp(alice_fpr, alice_new_fpr) != 0, alice_new_fpr);
}

void KeyResetMessageTests::check_reset_ident_own_priv_no_fpr() {
    send_setup(); // lazy
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), NULL);
    PEP_STATUS status = myself(session, alice);

    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(alice->fpr && alice->fpr[0]);
    TEST_ASSERT(alice->me);
    TEST_ASSERT_MSG(strcmp(alice->fpr, alice_fpr) == 0, alice->fpr);
    free(alice->fpr);
    alice->fpr = NULL;
    status = key_reset_identity(session, alice, NULL);
    status = myself(session, alice);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    char* alice_new_fpr = alice->fpr;
    TEST_ASSERT(alice_new_fpr && alice_new_fpr[0]);
    TEST_ASSERT_MSG(strcmp(alice_fpr, alice_new_fpr) != 0, alice_new_fpr);
}

void KeyResetMessageTests::check_reset_user_other_no_fpr() {
      char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
      char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
      char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
      char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

      pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                            NULL,
                                            "AlexID",
                                            "Alexander Braithwaite");

/*                                          
test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc
test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc
test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc
test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc
*/
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");

    alex_id->fpr = pubkey1;
    status = trust_personal_key(session, alex_id);
    alex_id->fpr = pubkey3;
    status = trust_personal_key(session, alex_id);
    status = set_as_pEp_user(session, alex_id);
    alex_id->fpr = pubkey4;
    status = trust_personal_key(session, alex_id);

    status = key_reset_user(session, alex_id->user_id, NULL);

    stringlist_t* keylist = NULL;

    alex_id->fpr = pubkey1;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_unknown, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey1, &keylist);
    TEST_ASSERT_MSG(status == PEP_GET_KEY_FAILED || !keylist || EMPTYSTR(keylist->value),
                    (string(pubkey1) + " was unfortunately not deleted.").c_str());        

    alex_id->fpr = pubkey2;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_unknown, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey2, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey2) + " was deleted and should not have been").c_str());        

    alex_id->fpr = pubkey3;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_unknown, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey3, &keylist);
    TEST_ASSERT_MSG(status == PEP_GET_KEY_FAILED || !keylist || EMPTYSTR(keylist->value),
                    (string(pubkey3) + " was unfortunately not deleted.").c_str());        

    alex_id->fpr = pubkey4;
    status = get_trust(session, alex_id);    
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_unknown, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey4, &keylist);
    TEST_ASSERT_MSG(status == PEP_GET_KEY_FAILED || !keylist || EMPTYSTR(keylist->value),
                    (string(pubkey4) + " was unfortunately not deleted.").c_str());        

    TEST_ASSERT(true);
}

void KeyResetMessageTests::check_reset_user_other_fpr() {
      char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
      char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
      char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
      char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

      pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                            NULL,
                                            "AlexID",
                                            "Alexander Braithwaite");

/*                                          
test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc
test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc
test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc
test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc
*/
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");

    alex_id->fpr = pubkey1;
    status = trust_personal_key(session, alex_id);
    alex_id->fpr = pubkey3;
    status = trust_personal_key(session, alex_id);
    status = set_as_pEp_user(session, alex_id);
    alex_id->fpr = pubkey4;
    status = trust_personal_key(session, alex_id);

    status = key_reset_user(session, alex_id->user_id, pubkey3);

    stringlist_t* keylist = NULL;

    alex_id->fpr = pubkey1;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_pEp, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey1, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey1) + " was deleted and should not have been").c_str());        

    free_stringlist(keylist);
    keylist = NULL;
    
    alex_id->fpr = pubkey2;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_unknown, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey2, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey2) + " was deleted and should not have been").c_str());        

    alex_id->fpr = pubkey3;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_unknown, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey3, &keylist);
    TEST_ASSERT_MSG(status == PEP_GET_KEY_FAILED || !keylist || EMPTYSTR(keylist->value),
                    (string(pubkey3) + " was unfortunately not deleted.").c_str());        

    alex_id->fpr = pubkey4;
    status = get_trust(session, alex_id);    
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_pEp, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey4, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey4) + " was deleted and should not have been").c_str());        

    // next line is for readability.
    alex_id->fpr = NULL;
    free_stringlist(keylist);
    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}

void KeyResetMessageTests::check_reset_user_own_fpr() {
      char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
      char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
      char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
      char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

      pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                            NULL,
                                            "AlexID",
                                            "Alexander Braithwaite");

/*                                          
test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc
test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc
test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc
test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc
*/
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xBDA17020_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    status = set_own_key(session, alex_id, pubkey3);
    status = set_own_key(session, alex_id, pubkey4);

    status = key_reset_user(session, alex_id->user_id, pubkey3);

    alex_id->fpr = pubkey1;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_pEp, tl_ct_string(alex_id->comm_type));
    
    alex_id->fpr = pubkey2;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_unknown, tl_ct_string(alex_id->comm_type));

    stringlist_t* keylist = NULL;
    
    alex_id->fpr = pubkey3;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_mistrusted, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey4, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey3) + " was deleted and should not have been. Status is " + tl_status_string(status)).c_str());        

    free_stringlist(keylist);
    keylist = NULL;
    
    alex_id->fpr = pubkey4;
    status = get_trust(session, alex_id);    
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_pEp, tl_ct_string(alex_id->comm_type));

    // next line is for readability.
    alex_id->fpr = NULL;
    free_stringlist(keylist);
    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}

void KeyResetMessageTests::check_reset_user_no_fpr() {
      char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
      char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
      char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
      char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

      pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                            NULL,
                                            "AlexID",
                                            "Alexander Braithwaite");

/*                                          
test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc
test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc
test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc
test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc
*/
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xBDA17020_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    status = set_own_key(session, alex_id, pubkey3);
    status = set_own_key(session, alex_id, pubkey4);

    status = key_reset_user(session, alex_id->user_id, NULL);
    
    TEST_ASSERT_MSG(status == PEP_ILLEGAL_VALUE, tl_status_string(status));

    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}

void KeyResetMessageTests::check_reset_all_own_keys() {
      char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
      char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
      char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
      char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

      pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                            NULL,
                                            "AlexID",
                                            "Alexander Braithwaite");

/*                                          
test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc
test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc
test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc
test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc
*/
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xBDA17020_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    status = set_own_key(session, alex_id, pubkey3);
    status = set_own_key(session, alex_id, pubkey4);

    status = key_reset_all_own_keys(session);

    stringlist_t* keylist = NULL;

    alex_id->fpr = pubkey1;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_mistrusted, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey1, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey1) + " was deleted and should not have been. Status is " + tl_status_string(status)).c_str());        
    
    free_stringlist(keylist);
    keylist = NULL;
    
    alex_id->fpr = pubkey2;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_unknown, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey2, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey2) + " was deleted and should not have been. Status is " + tl_status_string(status)).c_str());        

    free_stringlist(keylist);
    keylist = NULL;

    alex_id->fpr = pubkey3;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_mistrusted, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey3, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey3) + " was deleted and should not have been. Status is " + tl_status_string(status)).c_str());        

    free_stringlist(keylist);
    keylist = NULL;

    alex_id->fpr = pubkey4;
    status = get_trust(session, alex_id);    
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_mistrusted, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey4, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey4) + " was deleted and should not have been. Status is " + tl_status_string(status)).c_str());        

    free_stringlist(keylist);
    keylist = NULL;

    alex_id->fpr = NULL;
    status = myself(session, alex_id);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    TEST_ASSERT(alex_id->fpr);
    TEST_ASSERT(strcmp(alex_id->fpr, pubkey1));
    TEST_ASSERT(strcmp(alex_id->fpr, pubkey2));
    TEST_ASSERT(strcmp(alex_id->fpr, pubkey3));
    TEST_ASSERT(strcmp(alex_id->fpr, pubkey4));
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_pEp, tl_ct_string(alex_id->comm_type));
    
    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}

void KeyResetMessageTests::check_reset_all_own_no_own() {
      char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
      char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
      char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
      char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

      pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                            NULL,
                                            "AlexID",
                                            "Alexander Braithwaite");

/*                                          
test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc
test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc
test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc
test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc
*/
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");

    alex_id->fpr = pubkey1;
    status = trust_personal_key(session, alex_id);
    alex_id->fpr = pubkey3;
    status = trust_personal_key(session, alex_id);
    alex_id->fpr = pubkey4;
    status = trust_personal_key(session, alex_id);

    status = key_reset_all_own_keys(session);
    TEST_ASSERT_MSG(status == PEP_CANNOT_FIND_IDENTITY, tl_status_string(status));

    stringlist_t* keylist = NULL;

    alex_id->fpr = pubkey1;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_OpenPGP, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey1, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey1) + " was deleted and should not have been").c_str());        

    free_stringlist(keylist);
    keylist = NULL;
    
    alex_id->fpr = pubkey2;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_unknown, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey2, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey2) + " was deleted and should not have been").c_str());        

    alex_id->fpr = pubkey3;
    status = get_trust(session, alex_id);
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_OpenPGP, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey3, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey3) + " was deleted and should not have been").c_str());        

    alex_id->fpr = pubkey4;
    status = get_trust(session, alex_id);    
    TEST_ASSERT_MSG(alex_id->comm_type == PEP_ct_OpenPGP, tl_ct_string(alex_id->comm_type));
    status = find_keys(session, pubkey4, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value),
                    (string(pubkey4) + " was deleted and should not have been").c_str());        

    // next line is for readability.
    alex_id->fpr = NULL;
    free_stringlist(keylist);
    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);

}
