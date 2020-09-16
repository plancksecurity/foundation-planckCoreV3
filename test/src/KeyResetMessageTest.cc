// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <assert.h>
#include <iostream>
#include <fstream>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "mime.h"
#include "keymanagement.h"
#include "key_reset.h"

#include "test_util.h"
#include "TestConstants.h"


#include "Engine.h"

#include <gtest/gtest.h>

PEP_STATUS KRMT_message_send_callback(message* msg);
PEP_STATUS KRMT_ensure_passphrase_callback(PEP_SESSION session, const char* key);

static void* KRMT_fake_this;

//The fixture for KeyResetMessageTest
class KeyResetMessageTest : public ::testing::Test {
    public:
        Engine* engine;
        PEP_SESSION session;

        vector<message*> m_queue;
        vector<string> pass_list;

    protected:

        const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
        const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
        const char* carol_fpr = "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42";
        const char* dave_fpr = "E8AC9779A2D13A15D8D55C84B049F489BB5BCCF6";
        const char* erin_fpr = "1B0E197E8AE66277B8A024B9AEA69F509F8D7CBA";
        const char* fenris_fpr = "0969FA229DF21C832A64A04711B1B9804F3D2900";

        const char* alice_receive_reset_fpr = "9B3CC93A689B1167082A90C80766A463E439CB71";

        const string alice_user_id = PEP_OWN_USERID;
        const string bob_user_id = "BobId";
        const string carol_user_id = "carolId";
        const string dave_user_id = "DaveId";
        const string erin_user_id = "ErinErinErin";
        const string fenris_user_id = "BadWolf";

        const char* bob2_filename = "test_keys/bob-primary-with-password-bob-subkey-without.pgp";
        const char* bob2_fpr = "5C76378A62B04CF3F41BEC8D4940FC9FA1878736";

        const char* alice2_filename = "test_keys/alice-no-passwords.pgp";
        const char* alice2_fpr = "03AF88F728B8E9AADA7F370BD41801C62A649B9F";

        const char* erwin_filename = "test_keys/erwin_normal_encrypted.pgp";
        const char* erwin_fpr = "CBA968BC01FCEB89F04CCF155C5E9E3F0420A570";

        // You can remove any or all of the following functions if its body
        // is empty.
        KeyResetMessageTest() {
            // You can do set-up work for each test here.
            test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
            test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
            test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
        }

        ~KeyResetMessageTest() override {
            // You can do clean-up work that doesn't throw exceptions here.
        }

        // If the constructor and destructor are not enough for setting up
        // and cleaning up each test, you can define the following methods:

        void SetUp() override {
            // Code here will be called immediately after the constructor (right
            // before each test).

            KRMT_fake_this = (void*)this;
            // Leave this empty if there are no files to copy to the home directory path
            std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

            // Get a new test Engine.
            engine = new Engine(test_path);
            ASSERT_NOTNULL(engine);

            // Ok, let's initialize test directories etc.
            engine->prep(&KRMT_message_send_callback, NULL, &KRMT_ensure_passphrase_callback, init_files);

            // Ok, try to start this bugger.
            engine->start();
            ASSERT_NOTNULL(engine->session);
            session = engine->session;

            // Engine is up. Keep on truckin'
            m_queue.clear();
            pass_list.clear();
        }

        void TearDown() override {
            // Code here will be called immediately after each test (right
            // before the destructor).
            KRMT_fake_this = NULL;
            engine->shut_down();
            delete engine;
            engine = NULL;
            session = NULL;
        }

        void send_setup() {
            // Setup own identity
            PEP_STATUS status = read_file_and_import_key(session,
                        "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
            assert(status == PEP_KEY_IMPORTED);
            status = set_up_ident_from_scratch(session,
                        "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                        "pep.test.alice@pep-project.org", alice_fpr,
                        alice_user_id.c_str(), "Alice in Wonderland", NULL, true
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                        "pep.test.bob@pep-project.org", bob_fpr, bob_user_id.c_str(), "Bob's Burgers",
                        NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc",
                        "pep-test-carol@pep-project.org", carol_fpr, carol_user_id.c_str(), "Carol Burnett",
                        NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-dave-0xBB5BCCF6_pub.asc",
                        "pep-test-dave@pep-project.org", dave_fpr, dave_user_id.c_str(),
                        "David Hasselhoff (Germans Love Me)", NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-erin-0x9F8D7CBA_pub.asc",
                        "pep-test-erin@pep-project.org", erin_fpr, erin_user_id.c_str(),
                        "Éirinn go Brách", NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep.test.fenris-0x4F3D2900_pub.asc",
                        "pep.test.fenris@thisstilldoesntwork.lu", fenris_fpr, fenris_user_id.c_str(),
                        "Fenris Leto Hawke", NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);
        }

        void receive_setup() {
            PEP_STATUS status = read_file_and_import_key(session,
                        "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
            assert(status == PEP_KEY_IMPORTED);
            status = set_up_ident_from_scratch(session,
                        "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc",
                        "pep.test.bob@pep-project.org", bob_fpr,
                        bob_user_id.c_str(), "Robert Redford", NULL, true
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc",
                        "pep.test.alice@pep-project.org", alice_fpr, alice_user_id.c_str(), "Alice in Wonderland",
                        NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);
        }

        void create_msg_for_revoked_key() {
            PEP_STATUS status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-gabrielle-0xE203586C_pub.asc",
                        "pep-test-gabrielle@pep-project.org", NULL, PEP_OWN_USERID,
                        "Gabi", NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);
            status = set_up_ident_from_scratch(session,
                        "test_keys/priv/pep-test-gabrielle-0xE203586C_priv.asc",
                        "pep-test-gabrielle@pep-project.org", NULL, PEP_OWN_USERID,
                        "Gabi", NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc",
                        "pep.test.alice@pep-project.org", NULL, "AliceOther", "Alice in Wonderland",
                        NULL, false
                    );

            pEp_identity* from_ident = new_identity("pep-test-gabrielle@pep-project.org", NULL, PEP_OWN_USERID, NULL);
            status = myself(session, from_ident);
            ASSERT_OK;
            ASSERT_NOTNULL(from_ident->fpr);
            ASSERT_STRCASEEQ(from_ident->fpr, "906C9B8349954E82C5623C3C8C541BD4E203586C");
            ASSERT_TRUE(from_ident->me);

            // "send" some messages to update the social graph entries
            identity_list* send_idents =
                new_identity_list(
                    new_identity("pep.test.alice@pep-project.org", NULL, "AliceOther", NULL));
            status = update_identity(session, send_idents->ident);
            ASSERT_OK;
            status = set_as_pEp_user(session, send_idents->ident);

            message* outgoing_msg = new_message(PEP_dir_outgoing);
            ASSERT_NOTNULL(outgoing_msg);
            outgoing_msg->from = from_ident;
            outgoing_msg->to = send_idents;
            outgoing_msg->shortmsg = strdup("Well isn't THIS a useless message...");
            outgoing_msg->longmsg = strdup("Hi Mom...\n");
            outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
            output_stream << "Message created.\n\n";
            output_stream << "Encrypting message as MIME multipart…\n";
            message* enc_outgoing_msg = nullptr;
            output_stream << "Calling encrypt_message()\n";
            status = encrypt_message(session, outgoing_msg, NULL, &enc_outgoing_msg, PEP_enc_PGP_MIME, 0);
            ASSERT_OK;
            ASSERT_NOTNULL(enc_outgoing_msg);
            output_stream << "Message encrypted.\n";
            char* outstring = NULL;
            mime_encode_message(enc_outgoing_msg, false, &outstring, false);
            output_stream << outstring << endl;
            free_message(enc_outgoing_msg);
            free(outstring);
        }

    private:
        const char* test_suite_name;
        const char* test_name;
        string test_path;
        // Objects declared here can be used by all tests in the KeyResetMessageTest suite.

};

PEP_STATUS KRMT_message_send_callback(message* msg) {
    ((KeyResetMessageTest*)KRMT_fake_this)->m_queue.push_back(msg);
    return PEP_STATUS_OK;
}

PEP_STATUS KRMT_ensure_passphrase_callback(PEP_SESSION session, const char* fpr) {
    return config_valid_passphrase(session, fpr, ((KeyResetMessageTest*)KRMT_fake_this)->pass_list);
}

TEST_F(KeyResetMessageTest, check_reset_key_and_notify) {
    send_setup();

    pEp_identity* from_ident = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    PEP_STATUS status = myself(session, from_ident);
    ASSERT_OK;
    ASSERT_NOTNULL(from_ident->fpr);
    ASSERT_STRCASEEQ(from_ident->fpr, alice_fpr);
    ASSERT_TRUE(from_ident->me);

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
        
        // Poor Bob. He doesn't get to be a pEp user.
        if (strcmp(curr_ident->ident->user_id, bob_user_id.c_str()) == 0)
            continue;

        status = set_as_pEp_user(session, curr_ident->ident);
        ASSERT_OK;
    }

    output_stream << "Creating outgoing message to update DB" << endl;
    message* outgoing_msg = new_message(PEP_dir_outgoing);
    ASSERT_NOTNULL(outgoing_msg);
    outgoing_msg->from = from_ident;
    outgoing_msg->to = send_idents;
    outgoing_msg->shortmsg = strdup("Well isn't THIS a useless message...");
    outgoing_msg->longmsg = strdup("Hi Mom...\n");
    // outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    // that's illegal - VB.
    output_stream << "Message created.\n\n";
    output_stream << "Encrypting message as MIME multipart…\n";
    message* enc_outgoing_msg = nullptr;
    output_stream << "Calling encrypt_message()\n";
    status = encrypt_message(session, outgoing_msg, NULL, &enc_outgoing_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_outgoing_msg);
    output_stream << "Message encrypted.\n";

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
    ASSERT_EQ(int_result , SQLITE_OK);

    status = key_reset(session, alice_fpr, from_ident);
    ASSERT_OK;
    ASSERT_GT(m_queue.size(), 0);
    status = myself(session, from_ident);
    string new_fpr = from_ident->fpr;
    ASSERT_STRNE(alice_fpr, new_fpr.c_str());

    unordered_map<string, bool> hashmap;
    hashmap[alice_user_id] = false;
    hashmap[bob_user_id] = false;
    hashmap[carol_user_id] = false;
    hashmap[dave_user_id] = false;
    hashmap[erin_user_id] = false;
    hashmap[fenris_user_id] = false;

    // Number of messages we SHOULD be sending.
    ASSERT_EQ(m_queue.size(), 3);

    for (vector<message*>::iterator it = m_queue.begin(); it != m_queue.end(); it++) {
        message* curr_sent_msg = *it;
        ASSERT_NOTNULL(curr_sent_msg);
        ASSERT_NOTNULL(curr_sent_msg->to);
        ASSERT_NOTNULL(curr_sent_msg->to->ident);
        ASSERT_NULL(curr_sent_msg->to->next);
        pEp_identity* to = curr_sent_msg->to->ident;
        ASSERT_NOTNULL(to);
        ASSERT_NOTNULL(to->user_id);

        unordered_map<string, bool>::iterator jt = hashmap.find(to->user_id);

        ASSERT_NE(jt, hashmap.end());
        hashmap[jt->first] = true;

        // Uncomment to regenerate received message - remember to update
        // alice_receive_reset_fpr
        if (false) {
            output_stream << "WARNING: alice_receive_reset_fpr is now " << new_fpr << endl;
            output_stream << "PLEASE CHANGE THE VALUE IN KeyResetMessageTest.cc!!!!" << endl;
            if (strcmp(curr_sent_msg->to->ident->user_id, bob_user_id.c_str()) == 0) {
                ofstream outfile;
                outfile.open("test_files/398_reset_from_alice_to_bob.eml");
                char* bob_msg = NULL;
                mime_encode_message(curr_sent_msg, false, &bob_msg, false);
                outfile << bob_msg;
                outfile.close();
            }
            else if (strcmp(curr_sent_msg->to->ident->user_id, fenris_user_id.c_str()) == 0) {
                ofstream outfile;
                outfile.open("test_files/398_reset_from_alice_to_fenris.eml");
                char* fenris_msg = NULL;
                mime_encode_message(curr_sent_msg, false, &fenris_msg, false);
                outfile << fenris_msg;
                outfile.close();
            }
        }
    }

    // MESSAGE LIST NOW INVALID.
    m_queue.clear();

    // Make sure we have messages only to desired recips
    ASSERT_FALSE(hashmap[alice_user_id]);
    ASSERT_FALSE(hashmap[bob_user_id]); // non-pEp user
    ASSERT_TRUE(hashmap[carol_user_id]);
    ASSERT_FALSE(hashmap[dave_user_id]);
    ASSERT_TRUE(hashmap[erin_user_id]);
    ASSERT_TRUE(hashmap[fenris_user_id]);
    cout << "HEY! reset_fpr is " << new_fpr << endl;
}


TEST_F(KeyResetMessageTest, check_non_reset_receive_revoked) {
    receive_setup();
    pEp_identity* alice_ident = new_identity("pep.test.alice@pep-project.org", NULL,
                                            alice_user_id.c_str(), NULL);
    PEP_STATUS status = set_fpr_preserve_ident(session, alice_ident, alice_fpr, true);
    ASSERT_OK;
    status = update_identity(session, alice_ident);
    ASSERT_OK;
    ASSERT_STREQ(alice_fpr, alice_ident->fpr);

    string received_mail = slurp("test_files/398_reset_from_alice_to_bob.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    message* enc_msg_obj = NULL;
    message* dec_msg_obj = NULL;
    status = mime_decode_message(received_mail.c_str(), received_mail.size(), &enc_msg_obj, NULL);
    ASSERT_OK;
    status = decrypt_message(session, enc_msg_obj, &dec_msg_obj, &keylist, &rating, &flags);
//    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
//                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);

    ASSERT_OK;

    ASSERT_NOTNULL(keylist);

    // FIXME: key election - right now, this case is intended to fail. But I am not sure it should. Question to fdik on hold.
    /*
    if (keylist) // there's a test option to continue when asserts fail, so...
        ASSERT_STREQ(keylist->value,alice_receive_reset_fpr);

    status = update_identity(session, alice_ident);
    ASSERT_NOTNULL(alice_ident->fpr);
    ASSERT_STREQ(alice_receive_reset_fpr,alice_ident->fpr);
    //keylist = NULL; // WTF?
    */
    free_stringlist(keylist);
}

TEST_F(KeyResetMessageTest, check_reset_receive_revoked) {
    PEP_STATUS status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep.test.fenris-0x4F3D2900_pub.asc",
                "pep.test.fenris@thisstilldoesntwork.lu", fenris_fpr, fenris_user_id.c_str(),
                "Fenris Leto Hawke", NULL, false
            );
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.fenris-0x4F3D2900_priv.asc",
                "pep.test.fenris@thisstilldoesntwork.lu", fenris_fpr, fenris_user_id.c_str(),
                "Fenris Leto Hawke", NULL, true
            );
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc",
                "pep.test.alice@pep-project.org", alice_fpr, "ALICE_IS_NOT_OWN_ID", "Alice in Wonderland",
                NULL, false
            );
    ASSERT_EQ(status, PEP_STATUS_OK);

    pEp_identity* alice_ident = new_identity("pep.test.alice@pep-project.org", NULL,
                                            "ALICE_IS_NOT_OWN_ID", "Alice in Wonderland");

    status = update_identity(session, alice_ident);
    ASSERT_OK;
    ASSERT_STREQ(alice_fpr, alice_ident->fpr);

    string received_mail = slurp("test_files/398_reset_from_alice_to_fenris.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);

    ASSERT_OK;
    ASSERT_NOTNULL(keylist);
    if (keylist) // there's a test option to continue when asserts fail, so...
        ASSERT_STREQ(keylist->value, alice_receive_reset_fpr);

    status = update_identity(session, alice_ident);
    ASSERT_NOTNULL(alice_ident->fpr);
    ASSERT_STREQ(alice_receive_reset_fpr, alice_ident->fpr);

    keylist = NULL;

    free(keylist);
}

TEST_F(KeyResetMessageTest, revoke_and_check_receive_message) {
    pEp_identity* me = new_identity("inquisitor@darthmama.org", NULL, PEP_OWN_USERID, "INQUISITOR");
    string inbox = slurp("test_mails/to_inquisitor_pgp.eml");
    slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");
    slurp_and_import_key(session, "test_keys/priv/inquisitor-0xA4728718_renewed_priv.asc");

    PEP_STATUS status = set_own_key(session, me, "8E8D2381AE066ABE1FEE509821BA977CA4728718");
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = key_reset(session, "8E8D2381AE066ABE1FEE509821BA977CA4728718", me);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = myself(session, me);
    ASSERT_NOTNULL(me->fpr);
    ASSERT_STRNE(me->fpr, "8E8D2381AE066ABE1FEE509821BA977CA4728718");
    ASSERT_EQ(m_queue.size() , 0);
    m_queue.clear();
    
    message* enc_msg = NULL;
    mime_decode_message(inbox.c_str(), inbox.size(), &enc_msg, NULL);
    
    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;
    PEP_rating rating;
    
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_STATUS_OK);        
    ASSERT_NOTNULL(dec_msg);
    ASSERT_EQ(m_queue.size() , 0);
    m_queue.clear();
    free_stringlist(keylist);
    free_message(enc_msg);
    free_message(dec_msg);
}


TEST_F(KeyResetMessageTest, check_receive_message_to_revoked_key_from_unknown) {
    // create_msg_for_revoked_key(); // call to recreate msg
    send_setup();
    pEp_identity* from_ident = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    PEP_STATUS status = myself(session, from_ident);
    ASSERT_OK;
    ASSERT_NOTNULL(from_ident->fpr);
    ASSERT_STRCASEEQ(from_ident->fpr, alice_fpr);
    ASSERT_TRUE(from_ident->me);

    status = key_reset(session, alice_fpr, from_ident);
    ASSERT_OK;
    m_queue.clear();

    string received_mail = slurp("test_files/398_gabrielle_to_alice.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);
    ASSERT_EQ(m_queue.size() , 0);
    free(decrypted_msg);
    free(modified_src);
    free_stringlist(keylist);
    free_identity(from_ident);
}


TEST_F(KeyResetMessageTest, check_receive_message_to_revoked_key_from_contact) {
    // create_msg_for_revoked_key(); // call to recreate msg
    send_setup();
    pEp_identity* from_ident = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    PEP_STATUS status = myself(session, from_ident);
    ASSERT_OK;
    ASSERT_NOTNULL(from_ident->fpr);
    ASSERT_STRCASEEQ(from_ident->fpr, alice_fpr);
    ASSERT_TRUE(from_ident->me);

    // Send Gabrielle a message
    identity_list* send_idents = new_identity_list(new_identity("pep-test-gabrielle@pep-project.org", NULL, "Gabi", "Gabi"));
    output_stream << "Creating outgoing message to update DB" << endl;
    message* outgoing_msg = new_message(PEP_dir_outgoing);
    ASSERT_NOTNULL(outgoing_msg);
    outgoing_msg->from = from_ident;
    outgoing_msg->to = send_idents;
    outgoing_msg->shortmsg = strdup("Well isn't THIS a useless message...");
    outgoing_msg->longmsg = strdup("Hi Mom...\n");
    outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    output_stream << "Message created.\n\n";
    output_stream << "Encrypting message as MIME multipart…\n";
    message* enc_outgoing_msg = nullptr;
    output_stream << "Calling encrypt_message()\n";
    status = encrypt_message(session, outgoing_msg, NULL, &enc_outgoing_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status , PEP_UNENCRYPTED);
    //
    output_stream << "Message created." << endl;

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
    ASSERT_EQ(int_result , SQLITE_OK);

    // FIXME: longer term we need to fix the test, but the key attached to the message below has expired, so for now, we give her a new key
    slurp_and_import_key(session, "test_keys/pub/pep-test-gabrielle-0xE203586C_pub.asc");

    status = key_reset(session, alice_fpr, from_ident);
    ASSERT_OK;
    ASSERT_EQ(m_queue.size() , 0);
    m_queue.clear();

    // Now we get mail from Gabi, who only has our old key AND has become
    // a pEp user in the meantime...
    string received_mail = slurp("test_files/398_gabrielle_to_alice.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);

    ASSERT_EQ(m_queue.size() , 1);
    vector<message*>::iterator it = m_queue.begin();
    message* reset_msg = *it;
    ASSERT_NOTNULL(reset_msg);
    ASSERT_NOTNULL(reset_msg->from);
    ASSERT_NOTNULL(reset_msg->to);
    ASSERT_NOTNULL(reset_msg->to->ident);
    ASSERT_STREQ(reset_msg->to->ident->address, "pep-test-gabrielle@pep-project.org");
    ASSERT_STREQ(reset_msg->to->ident->fpr, "906C9B8349954E82C5623C3C8C541BD4E203586C");
    ASSERT_STRNE(reset_msg->from->fpr, alice_fpr);
    ASSERT_NOTNULL(keylist);
    ASSERT_NOTNULL(keylist->value);
    ASSERT_STRNE(keylist->value, alice_fpr);
    ASSERT_NOTNULL(keylist->next);
    if (strcmp(keylist->next->value, "906C9B8349954E82C5623C3C8C541BD4E203586C") != 0) {
        ASSERT_NOTNULL(keylist->next->next);
        ASSERT_STREQ(keylist->next->value, "906C9B8349954E82C5623C3C8C541BD4E203586C");
    }
}


TEST_F(KeyResetMessageTest, check_multiple_resets_single_key) {
    send_setup();

    pEp_identity* from_ident = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    PEP_STATUS status = myself(session, from_ident);
    ASSERT_OK;
    ASSERT_NOTNULL(from_ident->fpr);
    ASSERT_STRCASEEQ(from_ident->fpr, alice_fpr);
    ASSERT_TRUE(from_ident->me);

    status = key_reset(session, NULL, NULL);
    ASSERT_OK;

    status = key_reset(session, NULL, NULL);
    ASSERT_OK;

    status = myself(session, from_ident);
    ASSERT_OK;
    ASSERT_TRUE(from_ident->fpr != NULL && from_ident->fpr[0] != 0);
}


TEST_F(KeyResetMessageTest, check_reset_ident_uid_only) {
    send_setup(); // lazy
    pEp_identity* bob = new_identity(NULL, NULL, bob_user_id.c_str(), NULL);

    // Ok, let's reset it
    PEP_STATUS status = key_reset_identity(session, bob, NULL);
    ASSERT_EQ(status , PEP_ILLEGAL_VALUE);
}


TEST_F(KeyResetMessageTest, check_reset_ident_address_only) {
    send_setup(); // lazy
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, NULL, NULL);

    PEP_STATUS status = key_reset_identity(session, bob, NULL);
    ASSERT_EQ(status , PEP_ILLEGAL_VALUE);
}


TEST_F(KeyResetMessageTest, check_reset_ident_null_ident) {
    // Ok, let's reset it
    PEP_STATUS status = key_reset_identity(session, NULL, NULL);
    ASSERT_EQ(status , PEP_ILLEGAL_VALUE);
}

TEST_F(KeyResetMessageTest, check_reset_grouped_own) {
    send_setup(); // lazy
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), NULL);
    PEP_STATUS status = myself(session, alice);

    ASSERT_OK;
    ASSERT_TRUE(alice->fpr && alice->fpr[0]);
    ASSERT_TRUE(alice->me);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    
    char* main_key = NULL;
    status = get_main_user_fpr(session, alice->user_id, &main_key);
    ASSERT_STREQ(main_key, alice_fpr);        

    status = set_identity_flags(session, alice, alice->flags | PEP_idf_devicegroup);
    status = key_reset_identity(session, alice, alice_fpr);
    status = myself(session, alice);
    ASSERT_OK;
    char* alice_new_fpr = alice->fpr;
    ASSERT_TRUE(alice_new_fpr && alice_new_fpr[0]);
    ASSERT_STRNE(alice_fpr, alice_new_fpr);

    main_key = NULL;
    status = get_main_user_fpr(session, alice->user_id, &main_key);
    ASSERT_STRNE(main_key, alice_fpr);


    ASSERT_EQ(m_queue.size(), 1);

    if (false) {
        ofstream outfile;
        outfile.open("test_mails/check_reset_grouped_own_recv.eml");
        message* curr_sent_msg = m_queue.at(0);
        char* msg_txt = NULL;
        mime_encode_message(curr_sent_msg, false, &msg_txt, false);
        outfile << msg_txt;
        outfile.close();
        cout << "    ASSERT_STREQ(alice->fpr, \"" << alice_new_fpr << "\");" << endl;
        
        // Check what we have here, because it looks wrong
        char* ptext = NULL;
        stringlist_t* _keylist;
        size_t psize = 0;
        status = decrypt_and_verify(session, curr_sent_msg->attachments->next->value,
                                                       strlen(curr_sent_msg->attachments->next->value), NULL, 0,
                                                       &ptext, &psize, &_keylist,
                                                       NULL);
        message* inner_msg = NULL;
        status = mime_decode_message(ptext, psize, &inner_msg, NULL);
        
        bloblist_t* key_reset_payload = inner_msg->attachments;  
        message* keyreset_msg = NULL;
        status = mime_decode_message(key_reset_payload->value, key_reset_payload->size, &keyreset_msg, NULL);
        keyreset_command_list* cl = NULL;
        status = PER_to_key_reset_commands(keyreset_msg->attachments->value, keyreset_msg->attachments->size, &cl);                                             
        ASSERT_NOTNULL(cl);
        ASSERT_STREQ(cl->command->ident->address, "pep.test.alice@pep-project.org");
        ASSERT_STREQ(cl->command->ident->fpr, alice_fpr);        
        ASSERT_STREQ(cl->command->new_key, alice_new_fpr);                
        ASSERT_NULL(cl->next);
    }
}

TEST_F(KeyResetMessageTest, check_reset_grouped_own_recv) {
    send_setup(); // lazy
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), NULL);
    PEP_STATUS status = myself(session, alice);

    ASSERT_OK;
    ASSERT_TRUE(alice->fpr && alice->fpr[0]);
    ASSERT_TRUE(alice->me);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    
    char* main_key = NULL;
    status = get_main_user_fpr(session, alice->user_id, &main_key);
    ASSERT_STREQ(main_key, alice_fpr);    

    status = set_identity_flags(session, alice, alice->flags | PEP_idf_devicegroup);
    ASSERT_OK;
    status = myself(session, alice);
    ASSERT_OK;

    string received_mail = slurp("test_mails/check_reset_grouped_own_recv.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);

    status = myself(session, alice);
    ASSERT_OK;
    ASSERT_STRNE(alice->fpr, alice_fpr);
    ASSERT_STREQ(alice->fpr, "924DFC739144B9A6060A92D6EE9B17DF9E1B5A1B");
    bool revoked = false;
    status = key_revoked(session, alice_fpr, &revoked);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(revoked);

    main_key = NULL;
    status = get_main_user_fpr(session, alice->user_id, &main_key);
    ASSERT_STRNE(main_key, alice_fpr);
    ASSERT_STREQ(alice->fpr, "924DFC739144B9A6060A92D6EE9B17DF9E1B5A1B");
}

TEST_F(KeyResetMessageTest, check_reset_grouped_own_multi_ident_one_fpr) {
    char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");

    pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                        NULL,
                                        "AlexID",
                                        "Alexander Braithwaite");

    pEp_identity* alex_id2 = new_identity("pep.test.alexander6@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");

    pEp_identity* alex_id3 = new_identity("pep.test.alexander6a@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");

    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id, alex_id->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id2->me = true;
    status = set_own_key(session, alex_id2, pubkey1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id2, alex_id2->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id3->me = true;
    status = set_own_key(session, alex_id3, pubkey1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id3, alex_id3->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id3->fpr);

    status = key_reset_identity(session, alex_id, pubkey1);

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey1);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_mistrusted);

    bool revoked = false;
    status = key_revoked(session, pubkey1, &revoked);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(revoked);

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(pubkey1, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(pubkey1, alex_id3->fpr);

    ASSERT_STRNE(alex_id->fpr, alex_id2->fpr);
    ASSERT_STRNE(alex_id->fpr, alex_id3->fpr);
    ASSERT_STRNE(alex_id2->fpr, alex_id3->fpr);

    ASSERT_EQ(m_queue.size(),1);
    if (false) {
        ofstream outfile;
        message* curr_sent_msg = m_queue.at(0);        
        string fname = "test_mails/check_reset_grouped_own_multi_ident_one_fpr.eml";
        outfile.open(fname);
        char* msg_txt = NULL;
        mime_encode_message(curr_sent_msg, false, &msg_txt, false);
        outfile << msg_txt;
        outfile.close();        
        cout <<  "    // check_reset_grouped_own_multi_ident_one_fpr_recv" << endl;
        cout <<  "    const char* replkey1 = \"" << alex_id->fpr << "\";" << endl;    
        cout <<  "    const char* replkey2 = \"" << alex_id2->fpr << "\";" << endl;    
        cout <<  "    const char* replkey3 = \"" << alex_id3->fpr << "\";" << endl;        
    }    

    free_identity(alex_id);
    free_identity(alex_id2);
    free_identity(alex_id3);
}

TEST_F(KeyResetMessageTest, check_reset_grouped_own_multi_ident_one_fpr_recv) {
    PEP_STATUS status = PEP_STATUS_OK;
    
    // check_reset_grouped_own_multi_ident_one_fpr_recv
    const char* replkey1 = "BC8037710E12554418BAF475402E6E25F05AD93E";
    const char* replkey2 = "966CCF30267B521BD63365D2514B67B7EFAE8417";
    const char* replkey3 = "82D78C9C0071FF287EE854FCAF7A21CFC49C2C5C";
    
    // set up device own state
    char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");

    pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                        NULL,
                                        "AlexID",
                                        "Alexander Braithwaite");

    pEp_identity* alex_id2 = new_identity("pep.test.alexander6@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");

    pEp_identity* alex_id3 = new_identity("pep.test.alexander6a@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");

    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id, alex_id->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id2->me = true;
    status = set_own_key(session, alex_id2, pubkey1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id2, alex_id2->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id3->me = true;
    status = set_own_key(session, alex_id3, pubkey1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id3, alex_id3->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id3->fpr);

    // receive reset messages
    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    string fname = "test_mails/check_reset_grouped_own_multi_ident_one_fpr.eml";
    string mailstr = slurp(fname.c_str());
    message* new_msg = NULL;
    status = mime_decode_message(mailstr.c_str(), mailstr.size(), &new_msg, NULL);
    ASSERT_NOTNULL(new_msg);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = decrypt_message(session, new_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_STATUS_OK);        

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(replkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(replkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(replkey3, alex_id3->fpr);
}

TEST_F(KeyResetMessageTest, check_reset_grouped_own_multiple_keys_multiple_idents_reset_all) {
    char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
    char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
    char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");

    pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                        NULL,
                                        "AlexID",
                                        "Alexander Braithwaite");

    pEp_identity* alex_id2 = new_identity("pep.test.alexander6@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");

    pEp_identity* alex_id3 = new_identity("pep.test.alexander6a@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");


    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id, alex_id->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id2->me = true;
    status = set_own_key(session, alex_id2, pubkey2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id2, alex_id2->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id3->me = true;
    status = set_own_key(session, alex_id3, pubkey3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id3, alex_id3->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey3, alex_id3->fpr);

    status = key_reset_all_own_keys(session);

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey1);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_mistrusted);

    free(alex_id2->fpr);
    alex_id2->fpr = strdup(pubkey2);
    status = get_trust(session, alex_id2);
    ASSERT_EQ(alex_id2->comm_type , PEP_ct_mistrusted);

    free(alex_id3->fpr);
    alex_id3->fpr = strdup(pubkey3);
    status = get_trust(session, alex_id3);
    ASSERT_EQ(alex_id3->comm_type , PEP_ct_mistrusted);

    bool revoked = false;
    status = key_revoked(session, pubkey1, &revoked);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(revoked);

    revoked = false;
    status = key_revoked(session, pubkey2, &revoked);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(revoked);

    revoked = false;
    status = key_revoked(session, pubkey3, &revoked);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(revoked);

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(pubkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(pubkey3, alex_id3->fpr);

    // Not reaaaally necessary, but...
    ASSERT_STRNE(alex_id->fpr, alex_id2->fpr);
    ASSERT_STRNE(alex_id->fpr, alex_id3->fpr);
    ASSERT_STRNE(alex_id2->fpr, alex_id3->fpr);

    ASSERT_EQ(m_queue.size(),3);
    if (false) {
        ofstream outfile;
        int i = 0;
        for (vector<message*>::iterator it = m_queue.begin(); it != m_queue.end(); it++, i++) {
            message* curr_sent_msg = *it;        
            string fname = string("test_mails/check_reset_grouped_own_multiple_keys_multiple_idents_reset_all_") + to_string(i) + ".eml";
            outfile.open(fname);
            char* msg_txt = NULL;
            mime_encode_message(curr_sent_msg, false, &msg_txt, false);
            outfile << msg_txt;
            outfile.close();        
        }
        cout <<  "    // check_reset_grouped_own_multiple_keys_multiple_idents_reset_all_recv" << endl;        
        cout <<  "    // For " << alex_id->address << endl;
        cout <<  "    const char* replkey1 = \"" << alex_id->fpr << "\";" << endl;    
        cout <<  "    // For " << alex_id2->address << endl;        
        cout <<  "    const char* replkey2 = \"" << alex_id2->fpr << "\";" << endl;    
        cout <<  "    // For " << alex_id3->address << endl;        
        cout <<  "    const char* replkey3 = \"" << alex_id3->fpr << "\";" << endl;        
    }    

    free_identity(alex_id);
    free_identity(alex_id2);
    free_identity(alex_id3);
}

TEST_F(KeyResetMessageTest, check_reset_all_own_grouped) {
    char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
    char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
    char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");

    pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                        NULL,
                                        "AlexID",
                                        "Alexander Braithwaite");

    pEp_identity* alex_id2 = new_identity("pep.test.alexander6@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");

    pEp_identity* alex_id3 = new_identity("pep.test.alexander6a@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");


    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id, alex_id->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id2->me = true;
    status = set_own_key(session, alex_id2, pubkey2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id2, alex_id2->flags | PEP_idf_not_for_sync);
    ASSERT_OK;

    alex_id3->me = true;
    status = set_own_key(session, alex_id3, pubkey3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id3, alex_id3->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey3, alex_id3->fpr);

    status = key_reset_own_grouped_keys(session);

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey1);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_mistrusted);

    free(alex_id2->fpr);
    alex_id2->fpr = strdup(pubkey2);
    status = get_trust(session, alex_id2);
    ASSERT_EQ(alex_id2->comm_type , PEP_ct_pEp);

    free(alex_id3->fpr);
    alex_id3->fpr = strdup(pubkey3);
    status = get_trust(session, alex_id3);
    ASSERT_EQ(alex_id3->comm_type , PEP_ct_mistrusted);

    bool revoked = false;
    status = key_revoked(session, pubkey1, &revoked);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(revoked);

    revoked = false;
    status = key_revoked(session, pubkey2, &revoked);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_FALSE(revoked);

    revoked = false;
    status = key_revoked(session, pubkey3, &revoked);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(revoked);

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(pubkey3, alex_id3->fpr);

    ASSERT_EQ(m_queue.size(),2);
    if (false) {
        ofstream outfile;
        int i = 0;
        for (vector<message*>::iterator it = m_queue.begin(); it != m_queue.end(); it++, i++) {
            message* curr_sent_msg = *it;        
            string fname = string("test_mails/check_reset_all_own_grouped") + to_string(i) + ".eml";
            outfile.open(fname);
            char* msg_txt = NULL;
            mime_encode_message(curr_sent_msg, false, &msg_txt, false);
            outfile << msg_txt;
            outfile.close();        
        }
        cout <<  "    // For " << alex_id->address << endl;
        cout <<  "    const char* replkey1 = \"" << alex_id->fpr << "\";" << endl;    
        cout <<  "    // For " << alex_id3->address << endl;        
        cout <<  "    const char* replkey3 = \"" << alex_id3->fpr << "\";" << endl;        
    }    

    free_identity(alex_id);
    free_identity(alex_id2);
    free_identity(alex_id3);
}

TEST_F(KeyResetMessageTest, check_reset_all_own_grouped_recv) {
    PEP_STATUS status = PEP_STATUS_OK;
    char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
    char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
    char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");

    // For pep.test.alexander@darthmama.org
    const char* replkey1 = "0F9C2FBFB898AD3A1242257F300EFFDE4CE2C33F";
    // For pep.test.alexander6a@darthmama.org
    const char* replkey3 = "3671C09D3C79260C65045AE9A62A64E4CBEDAFDA";
        
    pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                        NULL,
                                        "AlexID",
                                        "Alexander Braithwaite");

    pEp_identity* alex_id2 = new_identity("pep.test.alexander6@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");

    pEp_identity* alex_id3 = new_identity("pep.test.alexander6a@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");


    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id, alex_id->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id2->me = true;
    status = set_own_key(session, alex_id2, pubkey2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id2, alex_id2->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id3->me = true;
    status = set_own_key(session, alex_id3, pubkey3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id3, alex_id3->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey3, alex_id3->fpr);

    char* old_main_key = NULL;
    status = get_main_user_fpr(session, "AlexID", &old_main_key);
    ASSERT_NOTNULL(old_main_key);


    const int num_msgs = 2;
    for (int i = 0; i < num_msgs; i++) {
        // receive reset messages
        message* dec_msg = NULL;
        stringlist_t* keylist = NULL;
        PEP_rating rating;
        PEP_decrypt_flags_t flags = 0;

        string fname = string("test_mails/check_reset_all_own_grouped") + to_string(i) + ".eml";
        string mailstr = slurp(fname.c_str());
        message* new_msg = NULL;
        status = mime_decode_message(mailstr.c_str(), mailstr.size(), &new_msg, NULL);
        ASSERT_NOTNULL(new_msg);
        ASSERT_EQ(status, PEP_STATUS_OK);

        status = decrypt_message(session, new_msg, &dec_msg, &keylist, &rating, &flags);
        ASSERT_EQ(status, PEP_STATUS_OK);        
    }

    char* new_main_key = NULL;
    status = get_main_user_fpr(session, "AlexID", &new_main_key);
    ASSERT_STRNE(old_main_key, new_main_key);

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(replkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(replkey3, alex_id3->fpr);
}

TEST_F(KeyResetMessageTest, check_reset_grouped_own_multiple_keys_multiple_idents_reset_all_recv) {
    PEP_STATUS status = PEP_STATUS_OK;
    char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
    char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
    char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");

    // check_reset_grouped_own_multiple_keys_multiple_idents_reset_all
    // For pep.test.alexander@darthmama.org
    const char* replkey1 = "16F48D6762AF45EC975C9AFBF749EC76C057320A";
    // For pep.test.alexander6@darthmama.org
    const char* replkey2 = "7FD82B86E27D6720CC2F9662DA3C4948313AFDAC";
    // For pep.test.alexander6a@darthmama.org
    const char* replkey3 = "CD270BBF3E9B086BA667B3BF5183787E27DC58FD";
            
    pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                        NULL,
                                        "AlexID",
                                        "Alexander Braithwaite");

    pEp_identity* alex_id2 = new_identity("pep.test.alexander6@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");

    pEp_identity* alex_id3 = new_identity("pep.test.alexander6a@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");


    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id, alex_id->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id2->me = true;
    status = set_own_key(session, alex_id2, pubkey2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id2, alex_id2->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id3->me = true;
    status = set_own_key(session, alex_id3, pubkey3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id3, alex_id3->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey3, alex_id3->fpr);

    const int num_msgs = 3;
    for (int i = 0; i < num_msgs; i++) {
        // receive reset messages
        message* dec_msg = NULL;
        stringlist_t* keylist = NULL;
        PEP_rating rating;
        PEP_decrypt_flags_t flags = 0;

        string fname = string("test_mails/check_reset_grouped_own_multiple_keys_multiple_idents_reset_all_") + to_string(i) + ".eml";
        string mailstr = slurp(fname.c_str());
        message* new_msg = NULL;
        status = mime_decode_message(mailstr.c_str(), mailstr.size(), &new_msg, NULL);
        ASSERT_NOTNULL(new_msg);
        ASSERT_EQ(status, PEP_STATUS_OK);

        status = decrypt_message(session, new_msg, &dec_msg, &keylist, &rating, &flags);
        ASSERT_EQ(status, PEP_STATUS_OK);        
    }

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(replkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(replkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(replkey3, alex_id3->fpr);
}


TEST_F(KeyResetMessageTest, check_reset_grouped_own_multiple_keys_multiple_idents_reset_one) {
    char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
    char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
    char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");

    pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                        NULL,
                                        "AlexID",
                                        "Alexander Braithwaite");

    pEp_identity* alex_id2 = new_identity("pep.test.alexander6@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");

    pEp_identity* alex_id3 = new_identity("pep.test.alexander6a@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");


    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id2, alex_id2->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id2->me = true;
    status = set_own_key(session, alex_id2, pubkey2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id2, alex_id2->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id3->me = true;
    status = set_own_key(session, alex_id3, pubkey3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id2, alex_id2->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey3, alex_id3->fpr);

    status = key_reset_identity(session, alex_id2, alex_id2->fpr);

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey1);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_pEp);

    free(alex_id2->fpr);
    alex_id2->fpr = strdup(pubkey2);
    status = get_trust(session, alex_id2);
    ASSERT_EQ(alex_id2->comm_type , PEP_ct_mistrusted);

    free(alex_id3->fpr);
    alex_id3->fpr = strdup(pubkey3);
    status = get_trust(session, alex_id3);
    ASSERT_EQ(alex_id3->comm_type , PEP_ct_pEp);

    bool revoked = false;
    status = key_revoked(session, pubkey1, &revoked);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_FALSE(revoked);

    revoked = false;
    status = key_revoked(session, pubkey2, &revoked);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(revoked);

    revoked = false;
    status = key_revoked(session, pubkey3, &revoked);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_FALSE(revoked);

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(pubkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey3, alex_id3->fpr);

    // Not reaaaally necessary, but...
    ASSERT_STRNE(alex_id->fpr, alex_id2->fpr);
    ASSERT_STRNE(alex_id->fpr, alex_id3->fpr);
    ASSERT_STRNE(alex_id2->fpr, alex_id3->fpr);

    ASSERT_EQ(m_queue.size(),1);
    if (false) {
        ofstream outfile;
        message* curr_sent_msg = m_queue.at(0);        
        string fname = "test_mails/check_reset_grouped_own_multiple_keys_multiple_idents_reset_one.eml";
        outfile.open(fname);
        char* msg_txt = NULL;
        mime_encode_message(curr_sent_msg, false, &msg_txt, false);
        outfile << msg_txt;
        outfile.close();   
        cout <<  "    // check_reset_grouped_own_multiple_keys_multiple_idents_reset_one_recv" << endl;  
        cout <<  "    const char* replkey2 = \"" << alex_id2->fpr << "\";" << endl;    
    }    
    

    free_identity(alex_id);
    free_identity(alex_id2);
    free_identity(alex_id3);
}

TEST_F(KeyResetMessageTest, check_reset_grouped_own_multiple_keys_multiple_idents_reset_one_recv) {
    char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
    char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
    char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
    
    // check_reset_grouped_own_multiple_keys_multiple_idents_reset_one_recv
    const char* replkey2 = "0D02665E48972A2F383EBE5FE3A14718A47460DB";
    
    pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                        NULL,
                                        "AlexID",
                                        "Alexander Braithwaite");

    pEp_identity* alex_id2 = new_identity("pep.test.alexander6@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");

    pEp_identity* alex_id3 = new_identity("pep.test.alexander6a@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");


    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id2, alex_id2->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id2->me = true;
    status = set_own_key(session, alex_id2, pubkey2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id2, alex_id2->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    alex_id3->me = true;
    status = set_own_key(session, alex_id3, pubkey3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_identity_flags(session, alex_id2, alex_id2->flags | PEP_idf_devicegroup);
    ASSERT_OK;

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey3, alex_id3->fpr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    string fname = "test_mails/check_reset_grouped_own_multiple_keys_multiple_idents_reset_one.eml";
    string mailstr = slurp(fname.c_str());
    message* new_msg = NULL;
    status = mime_decode_message(mailstr.c_str(), mailstr.size(), &new_msg, NULL);
    ASSERT_NOTNULL(new_msg);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = decrypt_message(session, new_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_STATUS_OK);        

    status = myself(session, alex_id);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey1, alex_id->fpr);

    status = myself(session, alex_id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(replkey2, alex_id2->fpr);

    status = myself(session, alex_id3);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(pubkey3, alex_id3->fpr);

    free_identity(alex_id);
    free_identity(alex_id2);
    free_identity(alex_id3);
}


TEST_F(KeyResetMessageTest, check_reset_ident_other_pub_fpr) {
    send_setup(); // lazy
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), NULL);
    PEP_STATUS status = update_identity(session, bob);

    ASSERT_OK;
    ASSERT_TRUE(bob->fpr && bob->fpr[0]);
    status = set_as_pEp_user(session, bob);
    status = trust_personal_key(session, bob);

    status = update_identity(session, bob);
    ASSERT_OK;
    ASSERT_EQ(bob->comm_type , PEP_ct_pEp);

    char* main_key = NULL;
    status = get_main_user_fpr(session, bob->user_id, &main_key);
    ASSERT_STREQ(main_key, bob->fpr);

    
    // Ok, let's reset it
    status = key_reset_identity(session, bob, bob->fpr);
    
    main_key = NULL;
    status = get_main_user_fpr(session, bob->user_id, &main_key);
    ASSERT_EQ(status, PEP_KEY_NOT_FOUND);
    ASSERT_STREQ(main_key, nullptr);
    
    status = update_identity(session, bob);
    ASSERT_OK;
    ASSERT_EQ(bob->comm_type , PEP_ct_key_not_found);
    ASSERT_TRUE(!(bob->fpr) || !(bob->fpr[0]));
    // TODO: import key, verify PEP_ct_OpenPGP_unconfirmed
}


// Corner case?
TEST_F(KeyResetMessageTest, check_reset_ident_other_priv_fpr) {
    send_setup(); // lazy
    // Also import Bob's private key, because that dude is a fool.
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc");
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), NULL);
    status = update_identity(session, bob);

    ASSERT_OK;
    ASSERT_TRUE(bob->fpr && bob->fpr[0]);
    ASSERT_FALSE(bob->me);

    status = set_as_pEp_user(session, bob);
    status = trust_personal_key(session, bob);

    status = update_identity(session, bob);
    ASSERT_OK;
    ASSERT_EQ(bob->comm_type , PEP_ct_pEp);
    ASSERT_FALSE(bob->me);

    // Ok, let's reset it
    status = key_reset_identity(session, bob, bob->fpr);
    status = update_identity(session, bob);
    ASSERT_OK;
    ASSERT_EQ(bob->comm_type , PEP_ct_key_not_found);
    ASSERT_TRUE(!(bob->fpr) || !(bob->fpr[0]));

    // TODO: import key, verify PEP_ct_OpenPGP_unconfirmed
}


TEST_F(KeyResetMessageTest, check_reset_ident_other_pub_no_fpr) {
    send_setup(); // lazy
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), NULL);
    PEP_STATUS status = update_identity(session, bob);

    ASSERT_OK;
    ASSERT_TRUE(bob->fpr && bob->fpr[0]);
    status = set_as_pEp_user(session, bob);
    status = trust_personal_key(session, bob);

    status = update_identity(session, bob);
    ASSERT_OK;
    ASSERT_EQ(bob->comm_type , PEP_ct_pEp);
    free(bob->fpr);
    bob->fpr = NULL;

    // Ok, let's reset it
    status = key_reset_identity(session, bob, NULL);
    status = update_identity(session, bob);
    ASSERT_OK;
    ASSERT_EQ(bob->comm_type , PEP_ct_key_not_found);
    ASSERT_TRUE(!(bob->fpr) || !(bob->fpr[0]));

    // TODO: import key, verify PEP_ct_OpenPGP_unconfirmed
}
//    const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
// TODO: multiplr keys above


TEST_F(KeyResetMessageTest, check_reset_ident_other_priv_no_fpr) {
    send_setup(); // lazy
    // Also import Bob's private key, because that dude is a fool.
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc");
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), NULL);
    status = update_identity(session, bob);

    ASSERT_OK;
    ASSERT_TRUE(bob->fpr && bob->fpr[0]);
    status = set_as_pEp_user(session, bob);
    status = trust_personal_key(session, bob);

    status = update_identity(session, bob);
    ASSERT_OK;
    ASSERT_EQ(bob->comm_type , PEP_ct_pEp);
    ASSERT_FALSE(bob->me);
    free(bob->fpr);
    bob->fpr = NULL;

    // Ok, let's reset it
    status = key_reset_identity(session, bob, NULL);
    status = update_identity(session, bob);
    ASSERT_OK;
    ASSERT_EQ(bob->comm_type , PEP_ct_key_not_found);
    ASSERT_TRUE(!(bob->fpr) || !(bob->fpr[0]));
    ASSERT_FALSE(bob->me);

    // TODO: import key, verify PEP_ct_OpenPGP_unconfirmed
}


// TEST_F(KeyResetMessageTest, check_reset_ident_own_pub_fpr) {
//     send_setup(); // lazy
//     pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), NULL);
//     PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander-0x26B54E4E_pub.asc");

//     // hacky
//     alice->fpr = strdup("3AD9F60FAEB22675DB873A1362D6981326B54E4E");
//     status = set_pgp_keypair(session, alice->fpr);
//     ASSERT_EQ(status , PEP_STATUS_OK);
//     alice->comm_type = PEP_ct_OpenPGP;
//     status = set_trust(session, alice);
//     ASSERT_EQ(status , PEP_STATUS_OK);

//     // Ok, let's reset it
//     status = key_reset_identity(session, alice, alice->fpr);
//     status = myself(session, alice);
//     ASSERT_EQ(status , PEP_STATUS_OK);

//     ASSERT_TRUE(alice->me);
//     ASSERT_NE(alice->fpr, nullptr);
//     ASSERT_STREQ(alice->fpr, alice_fpr);
//     ASSERT_EQ(alice->comm_type , PEP_ct_pEp);

//     free(alice->fpr);
//     alice->fpr = strdup("3AD9F60FAEB22675DB873A1362D6981326B54E4E");
//     status = get_trust(session, alice);
//     ASSERT_EQ(status , PEP_CANNOT_FIND_IDENTITY);
// }


TEST_F(KeyResetMessageTest, check_reset_ident_own_priv_fpr) {
    send_setup(); // lazy
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), NULL);
    PEP_STATUS status = myself(session, alice);

    ASSERT_OK;
    ASSERT_TRUE(alice->fpr && alice->fpr[0]);
    ASSERT_TRUE(alice->me);
    ASSERT_STREQ(alice->fpr, alice_fpr);

    status = key_reset_identity(session, alice, alice_fpr);
    status = myself(session, alice);
    ASSERT_OK;
    char* alice_new_fpr = alice->fpr;
    ASSERT_TRUE(alice_new_fpr && alice_new_fpr[0]);
    ASSERT_STRNE(alice_fpr, alice_new_fpr);
}


TEST_F(KeyResetMessageTest, check_reset_ident_own_priv_no_fpr) {
    send_setup(); // lazy
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), NULL);
    PEP_STATUS status = myself(session, alice);

    ASSERT_OK;
    ASSERT_TRUE(alice->fpr && alice->fpr[0]);
    ASSERT_TRUE(alice->me);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    free(alice->fpr);
    alice->fpr = NULL;
    status = key_reset_identity(session, alice, NULL);
    status = myself(session, alice);
    ASSERT_OK;
    char* alice_new_fpr = alice->fpr;
    ASSERT_TRUE(alice_new_fpr && alice_new_fpr[0]);
    ASSERT_STRNE(alice_fpr, alice_new_fpr);
}


TEST_F(KeyResetMessageTest, check_reset_user_other_no_fpr) {
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

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey1);
    status = trust_personal_key(session, alex_id);
    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey3);
    status = trust_personal_key(session, alex_id);
    status = set_as_pEp_user(session, alex_id);
    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey4);
    status = trust_personal_key(session, alex_id);

    status = key_reset_user(session, alex_id->user_id, NULL);

    stringlist_t* keylist = NULL;

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey1);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey1, &keylist);
    ASSERT_TRUE(status == PEP_GET_KEY_FAILED || !keylist || EMPTYSTR(keylist->value));

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey2);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey2, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey3);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey3, &keylist);
    ASSERT_TRUE(status == PEP_GET_KEY_FAILED || !keylist || EMPTYSTR(keylist->value));

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey4);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey4, &keylist);
    ASSERT_TRUE(status == PEP_GET_KEY_FAILED || !keylist || EMPTYSTR(keylist->value));

}


TEST_F(KeyResetMessageTest, check_reset_user_other_fpr) {
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

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey1);
    status = trust_personal_key(session, alex_id);
    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey3);
    status = trust_personal_key(session, alex_id);
    status = set_as_pEp_user(session, alex_id);
    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey4);
    status = trust_personal_key(session, alex_id);

    status = key_reset_user(session, alex_id->user_id, pubkey3);

    stringlist_t* keylist = NULL;

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey1);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_pEp);
    status = find_keys(session, pubkey1, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey2);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey2, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey3);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey3, &keylist);
    ASSERT_TRUE(status == PEP_GET_KEY_FAILED || !keylist || EMPTYSTR(keylist->value));

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey4);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_pEp);
    status = find_keys(session, pubkey4, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    // next line is for readability.
    alex_id->fpr = NULL;
    free_stringlist(keylist);
    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}


TEST_F(KeyResetMessageTest, check_reset_user_own_fpr) {
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
    status = set_own_key(session, alex_id, pubkey4);
    status = set_own_key(session, alex_id, pubkey3);

    status = myself(session, alex_id);

    status = key_reset_user(session, alex_id->user_id, pubkey3);

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey1);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_pEp);

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey2);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);

    stringlist_t* keylist = NULL;

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey3);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_mistrusted);
    status = find_keys(session, pubkey4, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey4);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_pEp);

    // next line is for readability.
    alex_id->fpr = NULL;
    free_stringlist(keylist);
    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}


TEST_F(KeyResetMessageTest, check_reset_user_no_fpr) {
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

    ASSERT_EQ(status , PEP_ILLEGAL_VALUE);

    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}


TEST_F(KeyResetMessageTest, check_reset_all_own_keys) {
    char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
    char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
    char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
    char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

    pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                         NULL,
                                         "AlexID",
                                         "Alexander Braithwaite");

    pEp_identity* alex_id2 = new_identity("pep.test.alexander6@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");


    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xBDA17020_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey3);
    status = myself(session, alex_id);
    status = set_own_key(session, alex_id, pubkey1);
    status = myself(session, alex_id);

    alex_id2->me = true;
    status = set_own_key(session, alex_id2, pubkey4);
    status = myself(session, alex_id2);

    status = key_reset_all_own_keys(session);

    stringlist_t* keylist = NULL;

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey1);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_mistrusted);
    status = find_keys(session, pubkey1, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey2);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey2, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey3);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_pEp);
    status = find_keys(session, pubkey3, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    free(alex_id2->fpr);
    alex_id2->fpr = strdup(pubkey4);
    status = get_trust(session, alex_id2);
    ASSERT_EQ(alex_id2->comm_type , PEP_ct_mistrusted);
    status = find_keys(session, pubkey4, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    alex_id->fpr = NULL;
    status = myself(session, alex_id);
    ASSERT_OK;

    ASSERT_NOTNULL(alex_id->fpr);
    output_stream << "alex_id->fpr is " << alex_id->fpr << endl;
    ASSERT_STRNE(alex_id->fpr, pubkey1);
    ASSERT_STRNE(alex_id->fpr, pubkey2);
    ASSERT_STRNE(alex_id->fpr, pubkey3);
    ASSERT_STRNE(alex_id->fpr, pubkey4);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_pEp);

    alex_id2->fpr = NULL;
    status = myself(session, alex_id2);
    ASSERT_OK;
    ASSERT_STRNE(alex_id2->fpr, pubkey1);
    ASSERT_STRNE(alex_id2->fpr, pubkey2);
    ASSERT_STRNE(alex_id2->fpr, pubkey3);
    ASSERT_STRNE(alex_id2->fpr, pubkey4);

    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}

TEST_F(KeyResetMessageTest, check_reset_replace_user_fpr_own_direct_reset) {
    char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
    char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

    pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                         NULL,
                                         "AlexID",
                                         "Alexander Braithwaite");

    pEp_identity* alex_id2 = new_identity("pep.test.alexander6@darthmama.org",
                                          NULL,
                                          "AlexID",
                                          "Alexander Braithwaite");


    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xBDA17020_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey3);
    status = myself(session, alex_id);

    char* main_key = NULL;
    
    status = get_main_user_fpr(session, alex_id->user_id, &main_key);
    ASSERT_NOTNULL(main_key);
    ASSERT_STREQ(main_key, pubkey3);
    
    alex_id2->me = true;
    status = set_own_key(session, alex_id2, pubkey4);
    status = myself(session, alex_id2);

    status = key_reset_all_own_keys(session);

    stringlist_t* keylist = NULL;

    status = get_main_user_fpr(session, alex_id->user_id, &main_key);
    ASSERT_NOTNULL(main_key);
    ASSERT_STRNE(main_key, pubkey3);

    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}

TEST_F(KeyResetMessageTest, check_reset_all_own_no_own) {
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

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey1);
    status = trust_personal_key(session, alex_id);
    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey3);
    status = trust_personal_key(session, alex_id);
    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey4);
    status = trust_personal_key(session, alex_id);

    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status , PEP_CANNOT_FIND_IDENTITY);

    stringlist_t* keylist = NULL;

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey1);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_OpenPGP);
    status = find_keys(session, pubkey1, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
        keylist = NULL;

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey2);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey2, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey3);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_OpenPGP);
    status = find_keys(session, pubkey3, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free(alex_id->fpr);
    alex_id->fpr = strdup(pubkey4);
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_OpenPGP);
    status = find_keys(session, pubkey4, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    // next line is for readability.
    alex_id->fpr = NULL;
    free_stringlist(keylist);
    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);

}

// TEST_F(KeyResetMessageTest, check_reset_mistrust_next_msg_have_mailed) {
//
// }

TEST_F(KeyResetMessageTest, not_a_test) {
    pEp_identity* bob = NULL;
    PEP_STATUS status = set_up_preset(session, BOB,
                                      true, true, true, true, true, &bob);

    const char* carol_fpr = "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42";
    slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
    slurp_and_import_key(session, "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc");

    pEp_identity* carol = new_identity("pep-test-carol@pep-project.org", carol_fpr, carol_user_id.c_str(), "Christmas Carol");
    status = set_identity(session, carol);

    message* bob_msg = new_message(PEP_dir_outgoing);
    bob_msg->from = identity_dup(bob);
    bob_msg->to = new_identity_list(carol);
    bob_msg->shortmsg = strdup("Engine bugs suck\n");
    bob_msg->longmsg = strdup("Everything is the engine's fault.\n");

    char* enc_msg_str = NULL;
    message* enc_msg = NULL;

    status = encrypt_message(session, bob_msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = mime_encode_message(enc_msg, false, &enc_msg_str, false);

    ofstream myfile;
    myfile.open("test_mails/ENGINE-654_bob_mail.eml");
    myfile << enc_msg_str;
    myfile.close();
}


TEST_F(KeyResetMessageTest, check_no_reset_message_to_self) {
    pEp_identity* bob = NULL;
    PEP_STATUS status = set_up_preset(session, BOB,
                                      true, true, true, true, true, &bob);

    slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");

    message* bob_msg = new_message(PEP_dir_outgoing);
    bob_msg->from = identity_dup(bob);
    bob_msg->to = new_identity_list(identity_dup(bob));
    bob_msg->shortmsg = strdup("Engine bugs suck\n");
    bob_msg->longmsg = strdup("Everything is the engine's fault.\n");

    message* enc_msg = NULL;

    status = encrypt_message(session, bob_msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);

    key_reset_all_own_keys(session);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(m_queue.size(), 0);
    ASSERT_EQ(status, PEP_VERIFY_SIGNER_KEY_REVOKED);
}


TEST_F(KeyResetMessageTest, check_reset_mistrust_next_msg_have_not_mailed) {
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL,
                                      true, true, true, true, true, &carol);

    status = myself(session, carol);
    ASSERT_STREQ(carol->fpr, "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42");

    slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", bob_fpr, NULL, "Bob's Burgers");
    status = set_fpr_preserve_ident(session, bob, bob_fpr, true);
    ASSERT_OK;
    status = update_identity(session, bob);
    ASSERT_OK;
    status = key_mistrusted(session, bob);
    ASSERT_OK;
    ASSERT_EQ(status, PEP_STATUS_OK);
//    ASSERT_NULL(bob->fpr);

    string mail_from_bob = slurp("test_mails/ENGINE-654_bob_mail.eml");
    //
    // // Ok, so let's see if the thing is mistrusted
    message* bob_enc_msg = NULL;
    //
    // mime_decode_message(mail_from_bob.c_str(), mail_from_bob.size(), &bob_enc_msg, NULL);
    //
    message* bob_dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    //
    // status = decrypt_message(session, bob_enc_msg, &bob_dec_msg, &keylist, &rating, &flags);
    // ASSERT_EQ(status, PEP_STATUS_OK);
    // ASSERT_EQ(rating, PEP_rating_mistrust);
    //
    // free_message(bob_enc_msg);
    // free_message(bob_dec_msg);

    free(bob->fpr);
    bob->fpr = NULL;

    status = key_reset_identity(session, bob, NULL);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // status = identity_rating(session, bob, &rating);
    // status = update_identity(session, bob);
    status = identity_rating(session, bob, &rating);
    ASSERT_EQ(rating, PEP_rating_have_no_key);
    //update_identity(session, bob);
            //    ASSERT_NULL(bob->fpr);

    mime_decode_message(mail_from_bob.c_str(), mail_from_bob.size(), &bob_enc_msg, NULL);

    bob_dec_msg = NULL;
    free_stringlist(keylist);
    keylist = NULL;
    flags = 0;

    status = decrypt_message(session, bob_enc_msg, &bob_dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_reliable);

}

// ENGINE-716
TEST_F(KeyResetMessageTest, check_reset_all_own_keys_one_URI_partner) {
    // me
    pEp_identity* me = new_identity("payto://BIC/SYSTEMA", NULL, "SystemA", NULL);
    PEP_STATUS status = myself(session, me);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(me->fpr);  
    char* copy_fpr = strdup(me->fpr);
    
    // I don't think this is relevant.
    pEp_identity* you = new_identity("payto://BIC/SYSTEMB", NULL, "SystemB", NULL); 
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/SYSTEMB-0xD47A817B3_pub.asc"));
    status = set_fpr_preserve_ident(session, you, "E53175090D2C520DF51E4C73258ACC4D47A817B3", true);
    ASSERT_OK;
    status = update_identity(session, you);
    ASSERT_OK;
    ASSERT_NOTNULL(you->fpr);  
    
    status = key_reset_all_own_keys(session);    
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = myself(session, me);
    ASSERT_STRNE(me->fpr, copy_fpr);
}

TEST_F(KeyResetMessageTest, check_reset_key_needs_passphrase) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);

    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_identity(session, bob2, bob2_fpr);
    ASSERT_EQ(status, PEP_PASSPHRASE_REQUIRED);

}

TEST_F(KeyResetMessageTest, check_reset_key_wrong_passphrase) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    config_passphrase(session, "julio");

    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_identity(session, bob2, bob2_fpr);

    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);    
}

TEST_F(KeyResetMessageTest, check_reset_key_correct_passphrase) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    config_passphrase(session, "bob");
    
    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_STATUS_OK);        
}

//
TEST_F(KeyResetMessageTest, check_reset_key_user_needs_passphrase) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);

    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_PASSPHRASE_REQUIRED);

}

TEST_F(KeyResetMessageTest, check_reset_key_user_wrong_passphrase) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    config_passphrase(session, "julio");

    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_all_own_keys(session);

    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);    
}

TEST_F(KeyResetMessageTest, check_reset_key_user_correct_passphrase) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    config_passphrase(session, "bob");
    
    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_STATUS_OK);        
}

TEST_F(KeyResetMessageTest, check_reset_key_user_multi_passphrase_first_wrong) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));

    PEP_STATUS status;
        
    config_passphrase(session, "erwin");
    
    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);

    pEp_identity* erwin = new_identity("erwin@example.org", erwin_fpr, "BOB", "Bob is Erwin");
    status = set_own_key(session, erwin, erwin_fpr);
    
    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);        
}

TEST_F(KeyResetMessageTest, check_reset_key_user_multi_passphrase_second_wrong) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));    

    PEP_STATUS status;
    
    config_passphrase(session, "bob");
    
    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    pEp_identity* erwin = new_identity("erwin@example.org", erwin_fpr, "BOB", "Bob is Erwin");
    status = set_own_key(session, erwin, erwin_fpr);
    
    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);        
}

TEST_F(KeyResetMessageTest, check_reset_key_user_multi_passphrase_with_passlist) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));    

    PEP_STATUS status;

    pass_list.push_back("erwin");
    pass_list.push_back("cathy");
    pass_list.push_back("bob");

    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    pEp_identity* erwin = new_identity("erwin@example.org", erwin_fpr, "BOB", "Bob is Erwin");
    status = set_own_key(session, erwin, erwin_fpr);
    
    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_STATUS_OK);        
}

TEST_F(KeyResetMessageTest, check_reset_key_user_multi_passphrase_with_passlist_first_configured) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));    

    PEP_STATUS status;

    config_passphrase(session, "bob");
    pass_list.push_back("erwin");
    pass_list.push_back("cathy");
    pass_list.push_back("bob");

    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    pEp_identity* erwin = new_identity("erwin@example.org", erwin_fpr, "BOB", "Bob is Erwin");
    status = set_own_key(session, erwin, erwin_fpr);
    
    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_STATUS_OK);        
}

TEST_F(KeyResetMessageTest, check_reset_key_user_multi_passphrase_with_passlist_second_configured) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));    

    PEP_STATUS status;

    config_passphrase(session, "erwin");
    pass_list.push_back("cathy");
    pass_list.push_back("bob");
    pass_list.push_back("erwin");

    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    pEp_identity* erwin = new_identity("erwin@example.org", erwin_fpr, "BOB", "Bob is Erwin");
    status = set_own_key(session, erwin, erwin_fpr);
    
    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_STATUS_OK);        
}

TEST_F(KeyResetMessageTest, check_reset_key_user_multi_passphrase_with_passlist_first_missing) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));    

    PEP_STATUS status;

    pass_list.push_back("cathy");
    pass_list.push_back("erwin");

    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    pEp_identity* erwin = new_identity("erwin@example.org", erwin_fpr, "BOB", "Bob is Erwin");
    status = set_own_key(session, erwin, erwin_fpr);
    
    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);        
}

TEST_F(KeyResetMessageTest, check_reset_key_user_multi_passphrase_with_passlist_second_missing) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));    

    PEP_STATUS status;

    pass_list.push_back("cathy");
    pass_list.push_back("bob");
 
    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    pEp_identity* erwin = new_identity("erwin@example.org", erwin_fpr, "BOB", "Bob is Erwin");
    status = set_own_key(session, erwin, erwin_fpr);
    
    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);        
}

TEST_F(KeyResetMessageTest, check_reset_key_user_multi_passphrase_with_passlist_config_all_missing) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));    

    PEP_STATUS status;

    config_passphrase(session, "cathy");
    pass_list.push_back("dragons!");
    pass_list.push_back("cheez whiz is gross");
    pass_list.push_back("Vashedan!");

    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    pEp_identity* erwin = new_identity("erwin@example.org", erwin_fpr, "BOB", "Bob is Erwin");
    status = set_own_key(session, erwin, erwin_fpr);
    
    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);        
}

TEST_F(KeyResetMessageTest, check_reset_key_user_multi_passphrase_with_passlist_empty_config_all_missing) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));    

    PEP_STATUS status;

    pass_list.push_back("dragons!");
    pass_list.push_back("cheez whiz is gross");
    pass_list.push_back("Vashedan!");

    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    pEp_identity* erwin = new_identity("erwin@example.org", erwin_fpr, "BOB", "Bob is Erwin");
    status = set_own_key(session, erwin, erwin_fpr);
    
    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);        
}

//

TEST_F(KeyResetMessageTest, check_reset_key_needs_passphrase_gen_key_matches) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);

    config_passphrase_for_new_keys(session, true, "bob");
    
    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_identity(session, bob2, bob2_fpr);
    ASSERT_EQ(status, PEP_PASSPHRASE_REQUIRED);

}

TEST_F(KeyResetMessageTest, check_reset_key_needs_passphrase_gen_key_matches_has_passlist) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);

    config_passphrase_for_new_keys(session, true, "bob");
    pass_list.push_back("bob");

    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_identity(session, bob2, bob2_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
}

TEST_F(KeyResetMessageTest, check_reset_key_wrong_passphrase_gen_key_matches) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    config_passphrase(session, "julio");
    config_passphrase_for_new_keys(session, true, "bob");
    
    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_identity(session, bob2, bob2_fpr);

    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);    
}

TEST_F(KeyResetMessageTest, check_reset_key_wrong_passphrase_gen_key_matches_has_passlist) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    config_passphrase(session, "julio");
    config_passphrase_for_new_keys(session, true, "bob");
    pass_list.push_back("april");
    pass_list.push_back("bob");

    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_identity(session, bob2, bob2_fpr);

    ASSERT_EQ(status, PEP_STATUS_OK);    
}


TEST_F(KeyResetMessageTest, check_reset_key_correct_passphrase_gen_key_matches) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    config_passphrase(session, "bob");
    config_passphrase_for_new_keys(session, true, "bob");
    
    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_identity(session, bob2, bob2_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);        
}

TEST_F(KeyResetMessageTest, check_reset_key_correct_passphrase_gen_key_differs) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    config_passphrase(session, "bob");
    config_passphrase_for_new_keys(session, true, "juan");
    
    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_identity(session, bob2, bob2_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);        
}

TEST_F(KeyResetMessageTest, check_reset_key_wrong_passphrase_gen_key_differs_has_passlist) {
    ASSERT_TRUE(slurp_and_import_key(session, bob2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    pass_list.push_back("amy");
    pass_list.push_back("Spurius Tettius");
    pass_list.push_back("bob");
    pass_list.push_back("Correct Horse Battery Staple");

    config_passphrase(session, "julio");
    config_passphrase_for_new_keys(session, true, "juan");
    
    pEp_identity* bob2 = new_identity("bob@example.org", bob2_fpr, "BOB", "Bob Dog");
    status = set_own_key(session, bob2, bob2_fpr);
    
    status = key_reset_identity(session, bob2, bob2_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);        
}

TEST_F(KeyResetMessageTest, check_reset_key_no_passphrase_but_has_gen_key) {
    ASSERT_TRUE(slurp_and_import_key(session, alice2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);

    config_passphrase_for_new_keys(session, true, "alice");
    
    pEp_identity* alice2 = new_identity("alice@example.org", alice2_fpr, "ALICE", "Alice");
    status = set_own_key(session, alice2, alice2_fpr);
    
    status = key_reset_identity(session, alice2, alice2_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

}

TEST_F(KeyResetMessageTest, check_reset_key_no_passphrase_needed_but_has_gen_key_and_passlist) {
    ASSERT_TRUE(slurp_and_import_key(session, alice2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);

    pass_list.push_back("julio");
    pass_list.push_back("juan");

    config_passphrase_for_new_keys(session, true, "alice");
    
    pEp_identity* alice2 = new_identity("alice@example.org", alice2_fpr, "ALICE", "Alice");
    status = set_own_key(session, alice2, alice2_fpr);
    
    status = key_reset_identity(session, alice2, alice2_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

}


TEST_F(KeyResetMessageTest, check_reset_key_gen_key_pass_required) {
    ASSERT_TRUE(slurp_and_import_key(session, alice2_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice2_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);

    session->new_key_pass_enable = true;
    
    pEp_identity* alice2 = new_identity("alice@example.org", alice2_fpr, "ALICE", "Alice");
    status = set_own_key(session, alice2, alice2_fpr);
    
    status = key_reset_identity(session, alice2, alice2_fpr);
    ASSERT_EQ(status, PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED);

}

/*
TEST_F(KeyResetMessageTest, check_reset_own_with_revocations) {
    pEp_identity* id1 = new_identity("krista-not-real@darthmama.org", NULL, PEP_OWN_USERID, "Krista at Home");
    PEP_STATUS status = myself(session, id1);
    pEp_identity* id2 = NULL;
    status = set_up_preset(session, ALICE, true, true, false, false, false, &id2);
    pEp_identity* id3 = new_identity("krista-not-real@angryshark.eu", NULL, PEP_OWN_USERID, "Krista at Shark");
    status = myself(session, id3);
    pEp_identity* id4 = NULL;
    status = set_up_preset(session, BOB, true, false, false, false, false, &id4);
    pEp_identity* id5 = new_identity("krista-not-real@pep.foundation", NULL, PEP_OWN_USERID, "Krista at Work");
    status = myself(session, id5);
    pEp_identity* id6 = new_identity("grrrr-not-real@angryshark.eu", NULL, PEP_OWN_USERID, "GRRRR is a Shark");
    status = myself(session, id6);
    pEp_identity* id7 = NULL;
    status = set_up_preset(session, CAROL, true, false, true, false, false, &id7);
    pEp_identity* id8 = NULL;
    status = set_up_preset(session, DAVE, true, true, true, false, false, &id8);

    identity_list* own_identities = NULL;
    stringlist_t* revocations = NULL;
    stringlist_t* keys = NULL;

    stringlist_t* first_keylist = new_stringlist(NULL);
    stringlist_add(first_keylist, strdup(id1->fpr));
    stringlist_add(first_keylist, strdup(id3->fpr));
    stringlist_add(first_keylist, strdup(id5->fpr));
    stringlist_add(first_keylist, strdup(id6->fpr));

    status = key_reset_own_and_deliver_revocations(session,
                                                   &own_identities,
                                                   &revocations,
                                                   &keys);

    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(own_identities);
    ASSERT_NOTNULL(revocations);
    ASSERT_NOTNULL(keys);

    int i = 0;
    identity_list* curr_ident = own_identities;
    stringlist_t* second_keylist = new_stringlist(NULL);

    for (i = 0; i < 4 && curr_ident; i++, curr_ident = curr_ident->next) {
        ASSERT_NOTNULL(curr_ident->ident);
        ASSERT_NOTNULL(curr_ident->ident->fpr);
        stringlist_t* found = stringlist_search(first_keylist, curr_ident->ident->fpr);
        ASSERT_NULL(found);
        PEP_comm_type ct = PEP_ct_unknown;
        status = get_key_rating(session, curr_ident->ident->fpr, &ct);
        ASSERT_EQ(ct, PEP_ct_OpenPGP_unconfirmed);
        stringlist_add(second_keylist, strdup(curr_ident->ident->fpr));
    }
    ASSERT_EQ(i, 4);
    ASSERT_NULL(curr_ident);

    stringlist_t* curr_key = first_keylist;
    for (i = 0; i < 4; i++, curr_key = curr_key->next) {
        PEP_comm_type ct = PEP_ct_unknown;
        status = get_key_rating(session, curr_key->value, &ct);
        ASSERT_EQ(ct, PEP_ct_key_revoked);
    }

    // Ok, now we're going to delete all the keys, and then try to reimport.
    curr_key = first_keylist;
    for (i = 0; i < 4; curr_key = curr_key->next, i++) {
        status = delete_keypair(session, curr_key->value);
        ASSERT_EQ(status, PEP_STATUS_OK);
    }
    ASSERT_EQ(i, 4);
    ASSERT_NULL(curr_key);

    curr_key = second_keylist;
    for (i = 0; i < 4; curr_key = curr_key->next, i++) {
        status = delete_keypair(session, curr_key->value);
        ASSERT_EQ(status, PEP_STATUS_OK);
    }
    ASSERT_EQ(i, 4);
    ASSERT_NULL(curr_key);

    // Make sure we can't find them
    curr_key = first_keylist;
    for (i = 0; i < 4; curr_key = curr_key->next, i++) {
        PEP_comm_type ct = PEP_ct_unknown;
        status = get_key_rating(session, curr_key->value, &ct);
        ASSERT_EQ(status, PEP_KEY_NOT_FOUND);
    }
    curr_key = second_keylist;
    for (i = 0; i < 4; curr_key = curr_key->next, i++) {
        PEP_comm_type ct = PEP_ct_unknown;
        status = get_key_rating(session, curr_key->value, &ct);
        ASSERT_EQ(status, PEP_KEY_NOT_FOUND);
    }


    // Reimport
    curr_key = revocations;
    for (i = 0; i < 4; curr_key = curr_key->next, i++) {
        status = import_key($1, $2, $3, $4, NULL, NULL);
        ASSERT_EQ(status, PEP_KEY_IMPORTED);
    }
    ASSERT_EQ(i, 4);
    ASSERT_NULL(curr_key);

    curr_key = keys;
    for (i = 0; i < 4; curr_key = curr_key->next, i++) {
        status = import_key($1, $2, $3, $4, NULL, NULL);
        ASSERT_EQ(status, PEP_KEY_IMPORTED);
    }
    ASSERT_EQ(i, 4);
    ASSERT_NULL(curr_key);

    // Check the revoked keys to be sure they are revoked
    curr_key = first_keylist;
    for (i = 0; i < 4; curr_key = curr_key->next, i++) {
        PEP_comm_type ct = PEP_ct_unknown;
        status = get_key_rating(session, curr_key->value, &ct);
        ASSERT_EQ(ct, PEP_ct_key_revoked);
        ASSERT_EQ(status, PEP_STATUS_OK);
    }
    // Check the imported keys to be sure they are OK
    curr_key = second_keylist;
    for (i = 0; i < 4; curr_key = curr_key->next, i++) {
        PEP_comm_type ct = PEP_ct_unknown;
        status = get_key_rating(session, curr_key->value, &ct);
        ASSERT_EQ(ct, PEP_ct_OpenPGP_unconfirmed);
        ASSERT_EQ(status, PEP_STATUS_OK);
    }
}
*/


TEST_F(KeyResetMessageTest, codec_test) {
    // create input values

    pEp_identity *ident1 = new_identity("alice@pep-project.org", "FEDCBA9876543210", "42", "Alice Miller");
    ASSERT_NOTNULL(ident1);
    const char *key1 = "0123456789ABCDEF";
    keyreset_command *cmd1 = new_keyreset_command(ident1, key1);
    ASSERT_NOTNULL(cmd1);

    keyreset_command_list *il = new_keyreset_command_list(cmd1);
    ASSERT_NOTNULL(il);

    pEp_identity *ident2 = new_identity("alice@peptest.ch", "0123456789abcdef", "42", "Alice Miller");
    ASSERT_NOTNULL(ident2);
    const char *key2 = "fedcba9876543210";
    keyreset_command *cmd2 = new_keyreset_command(ident2, key2);
    ASSERT_NOTNULL(cmd2);

    keyreset_command_list *_il = keyreset_command_list_add(il, cmd2);
    ASSERT_NOTNULL(_il);

    // check created struct

    ASSERT_NOTNULL(il->command);
    ASSERT_NOTNULL(il->command->ident);
    ASSERT_NOTNULL(il->command->new_key);

    ASSERT_STREQ(il->command->ident->address, ident1->address);
    ASSERT_STREQ(il->command->ident->fpr, ident1->fpr);
    ASSERT_STREQ(il->command->ident->user_id, ident1->user_id);
    ASSERT_STREQ(il->command->ident->username, ident1->username);
    ASSERT_STREQ(il->command->new_key, key1);

    ASSERT_NOTNULL(il->next);
    ASSERT_NOTNULL(il->next->command);
    ASSERT_NOTNULL(il->next->command->ident);
    ASSERT_NOTNULL(il->next->command->new_key);

    ASSERT_STREQ(il->next->command->ident->address, ident2->address);
    ASSERT_STRCASEEQ(il->next->command->ident->fpr, ident2->fpr);
    ASSERT_STREQ(il->next->command->ident->user_id, ident2->user_id);
    ASSERT_STREQ(il->next->command->ident->username, ident2->username);
    ASSERT_STRCASEEQ(il->next->command->new_key, key2);

    ASSERT_NULL(il->next->next);

    // encode

    char *cmds = nullptr;
    size_t size = 0;
    PEP_STATUS status = key_reset_commands_to_PER(il, &cmds, &size);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(cmds);
    ASSERT_NE(size, 0);

    // decode

    keyreset_command_list *ol = nullptr;
    status = PER_to_key_reset_commands(cmds, size, &ol);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(ol);

    // compare

    ASSERT_NOTNULL(ol->command);
    ASSERT_NOTNULL(ol->command->ident);
    ASSERT_NOTNULL(ol->command->new_key);

    ASSERT_STREQ(ol->command->ident->address, ident1->address);
    ASSERT_STREQ(ol->command->ident->fpr, ident1->fpr);
    ASSERT_STREQ(ol->command->ident->user_id, ident1->user_id);
    ASSERT_STREQ(ol->command->ident->username, ident1->username);
    ASSERT_STREQ(ol->command->new_key, key1);

    ASSERT_NOTNULL(ol->next);
    ASSERT_NOTNULL(ol->next->command);
    ASSERT_NOTNULL(ol->next->command->ident);
    ASSERT_NOTNULL(ol->next->command->new_key);

    ASSERT_STREQ(ol->next->command->ident->address, ident2->address);
    ASSERT_STRCASEEQ(ol->next->command->ident->fpr, ident2->fpr);
    ASSERT_STREQ(ol->next->command->ident->user_id, ident2->user_id);
    ASSERT_STREQ(ol->next->command->ident->username, ident2->username);
    ASSERT_STRCASEEQ(ol->next->command->new_key, key2);

    ASSERT_NULL(ol->next->next);

    // free

    free_keyreset_command_list(ol);
    free(cmds);

    free_identity(ident1);
    free_identity(ident2);
    free_keyreset_command_list(il);
}
