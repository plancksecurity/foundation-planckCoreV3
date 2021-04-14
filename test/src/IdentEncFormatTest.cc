#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for IdentEncFormatTest
    class IdentEncFormatTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            IdentEncFormatTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~IdentEncFormatTest() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

                // Get a new test Engine.
                engine = new Engine(test_path);
                ASSERT_NE(engine, nullptr);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NE(engine->session, nullptr);
                session = engine->session;

                // Engine is up. Keep on truckin'
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }
            const char* alice_filename = "test_keys/alice-no-passwords.pgp";
            const char* alice_pub_filename = "test_keys/pub/alice-0x2A649B9F_pub.asc";
            const char* bob_filename = "test_keys/bob-primary-with-password-bob-subkey-without.pgp";            
            const char* carol_filename = "test_keys/carol-subkeys-password-carol.pgp";
            const char* david_filename = "test_keys/david-encryption-subkey-password-encrypt-signing-subkey-password-sign.pgp";            
            const char* alice_fpr = "03AF88F728B8E9AADA7F370BD41801C62A649B9F";
            const char* bob_fpr = "5C76378A62B04CF3F41BEC8D4940FC9FA1878736";            
            const char* carol_fpr = "A5B3473EA7CBB5DF7A4F595A8883DC4BCD8BAC06";
            const char* david_fpr = "7F72E4B27C6161455CD9C50FE7A05D7BF3FF4E19";            
            

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the IdentEncFormatTest suite.

    };

}  // namespace


TEST_F(IdentEncFormatTest, check_ident_enc_format_unspecified) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = carol_fpr;
    const char* my_name = "Carol Peril";
    const char* my_address = "carol_peril@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    // Set up "to"
    ASSERT_TRUE(slurp_and_import_key(session, alice_pub_filename));    
    const char* to_fpr = alice_fpr;
    const char* to_name = "Alice Malice";
    const char* to_address = "alice_malice@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, "ALICE", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    message* msg = new_message(PEP_dir_outgoing);        
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Carol!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_auto, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
    // FIXME: This is fine for now, but needs to change when they are implemented separately
    ASSERT_TRUE(enc_msg->enc_format == PEP_enc_PEP || enc_msg->enc_format == PEP_enc_PGP_MIME);
    free_message(msg);
    free_message(enc_msg);    
    free_stringlist(found_key);    
}

TEST_F(IdentEncFormatTest, check_ident_enc_format_specified) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = carol_fpr;
    const char* my_name = "Carol Peril";
    const char* my_address = "carol_peril@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    // Set up "to"
    ASSERT_TRUE(slurp_and_import_key(session, alice_pub_filename));    
    const char* to_fpr = alice_fpr;
    const char* to_name = "Alice Malice";
    const char* to_address = "alice_malice@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, "ALICE", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    message* msg = new_message(PEP_dir_outgoing);        
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Carol!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_inline, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
    ASSERT_EQ(enc_msg->enc_format, PEP_enc_inline);
    free_message(msg);
    free_message(enc_msg);    
    free_stringlist(found_key);    
}


TEST_F(IdentEncFormatTest, check_ident_enc_format_one_to_nospec) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = carol_fpr;
    const char* my_name = "Carol Peril";
    const char* my_address = "carol_peril@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    // Set up "to"
    ASSERT_TRUE(slurp_and_import_key(session, alice_pub_filename));    
    const char* to_fpr = alice_fpr;
    const char* to_name = "Alice Malice";
    const char* to_address = "alice_malice@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, "ALICE", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    pEp_identity* to_setter = identity_dup(to_ident);
    status = set_ident_enc_format(session, to_setter, PEP_enc_inline_EA);
    free_identity(to_setter);
    ASSERT_EQ(status, PEP_STATUS_OK);
        
    message* msg = new_message(PEP_dir_outgoing);        
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Carol!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_auto, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
    ASSERT_EQ(enc_msg->enc_format, PEP_enc_inline_EA);
    free_message(msg);
    free_message(enc_msg);    
    free_stringlist(found_key);        
}

TEST_F(IdentEncFormatTest, check_ident_enc_format_multi_to_middle_nospec) {    
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = carol_fpr;
    const char* my_name = "Carol Peril";
    const char* my_address = "carol_peril@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    // Set up "to"
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));    
    const char* to_fpr = bob_fpr;
    const char* to_name = "Bob Mob";
    const char* to_address = "bob_mob@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, "BOB", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    to_ident = NULL;
            
    message* msg = new_message(PEP_dir_outgoing);        
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Carol!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   

    ASSERT_TRUE(slurp_and_import_key(session, alice_pub_filename));    
    to_fpr = alice_fpr;
    to_name = "Alice Malice";
    to_address = "alice_malice@darthmama.cool";    
    to_ident = new_identity(to_address, to_fpr, "ALICE", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    identity_list_add(msg->to, to_ident);
        
    pEp_identity* to_setter = identity_dup(to_ident);
    to_ident = NULL;    
    status = set_ident_enc_format(session, to_setter, PEP_enc_inline);
    free_identity(to_setter);
    ASSERT_EQ(status, PEP_STATUS_OK);
        
    ASSERT_TRUE(slurp_and_import_key(session, david_filename));    
    to_fpr = david_fpr;
    to_name = "Dave Rave";
    to_address = "dave_rave@darthmama.cool";
    to_ident = new_identity(to_address, to_fpr, "DAVID", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    identity_list_add(msg->to, to_ident);    
        
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_auto, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
    ASSERT_EQ(enc_msg->enc_format, PEP_enc_inline);
    free_message(msg);
    free_message(enc_msg);    
    free_stringlist(found_key);            
}

TEST_F(IdentEncFormatTest, check_ident_enc_format_multi_cc_nospec) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = carol_fpr;
    const char* my_name = "Carol Peril";
    const char* my_address = "carol_peril@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
        
    // Set up "to"
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));    
    const char* to_fpr = bob_fpr;
    const char* to_name = "Bob Mob";
    const char* to_address = "bob_mob@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, "BOB", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
            
    message* msg = new_message(PEP_dir_outgoing);        
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Carol!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   

    to_ident = NULL;

    ASSERT_TRUE(slurp_and_import_key(session, alice_pub_filename));    
    to_fpr = alice_fpr;
    to_name = "Alice Malice";
    to_address = "alice_malice@darthmama.cool";    
    to_ident = new_identity(to_address, to_fpr, "ALICE", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    msg->cc = new_identity_list(to_ident);
        
    pEp_identity* to_setter = identity_dup(to_ident);
    to_ident = NULL;    
    status = set_ident_enc_format(session, to_setter, PEP_enc_inline_EA);
    free_identity(to_setter);
    ASSERT_EQ(status, PEP_STATUS_OK);
        
    ASSERT_TRUE(slurp_and_import_key(session, david_filename));    
    to_fpr = david_fpr;
    to_name = "Dave Rave";
    to_address = "dave_rave@darthmama.cool";
    to_ident = new_identity(to_address, to_fpr, "DAVID", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    identity_list_add(msg->cc, to_ident);    

    to_setter = identity_dup(to_ident);
    to_ident = NULL;    
    status = set_ident_enc_format(session, to_setter, PEP_enc_S_MIME);
    free_identity(to_setter);
    ASSERT_EQ(status, PEP_STATUS_OK);
            
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_auto, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
    ASSERT_EQ(enc_msg->enc_format, PEP_enc_inline_EA);
    free_message(msg);
    free_message(enc_msg);    
    free_stringlist(found_key);                
}

TEST_F(IdentEncFormatTest, check_ident_enc_format_multi_bcc_nospec) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = carol_fpr;
    const char* my_name = "Carol Peril";
    const char* my_address = "carol_peril@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
        
    // Set up "to"
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));    
    const char* to_fpr = bob_fpr;
    const char* to_name = "Bob Mob";
    const char* to_address = "bob_mob@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, "BOB", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
            
    message* msg = new_message(PEP_dir_outgoing);        
    msg->from = my_ident;
    msg->bcc = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Carol!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
            
    pEp_identity* to_setter = identity_dup(to_ident);
    to_ident = NULL;    
    status = set_ident_enc_format(session, to_setter, PEP_enc_inline_EA);
    free_identity(to_setter);
    ASSERT_EQ(status, PEP_STATUS_OK);
                    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_auto, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
    ASSERT_EQ(enc_msg->enc_format, PEP_enc_inline_EA);
    free_message(msg);
    free_message(enc_msg);    
    free_stringlist(found_key);                
}

TEST_F(IdentEncFormatTest, check_ident_enc_format_multi_cc_specified) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = carol_fpr;
    const char* my_name = "Carol Peril";
    const char* my_address = "carol_peril@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
        
    // Set up "to"
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));    
    const char* to_fpr = bob_fpr;
    const char* to_name = "Bob Mob";
    const char* to_address = "bob_mob@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, "BOB", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
            
    message* msg = new_message(PEP_dir_outgoing);        
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Carol!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   

    to_ident = NULL;

    ASSERT_TRUE(slurp_and_import_key(session, alice_pub_filename));    
    to_fpr = alice_fpr;
    to_name = "Alice Malice";
    to_address = "alice_malice@darthmama.cool";    
    to_ident = new_identity(to_address, to_fpr, "ALICE", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    msg->cc = new_identity_list(to_ident);
        
    pEp_identity* to_setter = identity_dup(to_ident);
    to_ident = NULL;    
    status = set_ident_enc_format(session, to_setter, PEP_enc_PGP_MIME);
    free_identity(to_setter);
    ASSERT_EQ(status, PEP_STATUS_OK);
        
    ASSERT_TRUE(slurp_and_import_key(session, david_filename));    
    to_fpr = david_fpr;
    to_name = "Dave Rave";
    to_address = "dave_rave@darthmama.cool";
    to_ident = new_identity(to_address, to_fpr, "DAVID", to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    identity_list_add(msg->cc, to_ident);    

    to_setter = identity_dup(to_ident);
    to_ident = NULL;    
    status = set_ident_enc_format(session, to_setter, PEP_enc_S_MIME);
    free_identity(to_setter);
    ASSERT_EQ(status, PEP_STATUS_OK);
            
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_inline_EA, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
    ASSERT_EQ(enc_msg->enc_format, PEP_enc_inline_EA);
    free_message(msg);
    free_message(enc_msg);    
    free_stringlist(found_key);      
    
    to_name = "Alice Malice";
    to_address = "alice_malice@darthmama.cool";    
    to_ident = new_identity(to_address, NULL, "ALICE", to_name);
    status = update_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(to_ident->enc_format, PEP_enc_inline_EA);
    free_identity(to_ident);

    to_fpr = bob_fpr;
    to_address = "bob_mob@darthmama.cool";
    to_ident = new_identity(to_address, NULL, "BOB", NULL);    
    status = update_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(to_ident->enc_format, PEP_enc_inline_EA);
    free_identity(to_ident);
        
    to_address = "dave_rave@darthmama.cool";    
    to_ident = new_identity(to_address, NULL, NULL, NULL);
    status = update_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(to_ident->enc_format, PEP_enc_inline_EA);
    free_identity(to_ident);    
}
