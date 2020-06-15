#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>

#define PPTEST_DUMP 1

namespace {

	//The fixture for PassphraseTest
    class PassphraseTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            PassphraseTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~PassphraseTest() override {
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
                engine->prep(NULL, NULL, init_files);

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
            const char* bob_filename = "test_keys/bob-primary-with-password-bob-subkey-without.pgp";
            const char* carol_filename = "test_keys/carol-subkeys-password-carol.pgp";
            const char* david_filename = "test_keys/david-encryption-subkey-password-encrypt-signing-subkey-password-sign.pgp";
            const char* erwin_filename = "test_keys/erwin-primary-encrypted-erwin-subkey-unencrypted.pgp";
            const char* alice_fpr = "03AF88F728B8E9AADA7F370BD41801C62A649B9F";
            const char* bob_fpr = "5C76378A62B04CF3F41BEC8D4940FC9FA1878736";
            const char* carol_fpr = "A5B3473EA7CBB5DF7A4F595A8883DC4BCD8BAC06";
            const char* david_fpr = "7F72E4B27C6161455CD9C50FE7A05D7BF3FF4E19";
            const char* erwin_fpr = "A34048189F0067DF0006FB28CBD7CFBCC0FA7F97";
            
        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the PassphraseTest suite.

    };

}  // namespace


TEST_F(PassphraseTest, check_alice_no_passphrase_nopass_import) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_bob_primary_pass_subkey_no_passphrase_nopass_import) {
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, bob_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_carol_primary_unenc_subkeys_passphrase_nopass_import) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_david_primary_unenc_sign_and_encrypt_diff_pass_two_sign_unencrypted_nopass_import) {
    ASSERT_TRUE(slurp_and_import_key(session, david_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, david_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, david_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_erwin_primary_enc_subkey_encrypted_plus_unenc_sign_nopass_import) {
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, erwin_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, erwin_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_alice_no_passphrase_nopass_sign_encrypt) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = alice_fpr;
    const char* my_name = "Alice Malice";
    const char* my_address = "alice_malice@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    const char* to_fpr = alice_fpr;
    const char* to_name = "Alice Malice";
    const char* to_address = "alice_malice@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, PEP_OWN_USERID, to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Alice!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
    free_message(msg);
    free_message(enc_msg);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_bob_primary_pass_subkey_no_passphrase_nopass_sign) {
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, bob_fpr);
    ASSERT_EQ(found_key->next, nullptr);

    const char* my_fpr = bob_fpr;
    const char* my_name = "Bob Mob";
    const char* my_address = "bob_mob@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    // Set up "to"
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));    
    const char* to_fpr = alice_fpr;
    const char* to_name = "Alice Malice";
    const char* to_address = "alice_malice@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, PEP_OWN_USERID, to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    message* msg = new_message(PEP_dir_outgoing);   
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Bob!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_NE(status, PEP_STATUS_OK);
    ASSERT_EQ(enc_msg, nullptr);
    
    free_message(msg);
    free_message(enc_msg);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_carol_primary_unenc_subkeys_passphrase_nopass_sign) {
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
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));    
    const char* to_fpr = alice_fpr;
    const char* to_name = "Alice Malice";
    const char* to_address = "alice_malice@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, PEP_OWN_USERID, to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    message* msg = new_message(PEP_dir_outgoing);        
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Carol!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
    free_message(msg);
    free_message(enc_msg);    
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_david_primary_unenc_sign_and_encrypt_diff_pass_two_sign_unencrypted_nopass_sign) {
    ASSERT_TRUE(slurp_and_import_key(session, david_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, david_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, david_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = david_fpr;
    const char* my_name = "Dave Rave";
    const char* my_address = "dave_rave@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // Set up "to"
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));    
    const char* to_fpr = alice_fpr;
    const char* to_name = "Alice Malice";
    const char* to_address = "alice_malice@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, PEP_OWN_USERID, to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    message* msg = new_message(PEP_dir_outgoing);        
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from David!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
    free_message(msg);
    free_message(enc_msg);        
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_erwin_primary_enc_subkey_encrypted_plus_unenc_sign_nopass_sign) {
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, erwin_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, erwin_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = erwin_fpr;
    const char* my_name = "Irv Nerve";
    const char* my_address = "irv_nerve@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    // Set up "to"
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));    
    const char* to_fpr = alice_fpr;
    const char* to_name = "Alice Malice";
    const char* to_address = "alice_malice@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, PEP_OWN_USERID, to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    message* msg = new_message(PEP_dir_outgoing);    
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Erwin!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
    free_message(msg);
    free_message(enc_msg);            
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_bob_primary_pass_subkey_no_passphrase_nopass_encrypt) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = alice_fpr;
    const char* my_name = "Alice Malice";
    const char* my_address = "alice_malice@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));    
    const char* to_fpr = bob_fpr;
    const char* to_name = "Bob Mob";
    const char* to_address = "bob_mob@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, PEP_OWN_USERID, to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Alice!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
#if PPTEST_DUMP   
    char* outdata = NULL;
    mime_encode_message(enc_msg, false, &outdata, false);
    dump_out("test_mails/encrypt_to_bob.eml", outdata);
    free(outdata);
#endif
    
    free_message(msg);
    free_message(enc_msg);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_carol_primary_unenc_subkeys_passphrase_nopass_encrypt) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = alice_fpr;
    const char* my_name = "Alice Malice";
    const char* my_address = "alice_malice@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));    
    const char* to_fpr = carol_fpr;
    const char* to_name = "Carol Peril";
    const char* to_address = "carol_peril@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, PEP_OWN_USERID, to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Alice!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);

#if PPTEST_DUMP   
    char* outdata = NULL;
    mime_encode_message(enc_msg, false, &outdata, false);
    dump_out("test_mails/encrypt_to_carol.eml", outdata);
    free(outdata);
#endif
    
    free_message(msg);
    free_message(enc_msg);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_david_primary_unenc_sign_and_encrypt_diff_pass_two_sign_unencrypted_nopass_encrypt) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = alice_fpr;
    const char* my_name = "Alice Malice";
    const char* my_address = "alice_malice@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    ASSERT_TRUE(slurp_and_import_key(session, david_filename));    
    const char* to_fpr = david_fpr;
    const char* to_name = "Dave Rave";
    const char* to_address = "dave_rave@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, PEP_OWN_USERID, to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Alice!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    
#if PPTEST_DUMP   
    char* outdata = NULL;
    mime_encode_message(enc_msg, false, &outdata, false);
    dump_out("test_mails/encrypt_to_david.eml", outdata);
    free(outdata);
#endif
    
    free_message(msg);
    free_message(enc_msg);
    free_stringlist(found_key);
}    

TEST_F(PassphraseTest, check_erwin_primary_enc_subkey_encrypted_plus_unenc_sign_nopass_encrypt) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_EQ(found_key->next, nullptr);
    
    const char* my_fpr = alice_fpr;
    const char* my_name = "Alice Malice";
    const char* my_address = "alice_malice@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));    
    const char* to_fpr = erwin_fpr;
    const char* to_name = "Irv Nerve";
    const char* to_address = "irv_nerve@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, PEP_OWN_USERID, to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = my_ident;
    msg->to = new_identity_list(to_ident);
    msg->shortmsg = strdup("This is an exciting message from Alice!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);

#if PPTEST_DUMP   
    char* outdata = NULL;
    mime_encode_message(enc_msg, false, &outdata, false);
    dump_out("test_mails/encrypt_to_erwin.eml", outdata);
    free(outdata);
#endif
    
    free_message(msg);
    free_message(enc_msg);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_bob_primary_pass_subkey_no_passphrase_nopass_decrypt) {
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(found_key, nullptr);
    ASSERT_NE(found_key->value, nullptr);
    ASSERT_STREQ(found_key->value, bob_fpr);
    ASSERT_EQ(found_key->next, nullptr);

    const char* my_fpr = bob_fpr;
    const char* my_name = "Bob Mob";
    const char* my_address = "bob_mob@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    // Set up "to"
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));    
    const char* to_fpr = alice_fpr;
    const char* to_name = "Alice Malice";
    const char* to_address = "alice_malice@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, PEP_OWN_USERID, to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    string msg = slurp("test_mails/encrypt_to_bob.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;  
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(decrypted_msg, nullptr);
    
    free(decrypted_msg);
    free(modified_src);
    free_stringlist(keylist_used);
}

TEST_F(PassphraseTest, check_carol_primary_unenc_subkeys_passphrase_nopass_decrypt) {
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
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));    
    const char* to_fpr = alice_fpr;
    const char* to_name = "Alice Malice";
    const char* to_address = "alice_malice@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, PEP_OWN_USERID, to_name);
    status = set_identity(session, to_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    string msg = slurp("test_mails/encrypt_to_carol.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;  
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    ASSERT_NE(status, PEP_STATUS_OK);
    ASSERT_EQ(decrypted_msg, nullptr);
    
    free(decrypted_msg);
    free(modified_src);
    free_stringlist(keylist_used);
}    
