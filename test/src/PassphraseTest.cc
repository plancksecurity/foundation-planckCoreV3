#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "TestUtilities.h"
#include "TestConstants.h"
#include "Engine.h"
#include <fstream>

#include <gtest/gtest.h>

#define PPTEST_DUMP 0

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
                ASSERT_NOTNULL(engine);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NOTNULL(engine->session);
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
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_NULL(found_key->next);
    free_stringlist(found_key);
    
#if PPTEST_DUMP
    char* keytext = NULL;
    size_t size = 0;
    export_key(session, alice_fpr, &keytext, &size);
    dump_out("test_keys/pub/alice-0x2A649B9F_pub.asc", keytext);
    free(keytext);
#endif    
}

TEST_F(PassphraseTest, check_bob_primary_pass_subkey_no_passphrase_nopass_import) {
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, bob_fpr);
    ASSERT_NULL(found_key->next);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_carol_primary_unenc_subkeys_passphrase_nopass_import) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_NULL(found_key->next);
    free_stringlist(found_key);

#if PPTEST_DUMP
    char* keytext = NULL;
    size_t size = 0;
    status = export_key(session, carol_fpr, &keytext, &size);
    ASSERT_EQ(status, PEP_STATUS_OK);
    dump_out("test_keys/pub/carol-0xCD8BAC06_pub.asc", keytext);
    free(keytext);
#endif    
    
}

TEST_F(PassphraseTest, check_david_primary_unenc_sign_and_encrypt_diff_pass_two_sign_unencrypted_nopass_import) {
    ASSERT_TRUE(slurp_and_import_key(session, david_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, david_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, david_fpr);
    ASSERT_NULL(found_key->next);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_erwin_primary_enc_subkey_encrypted_plus_unenc_sign_nopass_import) {
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, erwin_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, erwin_fpr);
    ASSERT_NULL(found_key->next);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_alice_no_passphrase_nopass_sign_encrypt) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_NULL(found_key->next);
    
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
    ASSERT_NOTNULL(enc_msg);
    
    free_message(msg);
    free_message(enc_msg);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_alice_no_passphrase_nopass_sign_encrypt_to_carol) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_NULL(found_key->next);
    
    const char* my_fpr = alice_fpr;
    const char* my_name = "Alice Malice";
    const char* my_address = "alice_malice@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/carol-0xCD8BAC06_pub.asc"));
    const char* to_fpr = carol_fpr;
    const char* to_name = "Carol Peril";
    const char* to_address = "carol_peril@darthmama.cool";
    pEp_identity* to_ident = new_identity(to_address, to_fpr, "CAROL", to_name);
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
    ASSERT_NOTNULL(enc_msg);
    
    free_message(msg);
    free_message(enc_msg);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_bob_primary_pass_subkey_no_passphrase_nopass_sign) {
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, bob_fpr);
    ASSERT_NULL(found_key->next);

    const char* my_fpr = bob_fpr;
    const char* my_name = "Bob Mob";
    const char* my_address = "bob_mob@darthmama.cool";
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
    msg->shortmsg = strdup("This is an exciting message from Bob!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_PASSPHRASE_REQUIRED);
    ASSERT_NULL(enc_msg);
    
    free_message(msg);
    free_message(enc_msg);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_carol_primary_unenc_subkeys_passphrase_nopass_sign) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_NULL(found_key->next);
    
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
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(enc_msg);
    
    free_message(msg);
    free_message(enc_msg);    
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_david_primary_unenc_sign_and_encrypt_diff_pass_two_sign_unencrypted_nopass_sign) {
    ASSERT_TRUE(slurp_and_import_key(session, david_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, david_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, david_fpr);
    ASSERT_NULL(found_key->next);
    
    const char* my_fpr = david_fpr;
    const char* my_name = "Dave Rave";
    const char* my_address = "dave_rave@darthmama.cool";
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
    msg->shortmsg = strdup("This is an exciting message from David!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(enc_msg);
    
    free_message(msg);
    free_message(enc_msg);        
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_erwin_primary_enc_subkey_encrypted_plus_unenc_sign_nopass_sign) {
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, erwin_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, erwin_fpr);
    ASSERT_NULL(found_key->next);
    
    const char* my_fpr = erwin_fpr;
    const char* my_name = "Irv Nerve";
    const char* my_address = "irv_nerve@darthmama.cool";
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
    msg->shortmsg = strdup("This is an exciting message from Erwin!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(enc_msg);
    
    free_message(msg);
    free_message(enc_msg);            
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_bob_primary_pass_subkey_no_passphrase_nopass_encrypt) {
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_NULL(found_key->next);
    
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
    pEp_identity* to_ident = new_identity(to_address, to_fpr, "BOB", to_name);
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
    ASSERT_NOTNULL(enc_msg);
    
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
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_NULL(found_key->next);
    
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
    pEp_identity* to_ident = new_identity(to_address, to_fpr, "CAROL", to_name);
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
    ASSERT_NOTNULL(enc_msg);

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
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_NULL(found_key->next);
    
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
    pEp_identity* to_ident = new_identity(to_address, to_fpr, "DAVID", to_name);
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
    ASSERT_NOTNULL(enc_msg);
    
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
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_NULL(found_key->next);
    
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
    pEp_identity* to_ident = new_identity(to_address, to_fpr, "ERWIN", to_name);
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
    ASSERT_NOTNULL(enc_msg);

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
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, bob_fpr);
    ASSERT_NULL(found_key->next);

    const char* my_fpr = bob_fpr;
    const char* my_name = "Bob Mob";
    const char* my_address = "bob_mob@darthmama.cool";
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
    
    message* enc_msg = slurp_message_file_into_struct("test_mails/encrypt_to_bob.eml");
    message* decrypted_msg = NULL;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(decrypted_msg);

    free_message(enc_msg);
    free_message(decrypted_msg);
    free_stringlist(keylist_used);
}

TEST_F(PassphraseTest, check_carol_primary_unenc_subkeys_passphrase_nopass_decrypt) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_NULL(found_key->next);
    
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
    
    message* enc_msg = slurp_message_file_into_struct("test_mails/encrypt_to_carol.eml");
    message* decrypted_msg = NULL;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    ASSERT_EQ(status, PEP_PASSPHRASE_REQUIRED);
    ASSERT_NULL(decrypted_msg);

    free_message(enc_msg);
    free_message(decrypted_msg);
    free_stringlist(keylist_used);
}    

TEST_F(PassphraseTest, check_alice_no_passphrase_withpass_sign_encrypt) {    
    ASSERT_TRUE(slurp_and_import_key(session, alice_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, alice_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, alice_fpr);
    ASSERT_NULL(found_key->next);
    
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
    
    // Alice doesn't have a password, but we're gonna set one anyway
    const char* pass = "wombat";
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);

        
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(enc_msg);
    
    free_message(msg);
    free_message(enc_msg);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_bob_primary_pass_subkey_no_passphrase_withpass_sign) {
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, bob_fpr);
    ASSERT_NULL(found_key->next);

    const char* my_fpr = bob_fpr;
    const char* my_name = "Bob Mob";
    const char* my_address = "bob_mob@darthmama.cool";
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
    msg->shortmsg = strdup("This is an exciting message from Bob!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    const char* pass = "bob";
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);

    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(enc_msg);
    
#if PPTEST_DUMP   
    char* outdata = NULL;
    mime_encode_message(enc_msg, false, &outdata, false);
    dump_out("test_mails/signed_by_bob.eml", outdata);
    free(outdata);
#endif
    
    free_message(msg);
    free_message(enc_msg);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_carol_primary_unenc_subkeys_passphrase_withpass_sign) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_NULL(found_key->next);
    
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

    const char* pass = "carol";
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);

    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(enc_msg);
    
    free_message(msg);
    free_message(enc_msg);    
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_david_primary_unenc_sign_and_encrypt_diff_pass_two_sign_unencrypted_withpass_sign) {
    ASSERT_TRUE(slurp_and_import_key(session, david_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, david_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, david_fpr);
    ASSERT_NULL(found_key->next);
    
    const char* my_fpr = david_fpr;
    const char* my_name = "Dave Rave";
    const char* my_address = "dave_rave@darthmama.cool";
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
    msg->shortmsg = strdup("This is an exciting message from David!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    const char* pass = "sign";
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);

    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(enc_msg);
    
    free_message(msg);
    free_message(enc_msg);        
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_erwin_primary_enc_subkey_encrypted_plus_unenc_sign_withpass_sign) {
    ASSERT_TRUE(slurp_and_import_key(session, erwin_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, erwin_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, erwin_fpr);
    ASSERT_NULL(found_key->next);
    
    const char* my_fpr = erwin_fpr;
    const char* my_name = "Irv Nerve";
    const char* my_address = "irv_nerve@darthmama.cool";
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
    msg->shortmsg = strdup("This is an exciting message from Erwin!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");  
    
    const char* pass = "erwin";
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(enc_msg);
    
    free_message(msg);
    free_message(enc_msg);            
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_carol_primary_unenc_subkeys_passphrase_withpass_decrypt) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_NULL(found_key->next);
    
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
    
    const char* pass = "carol";
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);    
    
    message* enc_msg = slurp_message_file_into_struct("test_mails/encrypt_to_carol.eml");
    message* decrypted_msg = NULL;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(decrypted_msg);

    free_message(enc_msg);
    free_message(decrypted_msg);
    free_stringlist(keylist_used);
}    

TEST_F(PassphraseTest, check_carol_primary_unenc_subkeys_passphrase_wrongpass_decrypt) {
    ASSERT_TRUE(slurp_and_import_key(session, carol_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, carol_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, carol_fpr);
    ASSERT_NULL(found_key->next);
    
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
    
    const char* pass = "biteme";
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);    
    
    message* enc_msg = slurp_message_file_into_struct("test_mails/encrypt_to_carol.eml");
    message* decrypted_msg = NULL;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_NULL(decrypted_msg);

    free_message(enc_msg);
    free_message(decrypted_msg);
    free_stringlist(keylist_used);
}    

TEST_F(PassphraseTest, check_bob_primary_pass_subkey_no_passphrase_wrongpass_sign) {
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, bob_fpr);
    ASSERT_NULL(found_key->next);

    const char* my_fpr = bob_fpr;
    const char* my_name = "Bob Mob";
    const char* my_address = "bob_mob@darthmama.cool";
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
    msg->shortmsg = strdup("This is an exciting message from Bob!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    const char* pass = "biteme";
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);    
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_NULL(enc_msg);
    
    free_message(msg);
    free_message(enc_msg);
    free_stringlist(found_key);
}

TEST_F(PassphraseTest, check_fenris_encrypted_key_generate_with_passphrase) {
    const char* pass = "lyrium";    
    PEP_STATUS status = config_passphrase_for_new_keys(session, true, pass);
    ASSERT_EQ(status, PEP_STATUS_OK);    
    pEp_identity* my_ident = new_identity("fenris@darthmama.org", NULL, "FENRIS", "Fenris Hawke");    
    status = myself(session, my_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(my_ident->fpr);
    
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
    msg->shortmsg = strdup("This is an exciting message from Fenris!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);    
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(enc_msg);
    
    free_message(msg);
    free_message(enc_msg);
}

TEST_F(PassphraseTest, check_fenris_encrypted_key_generate_with_passphrase_decrypt_nopass) {
    PEP_STATUS status = config_passphrase_for_new_keys(session, true, "lyrium");
    ASSERT_EQ(status, PEP_STATUS_OK);    
    pEp_identity* my_ident = new_identity("fenris@darthmama.org", NULL, "FENRIS", "Fenris Hawke");    
    status = myself(session, my_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(my_ident->fpr);
    
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
    msg->shortmsg = strdup("This is an exciting message from Fenris!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
        
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_PASSPHRASE_REQUIRED);
    ASSERT_NULL(enc_msg);
    
    free_message(msg);
}

TEST_F(PassphraseTest, check_fenris_encrypted_key_generate_with_passphrase_decrypt) {
    const char* pass = "lyrium";    
    PEP_STATUS status = config_passphrase_for_new_keys(session, true, pass);
    ASSERT_EQ(status, PEP_STATUS_OK);    
    pEp_identity* my_ident = new_identity("fenris@darthmama.org", NULL, "FENRIS", "Fenris Hawke");    
    status = myself(session, my_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(my_ident->fpr);
    
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
    msg->shortmsg = strdup("This is an exciting message from Fenris!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);    
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(enc_msg);
    
    free_message(msg);
    msg = NULL;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &msg, &keylist_used, &rating, &flags);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(msg);

    free_message(msg);    
    free_message(enc_msg);    
}

TEST_F(PassphraseTest, check_fenris_encrypted_key_generate_with_passphrase_decrypt_wrongphrase) {
    const char* pass = "lyrium";    
    PEP_STATUS status = config_passphrase_for_new_keys(session, true, pass  );
    ASSERT_EQ(status, PEP_STATUS_OK);    
    pEp_identity* my_ident = new_identity("fenris@darthmama.org", NULL, "FENRIS", "Fenris Hawke");    
    status = myself(session, my_ident);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(my_ident->fpr);
    
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
    msg->shortmsg = strdup("This is an exciting message from Fenris!");
    msg->longmsg = strdup("Not\nVery\nExciting\n");   
    
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);    
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(enc_msg);

    pass = "bob";
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);    
    
    free_message(msg);
    msg = NULL;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &msg, &keylist_used, &rating, &flags);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_NULL(msg);

    free_message(enc_msg);    
}

TEST_F(PassphraseTest, check_sign_only_nopass) {
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, bob_fpr);
    ASSERT_NULL(found_key->next);
    free_stringlist(found_key);
    
    const char* my_fpr = bob_fpr;
    const char* my_name = "Bob Mob";
    const char* my_address = "bob_mob@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
            
    string msg_text = "Grrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr! I mean, yo. Greetings to Meesti.\n - Alice";
    ofstream test_file;
    test_file.open("tmp/signed_text.txt");
    test_file << msg_text;
    test_file.close();
    char* signed_text = NULL;
    size_t signed_text_size = 0;

    stringlist_t* keylist = NULL;

    status = sign_only(session, msg_text.c_str(), msg_text.size(), bob_fpr, &signed_text, &signed_text_size);
    ASSERT_EQ(status, PEP_PASSPHRASE_REQUIRED);

    // FIXME: free stuff    
}

TEST_F(PassphraseTest, check_sign_only_withpass) {
    
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    ASSERT_STREQ(found_key->value, bob_fpr);
    ASSERT_NULL(found_key->next);
    free_stringlist(found_key);
    
    const char* my_fpr = bob_fpr;
    const char* my_name = "Bob Mob";
    const char* my_address = "bob_mob@darthmama.cool";
    pEp_identity* my_ident = new_identity(my_address, my_fpr, PEP_OWN_USERID, my_name);
    status = set_own_key(session, my_ident, my_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
        
    const char* pass = "bob";
    status = config_passphrase(session, pass);    
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    string msg_text = "Grrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr! I mean, yo. Greetings to Meesti.\n - Alice";
    ofstream test_file;
    test_file.open("tmp/signed_text.txt");
    test_file << msg_text;
    test_file.close();
    char* signed_text = NULL;
    size_t signed_text_size = 0;

    stringlist_t* keylist = NULL;

    status = sign_only(session, msg_text.c_str(), msg_text.size(), bob_fpr, &signed_text, &signed_text_size);
    ASSERT_EQ(status, PEP_STATUS_OK);
    output_stream << signed_text << endl;
    test_file.open("tmp/signature.txt");
    test_file << signed_text;
    test_file.close();

    status = verify_text(session, msg_text.c_str(), msg_text.size(),
                         signed_text, signed_text_size, &keylist);

    ASSERT_EQ(status , PEP_VERIFIED);
    ASSERT_NOTNULL(keylist);
    ASSERT_NOTNULL(keylist->value);
    ASSERT_STREQ(keylist->value, bob_fpr);

    // FIXME: free stuff
}
