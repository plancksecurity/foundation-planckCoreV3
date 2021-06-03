#include <stdlib.h>
#include <string>
#include <cstring>
#include <fstream>
#include <iostream>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"


#include <gtest/gtest.h>


namespace {

	//The fixture for UnencryptedPepMailTest
    class UnencryptedPepMailTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            UnencryptedPepMailTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~UnencryptedPepMailTest() override {
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

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the UnencryptedPepMailTest suite.

    };

}  // namespace

// Check to see if a first unencrypted mail is pEpified
TEST_F(UnencryptedPepMailTest, check_unencrypted_pep_mail_outgoing) {
    pEp_identity* alice = NULL;
    pEp_identity* dave = NULL;

    PEP_STATUS status = set_up_preset(session, ALICE,
                                      true, true, true, true, true, true, &alice);

    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(alice);
/*
PEP_STATUS set_up_preset(PEP_SESSION session,
                         pEp_test_ident_preset preset_name,
                         bool set_ident,
                         bool set_pep,
                         bool trust,
                         bool set_own,
                         bool setup_private,
                         pEp_identity** ident) {
*/


    dave = new_identity("pep-test-dave@pep-project.org", NULL, NULL, "The Hoff");
    
    message* msg = new_message(PEP_dir_outgoing);
    
    msg->from = alice;
    msg->to = new_identity_list(dave);
    msg->shortmsg = strdup("No, I will *not* get into your car");
    msg->longmsg = strdup("Look, Dave... it's creepy. I'm not getting into your car.\n\n" 
                          "I do not want a cup of 'Hoffee', and you are not singlehandedly\n" 
                          "responsible for bringing down the Berlin Wall.\n\nGo away. - Alice");

    PEP_encrypt_flags_t flags = 0;
    message* enc_msg = NULL;
    
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, flags);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    ASSERT_TRUE(is_pEpmsg(msg));
    
    // char* outmsg = NULL;
    // mime_encode_message(msg, false, &outmsg, false);
    // ofstream outfile;
    // outfile.open("tmp/unenc_pep_msg_test_1.eml");
    // outfile << outmsg;
    // outfile.close();
    free_message(msg);
}

// Check to see if a first unencrypted mail is pEpified
TEST_F(UnencryptedPepMailTest, check_unencrypted_pep_mail_outgoing_MIME) {
    pEp_identity* alice = NULL;
    pEp_identity* dave = NULL;

    PEP_STATUS status = set_up_preset(session, ALICE,
                                      true, true, true, true, true, true, &alice);

    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(alice);
/*
PEP_STATUS set_up_preset(PEP_SESSION session,
                         pEp_test_ident_preset preset_name,
                         bool set_ident,
                         bool set_pep,
                         bool trust,
                         bool set_own,
                         bool setup_private,
                         pEp_identity** ident) {
*/


    dave = new_identity("pep-test-dave@pep-project.org", NULL, NULL, "The Hoff");
    
    message* msg = new_message(PEP_dir_outgoing);
    
    msg->from = alice;
    msg->to = new_identity_list(dave);
    msg->shortmsg = strdup("No, I will *not* get into your car");
    msg->longmsg = strdup("Look, Dave... it's creepy. I'm not getting into your car.\n\n" 
                          "I do not want a cup of 'Hoffee', and you are not singlehandedly\n" 
                          "responsible for bringing down the Berlin Wall.\n\nGo away. - Alice");
    char* outmsg = NULL;
    mime_encode_message(msg, false, &outmsg, false);
    char* encmsg = NULL;
        
    status = MIME_encrypt_message(session, outmsg, strlen(outmsg), NULL, &encmsg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    ASSERT_NOTNULL(encmsg);
    
    const char* contains = NULL;
    
    contains = strstr(encmsg, "X-pEp-Version");
    ASSERT_NOTNULL(encmsg);
    
    // char* outmsg = NULL;
    // mime_encode_message(msg, false, &outmsg, false);
    // ofstream outfile;
    // outfile.open("tmp/unenc_pep_msg_test_1.eml");
    // outfile << outmsg;
    // outfile.close();
    free_message(msg);
}

TEST_F(UnencryptedPepMailTest, check_unencrypted_pep_message_rcpt) {
    string msgstr = slurp("test_mails/unenc_pep_msg_test_1.eml");
    PEP_STATUS status = set_up_preset(session, DAVE,
                                      true, true, true, true, true, true, NULL);
    ASSERT_EQ(status, PEP_STATUS_OK);
    message* dec_msg = NULL;
    message* enc_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    
    mime_decode_message(msgstr.c_str(), msgstr.size(), &enc_msg, NULL);
    ASSERT_TRUE(is_pEpmsg(enc_msg));
    
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_TRUE(is_pEpmsg(enc_msg));    
    status = update_identity(session, enc_msg->from);
    ASSERT_EQ(enc_msg->from->comm_type, PEP_ct_pEp_unconfirmed);
    
}
