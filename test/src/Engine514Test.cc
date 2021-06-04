#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "TestUtilities.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for Engine514Test
    class Engine514Test : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            Engine514Test() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~Engine514Test() override {
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
            // Objects declared here can be used by all tests in the Engine514Test suite.

    };

}  // namespace

TEST_F(Engine514Test, check_engine514_unencrypted) {
    // Next time, provide a sample for reproduction so I don't have to do crap like this. 
    // A text file will do just fine.
    
    // Create sample internal message attachment 
    
    message* not_the_msg = new_message(PEP_dir_outgoing);
    char* attachment_text = NULL;
    
    pEp_identity* not_from = new_identity("julio@iglesias.es", NULL, NULL, "Julio Iglesias");
    pEp_identity* not_to = new_identity("juan@valdez.co", NULL, NULL, "Juan Valdez");  
    not_the_msg->from = not_from;
    not_the_msg->to = new_identity_list(not_to);
    not_the_msg->shortmsg = strdup("This is an ATTACHMENT");
    not_the_msg->longmsg = strdup("Some body text here.");

    mime_encode_message(not_the_msg, false, &attachment_text, false);
    ASSERT_NOTNULL(attachment_text);
    free_message(not_the_msg);
        
    message* msg = new_message(PEP_dir_outgoing);
    pEp_identity* carol = NULL;                         
    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::CAROL, true, true, true, true, true, true, &carol);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(carol);
    status = myself(session, carol);
    ASSERT_EQ(status, PEP_STATUS_OK);

    pEp_identity* no_key = new_identity("random@hacker.org", NULL, NULL, "Some Guy");
    msg->from = carol;
    msg->to = new_identity_list(no_key);
    msg->shortmsg = strdup("This is the actual message");
    msg->longmsg = strdup("When things go wrong, as they usually will\nAnd your daily road seems all uphill\nWhen funds are low, and debts are high\nYou try to smile, but can only cry\nWhen you really feel you'd like to quit\nDon't run to me, I don't give aNO CARRIER\n");
    msg->attachments = new_bloblist(attachment_text, strlen(attachment_text), "message/rfc822", NULL); 
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    ASSERT_NULL(enc_msg);
    ASSERT_STREQ(msg->attachments->mime_type, "message/rfc822");
    ASSERT_NOTNULL(msg->attachments->next);
    
    // Funny, it's not reproduceable here.
    char* output_str = NULL;
    mime_encode_message(msg, false, &output_str, false);
    char* find_the_mimetype = strstr(output_str, "message/rfc822");
    ASSERT_NOTNULL(find_the_mimetype);
    find_the_mimetype = strstr(output_str, "text/rfc822");
    ASSERT_NULL(find_the_mimetype);            
}

TEST_F(Engine514Test, check_engine514_unencrypted_second_position) {
    // Next time, provide a sample for reproduction so I don't have to do crap like this. 
    // A text file will do just fine.
    
    // Create sample internal message attachment 
    
    message* not_the_msg = new_message(PEP_dir_outgoing);
    char* attachment_text = NULL;
    
    pEp_identity* not_from = new_identity("julio@iglesias.es", NULL, NULL, "Julio Iglesias");
    pEp_identity* not_to = new_identity("juan@valdez.co", NULL, NULL, "Juan Valdez");  
    not_the_msg->from = not_from;
    not_the_msg->to = new_identity_list(not_to);
    not_the_msg->shortmsg = strdup("This is an ATTACHMENT");
    not_the_msg->longmsg = strdup("Some body text here.");

    mime_encode_message(not_the_msg, false, &attachment_text, false);
    ASSERT_NOTNULL(attachment_text);
    free_message(not_the_msg);
        
    message* msg = new_message(PEP_dir_outgoing);
    pEp_identity* carol = NULL;                         
    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::CAROL, true, true, true, true, true, true, &carol);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(carol);
    status = myself(session, carol);
    ASSERT_EQ(status, PEP_STATUS_OK);

    pEp_identity* no_key = new_identity("random@hacker.org", NULL, NULL, "Some Guy");
    msg->from = carol;
    msg->to = new_identity_list(no_key);
    msg->shortmsg = strdup("This is the actual message");
    msg->longmsg = strdup("When things go wrong, as they usually will\nAnd your daily road seems all uphill\nWhen funds are low, and debts are high\nYou try to smile, but can only cry\nWhen you really feel you'd like to quit\nDon't run to me, I don't give aNO CARRIER\n");
    string blah = "Just some crap.";
    msg->attachments = new_bloblist(strdup(blah.c_str()), blah.size(), "text/plain", "text.txt");
    msg->attachments->next = new_bloblist(attachment_text, strlen(attachment_text), "message/rfc822", NULL); 
    
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    ASSERT_NULL(enc_msg);
    ASSERT_STREQ(msg->attachments->next->mime_type, "message/rfc822");
    ASSERT_NOTNULL(msg->attachments->next->next);
    
    // Still not reproduceable
    char* output_str = NULL;
    mime_encode_message(msg, false, &output_str, false);
    cout << output_str << endl;
    char* find_the_mimetype = strstr(output_str, "message/rfc822");
    ASSERT_NOTNULL(find_the_mimetype);
    find_the_mimetype = strstr(output_str, "text/rfc822");
    ASSERT_NULL(find_the_mimetype);            
}

TEST_F(Engine514Test, check_engine514_encode_and_decode) {
    message* not_the_msg = new_message(PEP_dir_outgoing);
    char* attachment_text = NULL;
    
    pEp_identity* not_from = new_identity("julio@iglesias.es", NULL, NULL, "Julio Iglesias");
    pEp_identity* not_to = new_identity("juan@valdez.co", NULL, NULL, "Juan Valdez");  
    not_the_msg->from = not_from;
    not_the_msg->to = new_identity_list(not_to);
    not_the_msg->shortmsg = strdup("This is an ATTACHMENT");
    not_the_msg->longmsg = strdup("Some body text here.");

    mime_encode_message(not_the_msg, false, &attachment_text, false);
    ASSERT_NOTNULL(attachment_text);
    free_message(not_the_msg);
        
    message* msg = new_message(PEP_dir_outgoing);
    pEp_identity* carol = NULL;                         
    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::CAROL, true, true, true, true, true, true, &carol);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(carol);
    status = myself(session, carol);
    ASSERT_EQ(status, PEP_STATUS_OK);

    pEp_identity* dave = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::DAVE, true, true, true, true, false, false, &dave);
    msg->from = carol;
    msg->to = new_identity_list(dave);
    msg->shortmsg = strdup("This is the actual message");
    msg->longmsg = strdup("When things go wrong, as they usually will\nAnd your daily road seems all uphill\nWhen funds are low, and debts are high\nYou try to smile, but can only cry\nWhen you really feel you'd like to quit\nDon't run to me, I don't give aNO CARRIER\n");
    msg->attachments = new_bloblist(attachment_text, strlen(attachment_text), "message/rfc822", NULL); 
    
    char* output_str = NULL;
    mime_encode_message(msg, false, &output_str, false);
    cout << output_str << endl;
    char* find_the_mimetype = strstr(output_str, "message/rfc822");
    ASSERT_NOTNULL(find_the_mimetype);
    find_the_mimetype = strstr(output_str, "text/rfc822");
    ASSERT_NULL(find_the_mimetype);            

    message* checker = NULL;
    mime_decode_message(output_str, strlen(output_str), &checker, NULL);    
    ASSERT_STREQ(checker->attachments->mime_type, "message/rfc822");    
}

// Still annoyed.
TEST_F(Engine514Test, check_engine514_encrypted) {    
    // Create sample internal message attachment 
    
    message* not_the_msg = new_message(PEP_dir_outgoing);
    char* attachment_text = NULL;
    
    pEp_identity* not_from = new_identity("julio@iglesias.es", NULL, NULL, "Julio Iglesias");
    pEp_identity* not_to = new_identity("juan@valdez.co", NULL, NULL, "Juan Valdez");  
    not_the_msg->from = not_from;
    not_the_msg->to = new_identity_list(not_to);
    not_the_msg->shortmsg = strdup("This is an ATTACHMENT");
    not_the_msg->longmsg = strdup("Some body text here.");

    mime_encode_message(not_the_msg, false, &attachment_text, false);
    ASSERT_NOTNULL(attachment_text);
    free_message(not_the_msg);
        
    message* msg = new_message(PEP_dir_outgoing);
    pEp_identity* carol = NULL;                         
    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::CAROL, true, true, true, true, true, true, &carol);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(carol);
    status = myself(session, carol);
    ASSERT_EQ(status, PEP_STATUS_OK);

    pEp_identity* dave = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::DAVE, true, true, true, true, false, false, &dave);
    msg->from = carol;
    msg->to = new_identity_list(dave);
    msg->shortmsg = strdup("This is the actual message");
    msg->longmsg = strdup("When things go wrong, as they usually will\nAnd your daily road seems all uphill\nWhen funds are low, and debts are high\nYou try to smile, but can only cry\nWhen you really feel you'd like to quit\nDon't run to me, I don't give aNO CARRIER\n");
    msg->attachments = new_bloblist(attachment_text, strlen(attachment_text), "message/rfc822", NULL); 
        
    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(enc_msg);
    
    message* dec_msg = NULL;
    PEP_decrypt_flags_t flags = 0;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_STATUS_OK);    
    ASSERT_STREQ(msg->attachments->mime_type, "message/rfc822");
    ASSERT_NULL(msg->attachments->next);
    
    // Funny, it's not reproduceable here.
    // char* output_str = NULL;
    // mime_encode_message(msg, false, &output_str, false);
    // char* find_the_mimetype = strstr(output_str, "message/rfc822");
    // ASSERT_NOTNULL(find_the_mimetype);
    // find_the_mimetype = strstr(output_str, "text/rfc822");
    // ASSERT_NULL(find_the_mimetype);            
}
