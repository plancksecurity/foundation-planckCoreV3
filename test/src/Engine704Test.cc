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

	//The fixture for Engine704Test
    class Engine704Test : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            Engine704Test() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~Engine704Test() override {
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
            // Objects declared here can be used by all tests in the Engine704Test suite.

    };

}  // namespace


TEST_F(Engine704Test, check_engine704) {
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* alice = NULL;
    status = set_up_preset(session, ALICE, true, true, true, true, true, true, &alice);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(alice);
    status = myself(session, alice);
    char* alicename = strdup(alice->username);
    
    pEp_identity* alice_is_bob = NULL;
    status = set_up_preset(session, BOB, false, true, true, true, false, true, &alice_is_bob);
    alice_is_bob->fpr = strdup("BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39");
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(alice_is_bob);
    alice_is_bob->user_id = strdup(alice->user_id);
    alice_is_bob->me = true;
    char* bob_key_copy = strdup(alice_is_bob->fpr);
    // set_own_key contains myself. But let's try the external function,
    status = set_own_key(session, alice_is_bob, bob_key_copy);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(alice_is_bob->username, alicename);   
    // set_own_key contains myself. But let's try the external function,        
    status = myself(session, alice_is_bob);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STRNE(alice_is_bob->username, alicename);   
    
    // Make sure alice didn't take on Bob properties    
    status = myself(session, alice);
    ASSERT_STREQ(alice->username, alicename);
    
    // Ok then... let's just try to encrypt and decrypt a message 
    pEp_identity* alice2 = new_identity(alice->address, NULL, alice->user_id, alice->username);
    pEp_identity* bob = new_identity(alice_is_bob->address, NULL, alice_is_bob->user_id, alice_is_bob->username);
    ASSERT_STRNE(alice->username, alice_is_bob->username);
    char* bobname = strdup(alice_is_bob->username);
    message* cheesy_message = new_message(PEP_dir_outgoing);
    cheesy_message->from = alice2;
    cheesy_message->to = new_identity_list(bob);
    cheesy_message->shortmsg = strdup("This is from Alice, fools.");
    cheesy_message->longmsg = strdup("I am totally not Bob. If I were Bob, I would not be sending messages to myself.");
    
    message* enc_msg = NULL;
    
    status = encrypt_message(session, cheesy_message, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_STREQ(enc_msg->from->username, alicename);
    ASSERT_STREQ(enc_msg->to->ident->username, bobname);
    
    message* dec_msg = NULL;
    enc_msg->dir = PEP_dir_incoming;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);    
    ASSERT_STREQ(dec_msg->from->username, alicename);
    ASSERT_STREQ(dec_msg->to->ident->username, bobname);    
}
