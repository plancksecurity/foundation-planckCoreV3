#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "test_util.h"
#include "keymanagement.h"
#include "message_api.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for ReceiveFromMistrustedTest
    class ReceiveFromMistrustedTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;
            const char* alicemail_filename = "test_mails/simple_alice_to_bob_pEp_2.1.eml";

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            ReceiveFromMistrustedTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~ReceiveFromMistrustedTest() override {
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

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the ReceiveFromMistrustedTest suite.

    };

}  // namespace

#if 0
TEST_F(ReceiveFromMistrustedTest, generate_test_mails) {
    pEp_identity* alice = NULL;
    PEP_STATUS status = set_up_preset(session, ALICE, true, true, true, true, true, &alice);
    ASSERT_OK;
    pEp_identity* bob = NULL;
    status = set_up_preset(session, BOB, true, true, false, false, false, &bob);

    message* dec_msg = new_message(PEP_dir_outgoing);
    dec_msg->from = alice;
    dec_msg->to = new_identity_list(bob);
    dec_msg->shortmsg = strdup("Yo Bob! Come crash at my place!");
    dec_msg->longmsg = strdup("I am Alice, queen of dad jokes!");

    message* enc_msg = NULL;
    status = encrypt_message(session, dec_msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;
    char* enc_str = NULL;
    mime_encode_message(enc_msg, false, &enc_str, false);
    ASSERT_NE(enc_str, nullptr);
    dump_out(alicemail_filename, enc_str);
    free_message(dec_msg);
    free_message(enc_msg);
    free(enc_str);
}
#endif

TEST_F(ReceiveFromMistrustedTest, check_receive_from_mistrusted_simple) {
    // Easy case of JNI-153 *perhaps*
    // Bob mistrusts Alice and receives a message from her
    pEp_identity* me = NULL;
    PEP_STATUS status = set_up_preset(session, BOB, true, true, true, true, true, &me);
    ASSERT_OK;

    const char* alicefpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";

    pEp_identity* alice = NULL;
    status = set_up_preset(session, ALICE, false, false, false, false, false, &alice);
    ASSERT_OK;
    alice->fpr = strdup(alicefpr);
    free(alice->user_id);
    alice->user_id = strdup("TOFU_pep.test.apple@pep-project.org");
    status = set_identity(session, alice);
    ASSERT_OK;
    status = set_as_pEp_user(session, alice);
    ASSERT_OK;

    // Alice is now in the DB. Let's mistrust her key
    status = key_mistrusted(session, alice);
    ASSERT_OK;
    ASSERT_OK;

    string mail = slurp(alicemail_filename);
    message* inmail = string_to_msg(mail);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, inmail, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    free_message(dec_msg);
    free_identity(me);
    free_identity(alice);
}

TEST_F(ReceiveFromMistrustedTest, check_receive_from_mistrusted_TOFU_split) {
    pEp_identity* me = NULL;
    PEP_STATUS status = set_up_preset(session, BOB, true, true, true, true, true, &me);
    ASSERT_OK;

    const char* alicefpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";

    // JNI-153 DB looks like this:
    // It first gets a TOFU identity...
    pEp_identity* alice = NULL;
    status = set_up_preset(session, ALICE, false, false, false, false, false, &alice);
    ASSERT_OK;
    alice->fpr = strdup(alicefpr);
    free(alice->user_id);
    alice->user_id = strdup("TOFU_pep.test.apple@pep-project.org");
    status = set_identity(session, alice);
    ASSERT_OK;
    status = update_identity(session, alice);
    ASSERT_EQ(alice->comm_type, PEP_ct_OpenPGP_unconfirmed);

    free_identity(alice);
    alice = NULL;
    status = set_up_preset(session, ALICE, false, false, false, false, false, &alice);
    ASSERT_OK;
    alice->fpr = strdup(alicefpr);
    free(alice->user_id);
    alice->user_id = strdup("ALICE");
    status = set_identity(session, alice);
    ASSERT_OK;
    status = set_as_pEp_user(session, alice);
    ASSERT_OK;
    status = set_trust(session, alice);
    ASSERT_OK;

    // Explicitly DON'T call update_identity here.

    // Now, let's mistrust her key
    // Let's mistrust her key
    status = key_mistrusted(session, alice);
    ASSERT_OK;

    string mail = slurp(alicemail_filename);
    message* inmail = string_to_msg(mail);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, inmail, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_EQ(rating, PEP_rating_mistrust);
    free_message(dec_msg);
    free_identity(me);
    free_identity(alice);
}

