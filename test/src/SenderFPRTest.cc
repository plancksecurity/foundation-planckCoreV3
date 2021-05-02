// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include "test_util.h"
#include "TestConstants.h"

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "mime.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for SenderFPRTest
    class SenderFPRTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            SenderFPRTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~SenderFPRTest() override {
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
            // Objects declared here can be used by all tests in the SenderFPRTest suite.

    };

}  // namespace


TEST_F(SenderFPRTest, check_sender_f_p_r) {
    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                "pep.test.alice@pep-project.org", alice_fpr,
                PEP_OWN_USERID, "Alice in Wonderland", NULL, true
            );
    ASSERT_OK;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"));


    message* msg = new_message(PEP_dir_outgoing);
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", "Bob", "Bob");
    status = myself(session, alice);
    ASSERT_OK;
    status = set_identity(session, bob);
    ASSERT_OK;
    status = update_identity(session, bob);
    ASSERT_OK;
    status = set_as_pEp_user(session, bob);
    ASSERT_OK;

    msg->to = new_identity_list(bob);
    msg->from = alice;
    msg->shortmsg = strdup("Yo Bob!");
    msg->longmsg = strdup("Look at my hot new sender fpr field!");

    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;
    ASSERT_NULL(stringpair_list_find(enc_msg->opt_fields, "X-pEp-Sender-FPR"));

    message* dec_msg = NULL;

    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    char* text = NULL;
    mime_encode_message(dec_msg, false, &text, false);
    output_stream << text << endl;
    free(text);

    stringpair_list_t* fpr_node = stringpair_list_find(dec_msg->opt_fields, "X-pEp-Sender-FPR");
    ASSERT_NOTNULL(fpr_node);
    ASSERT_STREQ(fpr_node->value->value, alice_fpr);
}
