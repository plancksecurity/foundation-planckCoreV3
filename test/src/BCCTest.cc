// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <assert.h>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "message_api.h"
#include "TestConstants.h"

#include "TestUtilities.h"


#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for BCCTest
    class BCCTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            BCCTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~BCCTest() override {
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
                
                string keystr = slurp("test_keys/priv/bcc_test_dude_0-0x1CCCFC41_priv.asc");
                PEP_STATUS status = import_key(session, keystr.c_str(), keystr.size(), NULL);
                ASSERT_TRUE(status == PEP_TEST_KEY_IMPORT_SUCCESS);    
                pEp_identity * me = new_identity("bcc_test_dude_0@darthmama.cool", "0AE9AA3E320595CF93296BDFA155AC491CCCFC41", PEP_OWN_USERID, "BCC Test Sender");    
                status = set_own_key(session, me, "0AE9AA3E320595CF93296BDFA155AC491CCCFC41");
                keystr = slurp("test_keys/pub/bcc_test_dude_0-0x1CCCFC41_pub.asc");
                status = import_key(session, keystr.c_str(), keystr.size(), NULL);
                ASSERT_TRUE(status == PEP_TEST_KEY_IMPORT_SUCCESS);
                keystr = slurp("test_keys/pub/bcc_test_dude_1-0xDAC746BE_pub.asc");
                status = import_key(session, keystr.c_str(), keystr.size(), NULL);
                ASSERT_TRUE(status == PEP_TEST_KEY_IMPORT_SUCCESS);
                keystr = slurp("test_keys/pub/bcc_test_dude_2-0x53CECCF7_pub.asc");
                status = import_key(session, keystr.c_str(), keystr.size(), NULL);
                ASSERT_TRUE(status == PEP_TEST_KEY_IMPORT_SUCCESS);    

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
            // Objects declared here can be used by all tests in the BCCTest suite.

    };

}  // namespace

TEST_F(BCCTest, check_single_BCC) {
    PEP_STATUS status = PEP_UNKNOWN_ERROR;

    // 0AE9AA3E320595CF93296BDFA155AC491CCCFC41
    // D0AF2F9695E186A8DC058B935FE2793DDAC746BE
    // B36E468E7A381946FCDBDDFA84B1F3E853CECCF7
    pEp_identity* sender = new_identity("bcc_test_dude_0@darthmama.cool", NULL, PEP_OWN_USERID, "BCC Test Sender");

    // Now require explicit sets in the new world order... Key election removal FTW!
    pEp_identity* open_recip = new_identity("bcc_test_dude_1@darthmama.cool", "B36E468E7A381946FCDBDDFA84B1F3E853CECCF7", "TOFU_bcc_test_dude_1@darthmama.cool", "BCC Test Recip");
    pEp_identity* bcc_recip = new_identity("bcc_test_dude_2@darthmama.cool", "B36E468E7A381946FCDBDDFA84B1F3E853CECCF7", "TOFU_bcc_test_dude_2@darthmama.cool", "BCC Super Sekrit Test Recip");

    status = set_identity(session, open_recip);
    ASSERT_OK;
    status = set_identity(session, bcc_recip);
    ASSERT_OK;

    message *msg = new_message(PEP_dir_outgoing);
    ASSERT_NOTNULL(msg);
    msg->from = sender;
//    msg->to = new_identity_list(open_recip); FYI, this is supposed to fail for now. Unfortunately.
    msg->bcc = new_identity_list(bcc_recip);
    msg->shortmsg = strdup("Hello, world");
    msg->longmsg = strdup("Your mother was a hamster and your father smelt of elderberries.");
    msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    message *enc_msg = nullptr;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);

    ASSERT_EQ(status, PEP_STATUS_OK);
    free_message(msg);
    free_message(enc_msg);
}
