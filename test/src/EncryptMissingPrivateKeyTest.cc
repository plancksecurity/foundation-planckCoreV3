// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()
#include <assert.h>

#include "blacklist.h"
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"
#include "test_util.h"

#include "pEpEngine.h"
#include "pEp_internal.h"




#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for EncryptMissingPrivateKeyTest
    class EncryptMissingPrivateKeyTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            EncryptMissingPrivateKeyTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~EncryptMissingPrivateKeyTest() override {
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
                string recip_key = slurp("test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
                PEP_STATUS status = import_key(session, recip_key.c_str(), recip_key.size(), NULL);
                ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);

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
            // Objects declared here can be used by all tests in the EncryptMissingPrivateKeyTest suite.

    };

}  // namespace


TEST_F(EncryptMissingPrivateKeyTest, check_encrypt_missing_private_key) {

    pEp_identity* no_key_identity = new_identity("blacklistself@kgrothoff.org",
                                                      NULL,
                                                      PEP_OWN_USERID,
                                                      "Blacklist Self");
    no_key_identity->me = true;
    PEP_STATUS status8 = myself(session, no_key_identity);
    ASSERT_EQ(status8, PEP_STATUS_OK);

    /* Now let's try to encrypt a message. */

    message* tmp_msg = NULL;
    message* enc_msg = NULL;

    const string mailtext = slurp("test_mails/blacklist_no_key.eml");

    PEP_STATUS status = mime_decode_message(mailtext.c_str(), mailtext.length(), &tmp_msg, NULL);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = update_identity(session, tmp_msg->from);
    identity_list* to_list = tmp_msg->to;

    while (to_list) {
        if (to_list->ident)
            update_identity(session, to_list->ident);
        to_list = to_list->next;
    }

    // This isn't incoming, though... so we need to reverse the direction
    tmp_msg->dir = PEP_dir_outgoing;
    status = encrypt_message(session,
                             tmp_msg,
                             NULL,
                             &enc_msg,
                             PEP_enc_PGP_MIME,
                             0);
    ASSERT_EQ(status, PEP_STATUS_OK);


    char* new_key = enc_msg->from->fpr;
    output_stream << "Encrypted with key " << new_key << endl;

    free_message(tmp_msg);
    free_message(enc_msg);
}
