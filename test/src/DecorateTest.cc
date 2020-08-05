// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>
#include <sstream>
#include "mime.h"
#include "message_api.h"
#include "test_util.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for DecorateTest
    class DecorateTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            DecorateTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~DecorateTest() override {
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
            // Objects declared here can be used by all tests in the DecorateTest suite.

    };

}  // namespace


TEST_F(DecorateTest, check_decorate) {

    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string alice_priv_key = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    const string bob_pub_key = slurp("test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
    PEP_STATUS statuspub = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    PEP_STATUS statuspriv = import_key(session, alice_priv_key.c_str(), alice_priv_key.length(), NULL);
    PEP_STATUS statusbob = import_key(session, bob_pub_key.c_str(), bob_pub_key.length(), NULL);
    ASSERT_EQ(statuspub , PEP_TEST_KEY_IMPORT_SUCCESS);
    ASSERT_EQ(statuspriv , PEP_TEST_KEY_IMPORT_SUCCESS);
    ASSERT_EQ(statusbob , PEP_TEST_KEY_IMPORT_SUCCESS);

    output_stream << "creating message…\n";
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    pEp_identity* alice_dup = identity_dup(alice);
    PEP_STATUS status = set_own_key(session, alice_dup, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    ASSERT_EQ(status , PEP_STATUS_OK);
    free_identity(alice_dup);

    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test");
    alice->me = true;
    identity_list* to_list = new_identity_list(bob); // to bob
    message* outgoing_message = new_message(PEP_dir_outgoing);
    ASSERT_NE(outgoing_message, nullptr);
    outgoing_message->from = alice;
    outgoing_message->to = to_list;
    outgoing_message->shortmsg = strdup("Greetings, humans!");
    outgoing_message->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    outgoing_message->longmsg = strdup("This is a dumb message.\nBut it's done.\n");
    ASSERT_NE(outgoing_message->longmsg, nullptr);
    output_stream << "message created.\n";

    char* encoded_text = nullptr;

    message* encrypted_msg = nullptr;
    output_stream << "calling encrypt_message\n";
    status = encrypt_message (session, outgoing_message, NULL, &encrypted_msg, PEP_enc_PGP_MIME, 0);
    output_stream << "encrypt_message() returns " << tl_status_string(status) << '.' << endl;
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(encrypted_msg, nullptr);
    output_stream << "message encrypted.\n";

    status = mime_encode_message(encrypted_msg, false, &encoded_text, false);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(encoded_text, nullptr);

    bool contains_version = false;

    const char* version_str = "X-pEp-Version: ";
    size_t version_prefix_len = strlen(version_str);

    istringstream f(encoded_text);
    string enc_string;
    while (getline(f, enc_string)) {
        if (strncmp(enc_string.c_str(), version_str, version_prefix_len) == 0)
            contains_version = true;
    }
    ASSERT_TRUE(contains_version);

    if (contains_version)
        output_stream << "Version string in encrypted message, as it should be." << endl;
}
