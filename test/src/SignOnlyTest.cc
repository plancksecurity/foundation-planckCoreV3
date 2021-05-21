// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <fstream>

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "test_util.h"
#include "TestConstants.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for SignOnlyTest
    class SignOnlyTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            SignOnlyTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~SignOnlyTest() override {
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
            // Objects declared here can be used by all tests in the SignOnlyTest suite.

    };

}  // namespace


TEST_F(SignOnlyTest, check_sign_only) {
    slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    string msg_text = "Grrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr! I mean, yo. Greetings to Meesti.\n - Alice";
    ofstream test_file;
    test_file.open("tmp/signed_text.txt");
    test_file << msg_text;
    test_file.close();
    char* signed_text = NULL;
    size_t signed_text_size = 0;

    stringlist_t* keylist = NULL;

    PEP_STATUS status = sign_only(session, msg_text.c_str(), msg_text.size(), alice_fpr, &signed_text, &signed_text_size);
    ASSERT_EQ(status , PEP_STATUS_OK);
    output_stream << signed_text << endl;
    test_file.open("tmp/signature.txt");
    test_file << signed_text;
    test_file.close();

    status = verify_text(session, msg_text.c_str(), msg_text.size(),
                         signed_text, signed_text_size, &keylist);

#ifndef USE_NETPGP
    ASSERT_EQ(status , PEP_VERIFIED);
#else
    ASSERT_EQ(status , PEP_VERIFIED_AND_TRUSTED);
#endif
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_STREQ(keylist->value, alice_fpr);

    // FIXME: free stuff

}
