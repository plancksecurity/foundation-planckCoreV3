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

	//The fixture for LiteralFilenameTest
    class LiteralFilenameTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            LiteralFilenameTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~LiteralFilenameTest() override {
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
            // Objects declared here can be used by all tests in the LiteralFilenameTest suite.

    };

}  // namespace

// FIXME: crypto-engine-specific tests should either be labelled as such, or we should use them to ensure consistent behaviour.
TEST_F(LiteralFilenameTest, check) {
#ifdef USE_SEQUOIA    
    slurp_and_import_key(session, "test_keys/priv/pep-test-lisa-0xBA0997C1514E70EB_priv.asc");

    string ciphertext = slurp("test_files/literal-packet-with-filename.pgp");

    // Decrypt and verify it.
    char *plaintext = NULL;
    size_t plaintext_size = 0;
    stringlist_t *keylist = NULL;
    char *filename = NULL;
    PEP_STATUS status = decrypt_and_verify(session,
                                           ciphertext.c_str(),
                                           ciphertext.size(),
                                           NULL, 0,
                                           &plaintext, &plaintext_size,
                                           &keylist, &filename);

    ASSERT_EQ(status , PEP_DECRYPTED_AND_VERIFIED);
    ASSERT_NE(filename, nullptr);
    ASSERT_STREQ(filename, "filename.txt");
#else
    ASSERT_TRUE(true); // DOH 
#endif
}
