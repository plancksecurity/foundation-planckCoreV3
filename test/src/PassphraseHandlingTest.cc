#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "TestUtilities.h"
#include "TestConstants.h"
#include "Engine.h"
#include <fstream>

#include <gtest/gtest.h>

namespace {

	// Tests for RFC-16 Passphrase Handling
    class PassphraseHandlingTest : public ::testing::Test {
        public:
            Engine *engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            PassphraseHandlingTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~PassphraseHandlingTest() override {
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
            
            const char *tyrell_no_passphrase_email = "tyrell@example.com";
            const char *tyrell_no_passphrase_username = "Eldon Tyrell (no passphrase)";

            const char *tyrell_no_passphrase_fpr = "C203044D09E2EC0BD56FD32B66C9C6A984B31398";
            const char *tyrell_no_passphrase_filename = "test_keys/passphrase_handling/tyrell_no_passphrase.pgp";

            const char *tyrell_passphrase_email = "tyrell_passphrase@example.com";
            const char *tyrell_passphrase_username = "Eldon Tyrell (passphrase)";
            const char *tyell_passphrase = "blarg";
            const char *tyrell_passphrase_fpr = "DF862D31226F89F4662474AF42A7DE95EADE3B2C";
            const char *tyrell_passphrase_filename = "test_keys/passphrase_handling/tyrell_passphrase.pgp";
            
        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the PassphraseHandlingTest suite.
    };

}  // namespace

TEST_F(PassphraseHandlingTest, tyrell_no_passphrase) {
    pEp_identity *tyrell_identity = NULL;
    PEP_STATUS status = set_up_ident_from_scratch(session,
        tyrell_no_passphrase_filename,
        tyrell_no_passphrase_email,
        tyrell_no_passphrase_fpr,
        PEP_OWN_USERID,
        tyrell_no_passphrase_username,
        &tyrell_identity,
        true);
    ASSERT_EQ(status, PEP_STATUS_OK);

    bool passphrase_bool = false;
    status = has_passphrase(session, tyrell_no_passphrase_email, &passphrase_bool);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_FALSE(passphrase_bool);
}

TEST_F(PassphraseHandlingTest, tyrell_passphrase) {
    pEp_identity *tyrell_identity = NULL;
    PEP_STATUS status = set_up_ident_from_scratch(session,
        tyrell_passphrase_filename,
        tyrell_passphrase_email,
        tyrell_passphrase_fpr,
        PEP_OWN_USERID,
        tyrell_passphrase_username,
        &tyrell_identity,
        true);
    ASSERT_EQ(status, PEP_STATUS_OK);

    bool passphrase_bool = false;
    status = has_passphrase(session, tyrell_passphrase_email, &passphrase_bool);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(passphrase_bool);
}
