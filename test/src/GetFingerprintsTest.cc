// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <fstream>

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "TestUtilities.h"
#include "TestConstants.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for VerifyTest(keylist->next) != (nullptr)
    class GetFingerprintsTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;
        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            GetFingerprintsTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~GetFingerprintsTest() override {
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
            // Objects declared here can be used by all tests in the VerifyTest suite.

    };

}  // namespace

// Neal: how are these supposed to behave under gnupg? Or is this again sequoia-specific?
#ifdef USE_SEQUOIA
TEST_F(GetFingerprintsTest, list_keys   ) {
    PEP_STATUS status;
    string input_key;

    // key for main own user
    //
    // 13A9F97964A2B52520CAA40E51BCA783C065A213
    input_key = slurp("test_keys/pub/priv-key-import-test-main_0-0xC065A213_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);

    input_key = slurp("test_keys/priv/priv-key-import-test-main_0-0xC065A213_priv.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);


    message* encoded_text = slurp_message_file_into_struct("test_mails/priv_key_attach.eml");

    // Decrypt and verify it.
    char *plaintext = NULL;
    size_t plaintext_size = 0;
    stringlist_t *keylist = NULL;
    status = get_fprs(session, encoded_text, &keylist);

    int i;

    char* key_ids[2];
    stringlist_t* kl;
    i = 0;
    for (kl = keylist; kl; kl = kl->next) {
        key_ids[i] = kl->value;
        i++;
    }

    ASSERT_STREQ(key_ids[0], "7B5CFD514018722E");
    ASSERT_STREQ(key_ids[1], "8AFCFF3681C48932");

    keylist = NULL;
    find_keys(session, key_ids[0], &keylist);
    i = 0;
    char* key_fprs[2];
    for (kl = keylist; kl; kl = kl->next) {
        key_fprs[i] = kl->value;
        i++;
    }
    ASSERT_STREQ(key_fprs[0], "13A9F97964A2B52520CAA40E51BCA783C065A213");
}

#endif
