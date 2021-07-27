#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "TestUtilities.h"
#include "TestConstants.h"
#include "Engine.h"
#include "pgp_sequoia.h"
#include <gtest/gtest.h>

#if 0
namespace {

	//The fixture for EncryptSignDirectLoopTest
    class EncryptSignDirectLoopTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            EncryptSignDirectLoopTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~EncryptSignDirectLoopTest() override {
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
            // Objects declared here can be used by all tests in the EncryptSignDirectLoopTest suite.

    };

}  // namespace


TEST_F(EncryptSignDirectLoopTest, check_encrypt_sign_optional_loop) {
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc"));

    string plaintext = slurp("test_files/just_the_mimetext_maam.txt");
    const char* ptext = plaintext.c_str();
    size_t psize = plaintext.size();
    stringlist_t* keylist = new_stringlist("4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    stringlist_add(keylist, "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42");

    for (int i = 0; i < 1000; i++) {
        char* ctext = NULL;
        size_t csize = 0;
        PEP_STATUS status = encrypt_and_sign(session, keylist, ptext, psize, &ctext, &csize);
        ASSERT_OK;
        if (i % 10 == 0)
            cout << i << endl;
        free(ctext);
    }
    free_stringlist(keylist);
}
#endif
