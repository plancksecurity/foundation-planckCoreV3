#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for KeyManipulationTest
    class KeyManipulationTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            KeyManipulationTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~KeyManipulationTest() override {
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
                engine->prep(NULL, NULL, init_files);

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
            // Objects declared here can be used by all tests in the KeyManipulationTest suite.

    };

}  // namespace

/***
Key manipulation functions to test:
 
pEpEngine.h: 
generate_keypair()
delete_keypair()
import_key()
export_key()
export_secret_key()
recv_key()
find_keys()
send_key()
get_key_rating()
renew_key()
revoke_key()
key_expired()
key_revoked()
set_revoked()
get_revoked()

***/
TEST_F(KeyManipulationTest, check_generate_keypair) {

    stringlist_t* keylist = NULL;
    pEp_identity* id = new_identity(
        "leon.schumacher@digitalekho.com",
        NULL,
        "23",
        "Leon Schumacher"
    );

    //PEP_STATUS status = set_identity(session, id);
    //ASSERT_EQ(status, PEP_STATUS_OK);
    
    PEP_STATUS status = generate_keypair(session, id);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // Is it there?
    status = find_keys(session, id->address, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    free_stringlist(keylist);
}

TEST_F(KeyManipulationTest, check_generate_keypair_no_valid_session) {

    stringlist_t* keylist = NULL;
    pEp_identity* id = new_identity(
        "leon.schumacher@digitalekho.com",
        NULL,
        "23",
        "Leon Schumacher"
    );

    PEP_STATUS status = generate_keypair(NULL, id);
    ASSERT_NE(status, PEP_STATUS_OK);

    status = find_keys(session, id->address, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_FALSE(keylist && keylist->value);
    free_stringlist(keylist);
}
