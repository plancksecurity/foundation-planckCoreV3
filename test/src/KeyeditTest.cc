// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring>

#include "pEpEngine.h"
#include "platform.h"

#include "test_util.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for KeyeditTest
    class KeyeditTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            KeyeditTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~KeyeditTest() override {
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
            // Objects declared here can be used by all tests in the KeyeditTest suite.

    };

}  // namespace


TEST_F(KeyeditTest, check_keyedit) {

    // generate test key

    output_stream << "\ngenerating key for keyedit test\n";
    pEp_identity *identity = new_identity(
            "expire@dingens.org",
            NULL,
            "423",
            "expire test key"
        );
    ASSERT_NE(identity, nullptr);
    PEP_STATUS generate_status = generate_keypair(session, identity);
    output_stream << "generate_keypair() exits with " << generate_status << "\n";
    ASSERT_EQ(generate_status, PEP_STATUS_OK);
    output_stream << "generated key is " << identity->fpr << "\n";

    string key(identity->fpr);
    free_identity(identity);

    // keyedit test code

    time_t now = time(NULL);
    output_stream << "Time is " << now << endl;
    timestamp *ts = new_timestamp(now);
    ts->tm_year += 2;

    output_stream << "key shall expire on " << asctime(ts) << "\n";

    PEP_STATUS status2 = renew_key(session, key.c_str(), ts);
    output_stream << "renew_key() exited with " << status2 << "\n";
    ASSERT_EQ(status2, PEP_STATUS_OK);
    free_timestamp(ts);

    output_stream << "key renewed.\n";

    output_stream << "key will be revoked\n";
    PEP_STATUS status3 = revoke_key(session, key.c_str(), "revoke test");
    output_stream << "revoke_key() exited with " << status3 << "\n";
    ASSERT_EQ(status3, PEP_STATUS_OK);

    output_stream << "key revoked.\n";

    // Because pEp's policy is never to delete keys from the keyring and delete_keypair
    // though gnupg makes responding to a dialog mandatory under Debian, we will not test
    // this anymore.

    // output_stream << "deleting key pair " << key.c_str() << "\n";
    // PEP_STATUS delete_status = delete_keypair(session, key.c_str());
    // output_stream << "delete_keypair() exits with " << delete_status << "\n";
    // ASSERT_EQ(delete_status , PEP_STATUS_OK);
}
