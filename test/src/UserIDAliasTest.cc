// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <iostream>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()
#include "pEpEngine.h"
#include "pEp_internal.h"
#include "message_api.h"
#include "keymanagement.h"
#include "TestUtilities.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for UserIDAliasTest
    class UserIDAliasTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            UserIDAliasTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~UserIDAliasTest() override {
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
            // Objects declared here can be used by all tests in the UserIDAliasTest suite.

    };

}  // namespace


TEST_F(UserIDAliasTest, check_userid_aliases) {
    output_stream << "\n*** userid_alias_test ***\n\n";

    PEP_STATUS status = PEP_STATUS_OK;

    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string alice_priv_key = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");

    PEP_STATUS statuspub = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    PEP_STATUS statuspriv = import_key(session, alice_priv_key.c_str(), alice_priv_key.length(), NULL);
    ASSERT_EQ(statuspub , PEP_TEST_KEY_IMPORT_SUCCESS);
    ASSERT_EQ(statuspriv , PEP_TEST_KEY_IMPORT_SUCCESS);

    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", PEP_OWN_USERID, "Alice Test");

    const char* alias1 = "TheBigCheese";
    const char* alias2 = "PEBKAC";

    char* own_id = NULL;
    status = get_default_own_userid(session, &own_id);
    if (!own_id)
        own_id = strdup(PEP_OWN_USERID);

    output_stream << "First, set up an identity with PEP_OWN_USERID as user_id." << endl;
    status = myself(session, alice);
    ASSERT_OK;
    output_stream << "After myself, user_id is " << alice->user_id << endl;
    ASSERT_STREQ(alice->user_id, own_id);

    output_stream << "Now set up an identity with " << alias1 << " as user_id." << endl;
    free(alice->user_id);

    alice->user_id = strdup(alias1);
    status = myself(session, alice);
    ASSERT_OK;
    output_stream << "After myself, user_id is " << alice->user_id << endl;
    ASSERT_STREQ(alice->user_id, own_id);

    output_stream << "Now set up an identity with " << alias2 << " as user_id." << endl;
    free(alice->user_id);

    alice->user_id = strdup(alias2);
    status = myself(session, alice);
    ASSERT_OK;
    output_stream << "After myself, user_id is " << alice->user_id << endl;
    ASSERT_STREQ(alice->user_id, own_id);

    char* default_id = NULL;
    status = get_userid_alias_default(session, alias1, &default_id);
    ASSERT_OK;
    output_stream << "Default user_id for " << alias1 << " is " << default_id << endl;
    ASSERT_STREQ(default_id, own_id);

    free(default_id);
    default_id = NULL;
    status = get_userid_alias_default(session, alias2, &default_id);
    ASSERT_OK;
    output_stream << "Default user_id for " << alias2 << " is " << default_id << endl;
    ASSERT_STREQ(default_id, own_id);

}
