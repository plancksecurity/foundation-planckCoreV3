// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include "pEpEngine.h"
#include "keymanagement.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for OwnIdentitiesRetrieveTest
    class OwnIdentitiesRetrieveTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            OwnIdentitiesRetrieveTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~OwnIdentitiesRetrieveTest() override {
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
            // Objects declared here can be used by all tests in the OwnIdentitiesRetrieveTest suite.

    };

}  // namespace


TEST_F(OwnIdentitiesRetrieveTest, check_own_identities_retrieve) {
    stringlist_t* keylist = NULL;
    PEP_STATUS status = own_keys_retrieve(session, &keylist);
    ASSERT_EQ(keylist , nullptr);
    ASSERT_EQ(status , PEP_STATUS_OK);

    identity_list* id_list = NULL;
    status = own_identities_retrieve(session, &id_list);
    ASSERT_TRUE(id_list == NULL || !(id_list->ident));
    ASSERT_EQ(status, PEP_STATUS_OK);

    pEp_identity* me = new_identity("krista_b@darthmama.cool", NULL, "MyOwnId", "Krista B.");
    status = myself(session, me);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(me->fpr, nullptr);

    // Ok, there's a me identity in the DB.
    // Call the naughty function.

    status = own_keys_retrieve(session, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    cout << keylist->value << endl;

    status = own_identities_retrieve(session, &id_list);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(id_list, nullptr);
    ASSERT_NE(id_list->ident, nullptr);
}
