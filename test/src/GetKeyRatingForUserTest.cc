// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include "test_util.h"
#include "TestConstants.h"

#include "pEpEngine.h"
#include "pEp_internal.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for GetKeyRatingForUserTest
    class GetKeyRatingForUserTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            GetKeyRatingForUserTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~GetKeyRatingForUserTest() override {
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
            // Objects declared here can be used by all tests in the GetKeyRatingForUserTest suite.

    };

}  // namespace


TEST_F(GetKeyRatingForUserTest, check_get_key_rating_for_user) {
    pEp_identity* alice = NULL;
    PEP_STATUS status = set_up_preset(session, ALICE, false, false, false, false, false, &alice);
    pEp_identity* test_null = NULL;
    const char* fpr_save = alice->fpr;
    alice->fpr = NULL;
    status = get_identity(session, alice->address, alice->user_id, &test_null);
    ASSERT_EQ(test_null, nullptr);
    ASSERT_EQ(status , PEP_CANNOT_FIND_IDENTITY);
    ASSERT_EQ(alice->comm_type , PEP_ct_unknown);

    // Ok, so we have no info really, let's set it.
    status = set_identity(session, alice);

    status = update_identity(session, alice);
    ASSERT_NE(alice->fpr, nullptr);

    PEP_rating rating;
    status = get_key_rating_for_user(session, alice->user_id, alice->fpr, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    output_stream << tl_rating_string(rating) << endl;
}
