#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for StickyBitTest
    class StickyBitTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            StickyBitTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~StickyBitTest() override {
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
            // Objects declared here can be used by all tests in the StickyBitTest suite.

    };

}  // namespace


TEST_F(StickyBitTest, check_set_sticky_bit_normal) {

    PEP_STATUS status = PEP_STATUS_OK;

    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc"));

    const char* bob_name = "STOP MESSING WITH ME ALICE";
    const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
    pEp_identity* me = new_identity("pep.test.bob@pep-project.org", NULL, PEP_OWN_USERID, bob_name);
    status = set_own_imported_key(session, me, bob_fpr);
    ASSERT_EQ(status , PEP_STATUS_OK);
    status = myself(session, me);
    ASSERT_EQ(status , PEP_STATUS_OK);
    bool sticky = false;
    status = get_key_sticky_bit_for_user(session, me->user_id, bob_fpr, &sticky);
    ASSERT_TRUE(sticky);
    free_identity(me);
}
