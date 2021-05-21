#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"
#include <iostream>
#include <fstream>

#include <gtest/gtest.h>


namespace {

	//The fixture for Engine736Test
    class Engine736Test : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            Engine736Test() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~Engine736Test() override {
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
            // Objects declared here can be used by all tests in the Engine736Test suite.

    };

}  // namespace


TEST_F(Engine736Test, check_engine736) {
    // This is just a dummy test case. The convention is check_whatever_you_are_checking
    // so for multiple test cases in a suite, be more explicit ;)
    
    pEp_identity* huss1 = new_identity("huss_android@huss.android.cool", NULL, PEP_OWN_USERID, "Huss (Android)");
    PEP_STATUS status = myself(session, huss1);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(huss1->fpr, nullptr);
    
    // This is just so we can look at the keys externally and ensure the userid is OK.
    char* key = NULL;
    size_t size = 0;
    status = export_key(session, huss1->fpr, &key, &size);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(key, nullptr);
    ofstream outfile;
    outfile.open("test_keys/736_a.asc");
    outfile << key;
    outfile.close();
    
    char* bad_uname = strdup("Huss #2 at (Android) with bad control character here ");
    int ctrlchar_pos = strlen(bad_uname) - 1;
    bad_uname[ctrlchar_pos] = 7; // bell! :)    
    pEp_identity* huss2 = new_identity("huss_android2@huss.android.cool", NULL, PEP_OWN_USERID, bad_uname);
    status = myself(session, huss2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(huss2->fpr, nullptr);

    free(key);
    key = NULL;
    size = 0;
    status = export_key(session, huss2->fpr, &key, &size);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(key, nullptr);
    outfile.open("test_keys/736_b.asc");
    outfile << key;
    outfile.close();

}
