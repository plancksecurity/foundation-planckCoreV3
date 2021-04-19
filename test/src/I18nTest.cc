// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <iostream>

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "test_util.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for I18nTest
    class I18nTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            I18nTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~I18nTest() override {
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
            // Objects declared here can be used by all tests in the I18nTest suite.

    };

}  // namespace


TEST_F(I18nTest, check_i18n) {

    // i18n test code

    char *languages;
    PEP_STATUS status2 = get_languagelist(session, &languages);
    ASSERT_EQ(status2 , PEP_STATUS_OK);
    ASSERT_NOTNULL(languages);

    output_stream << languages;
    pEp_free(languages);

    char *phrase;
    PEP_STATUS status3 = get_phrase(session, "de", 1000, &phrase);
    ASSERT_EQ(status3 , PEP_STATUS_OK);
    ASSERT_NOTNULL(phrase);

    output_stream << "\nGerman: " << phrase << "\n";
    pEp_free(phrase);

    status3 = get_phrase(session, "zz", 1000, &phrase);
    ASSERT_EQ(status3, PEP_PHRASE_NOT_FOUND);
    ASSERT_NULL(phrase);
}
