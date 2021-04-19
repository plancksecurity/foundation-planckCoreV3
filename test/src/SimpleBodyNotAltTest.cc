// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "message.h"
#include "mime.h"
#include "test_util.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for SimpleBodyNotAltTest
    class SimpleBodyNotAltTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            SimpleBodyNotAltTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~SimpleBodyNotAltTest() override {
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
            // Objects declared here can be used by all tests in the SimpleBodyNotAltTest suite.

    };

}  // namespace


TEST_F(SimpleBodyNotAltTest, check_text_w_html_attach) {
    string msg = slurp("test_mails/text message with html attach.eml");
    message* parsed = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &parsed, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(parsed);
    ASSERT_NOTNULL(parsed->longmsg);
    ASSERT_NULL(parsed->longmsg_formatted );
    ASSERT_NOTNULL(parsed->attachments);
    ASSERT_NULL(parsed->attachments->next );
    ASSERT_NOTNULL(parsed->attachments->filename);
    ASSERT_STREQ(parsed->attachments->filename, "file://index.html");
    ASSERT_NOTNULL(parsed->attachments->mime_type);
    ASSERT_STREQ(parsed->attachments->mime_type, "text/html");
    free_message(parsed);
}

TEST_F(SimpleBodyNotAltTest, check_html_w_text_attach) {
    string msg = slurp("test_mails/HTML-only body w text attachment.eml");
    message* parsed = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &parsed, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(parsed);
    ASSERT_NULL(parsed->longmsg );
    ASSERT_NOTNULL(parsed->longmsg_formatted);
    ASSERT_NOTNULL(parsed->attachments);
    ASSERT_NULL(parsed->attachments->next );
    ASSERT_NOTNULL(parsed->attachments->filename);
    ASSERT_STREQ(parsed->attachments->filename, "file://cheese.txt");
    ASSERT_NOTNULL(parsed->attachments->mime_type);
    ASSERT_STREQ(parsed->attachments->mime_type, "text/plain");
    free_message(parsed);
}
