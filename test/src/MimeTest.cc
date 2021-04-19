// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
#include <assert.h>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "platform.h"
#include "mime.h"

#include "test_util.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for MimeTest
    class MimeTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            MimeTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~MimeTest() override {
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
            void test_mime_decoding(string filename) {
                output_stream << "opening " << filename << " for reading\n";
                ifstream inFile3 (filename.c_str());

                ASSERT_TRUE(inFile3.is_open());

                string mimetext3;

                output_stream << "reading mime sample\n";
                while (!inFile3.eof()) {
                    static string line;
                    getline(inFile3, line);
                    mimetext3 += line + "\n";
                }
                inFile3.close();

                output_stream << "decoding message…\n";
                message *msg3;
                PEP_STATUS status3 = mime_decode_message(mimetext3.c_str(), mimetext3.length(), &msg3, NULL);
                assert(status3 == PEP_STATUS_OK);
                assert(msg3);
                output_stream << "decoded.\n\n";
                output_stream << "Subject: " << msg3->shortmsg << "\n\n";
                if (msg3->longmsg)
                    output_stream << msg3->longmsg << "\n\n";
                if (msg3->longmsg_formatted)
                    output_stream << msg3->longmsg_formatted << "\n\n";
                bloblist_t *_b;
                for (_b = msg3->attachments; _b; _b = _b->next) {
                    output_stream << "attachment of type " << _b->mime_type << "\n";
                    if (_b->filename) {
                        output_stream << "filename: " << _b->filename << "\n";
                        unlink(_b->filename);
                        ofstream outFile3(_b->filename);
                        outFile3.write(_b->value, _b->size);
                        outFile3.close();
                    }
                }

                free_message(msg3);
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the MimeTest suite.

    };

}  // namespace



TEST_F(MimeTest, check_mime) {

    // testing multipart/alternative

    message *msg2 = new_message(PEP_dir_incoming);
    ASSERT_NOTNULL(msg2);
    msg2->from = new_identity("vb@dingens.org", NULL, NULL, "Volker Birk");
    msg2->to = new_identity_list(new_identity("trischa@dingens.org", NULL, NULL, "Patricia Bädnar")),
    msg2->shortmsg = strdup("my sübject");

    string text2 = "my mèssage to yoü";
    msg2->longmsg = strdup(text2.c_str());
    string html2 = "<html><body><p>my message to you</p></body></html>";
    msg2->longmsg_formatted = strdup(html2.c_str());
    ASSERT_NOTNULL(msg2->longmsg_formatted);

    output_stream << "encoding message…\n";
    char *result2;
    PEP_STATUS status2 = mime_encode_message(msg2, false, &result2, false);
    ASSERT_NOTNULL(result2);
    ASSERT_EQ(status2, PEP_STATUS_OK);

    output_stream << "result:\n";
    output_stream << result2 << "\n";

    free(result2);
    free_message(msg2);

    test_mime_decoding("test_mails/msg1.asc");
    test_mime_decoding("test_mails/msg2.asc");
    test_mime_decoding("test_mails/msg3.asc");
}
