// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include "mime.h"
#include "message_api.h"
#include "test_util.h"
#include "TestConstants.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for CaseAndDotAddressTest
    class CaseAndDotAddressTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            CaseAndDotAddressTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~CaseAndDotAddressTest() override {
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
            // Objects declared here can be used by all tests in the CaseAndDotAddressTest suite.

    };

}  // namespace


TEST_F(CaseAndDotAddressTest, check_case_and_dot_address) {
    output_stream << "\n*** case_and_dot_address_test.cc ***\n\n";

    char* user_id = get_new_uuid();

    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");

    const char* alice_email_case = "pEp.teST.AlICe@pEP-pRoJeCt.ORG";
    const char* alice_email_dot = "pe.p.te.st.a.l.i.ce@pep-project.org";
    const char* alice_email_dotless = "peptestalice@pep-project.org";
    const char* alice_email_case_and_dot = "PE.p.teS.t.ALICE@pep-project.OrG";

    PEP_STATUS statuspub = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    ASSERT_EQ(statuspub , PEP_TEST_KEY_IMPORT_SUCCESS);

    pEp_identity * alice_id = new_identity("pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", user_id, "Alice Test");

    PEP_STATUS status = trust_personal_key(session, alice_id);

    pEp_identity * new_alice_id = new_identity("pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", user_id, "Alice Test");
    status = _update_identity(session, new_alice_id, true);
    ASSERT_NE(new_alice_id->fpr, nullptr);
    ASSERT_STREQ(new_alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    free_identity(new_alice_id);
    free_identity(alice_id);
    alice_id = NULL;
    new_alice_id = NULL;

    alice_id = new_identity(alice_email_case, NULL, user_id, "Alice Test");
    status = _update_identity(session, alice_id, true);
    ASSERT_NE(alice_id->fpr, nullptr);
    output_stream << "Alice email: " << alice_email_case << " Alice fpr (should be 4ABE3AAF59AC32CFE4F86500A9411D176FF00E97): " << alice_id->fpr << endl;
    ASSERT_STREQ(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    free_identity(alice_id);
    alice_id = NULL;

    alice_id = new_identity(alice_email_dot, NULL, user_id, "Alice Test");
    status = _update_identity(session, alice_id, true);
    ASSERT_NE(alice_id->fpr, nullptr);
    output_stream << "Alice email: " << alice_email_dot << " Alice fpr (should be 4ABE3AAF59AC32CFE4F86500A9411D176FF00E97): " << alice_id->fpr << endl;
    ASSERT_STREQ(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    free_identity(alice_id);
    alice_id = NULL;

    alice_id = new_identity(alice_email_dotless, NULL, user_id, "Alice Test");
    status = _update_identity(session, alice_id, true);
    ASSERT_NE(alice_id->fpr, nullptr);
    output_stream << "Alice email: " << alice_email_dotless << " Alice fpr (should be 4ABE3AAF59AC32CFE4F86500A9411D176FF00E97): " << alice_id->fpr << endl;
    ASSERT_STREQ(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    free_identity(alice_id);
    alice_id = NULL;

    alice_id = new_identity(alice_email_case_and_dot, NULL, user_id, "Alice Test");
    status = _update_identity(session, alice_id, true);
    ASSERT_NE(alice_id->fpr, nullptr);
    output_stream << "Alice email: " << alice_email_case_and_dot << " Alice fpr (should be 4ABE3AAF59AC32CFE4F86500A9411D176FF00E97): " << alice_id->fpr << endl;
    ASSERT_STREQ(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    free_identity(alice_id);
    alice_id = NULL;
}
