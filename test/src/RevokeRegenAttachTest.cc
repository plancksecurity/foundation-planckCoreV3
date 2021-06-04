// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cstring>
#include <time.h>
#include <iostream>
#include <fstream>
#include <assert.h>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "platform.h"
#include "mime.h"
#include "message_api.h"

#include "TestUtilities.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for RevokeRegenAttachTest
    class RevokeRegenAttachTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            RevokeRegenAttachTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~RevokeRegenAttachTest() override {
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
                string recip_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
                PEP_STATUS status = import_key(session, recip_key.c_str(), recip_key.size(), NULL);
                ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);                
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
            // Objects declared here can be used by all tests in the RevokeRegenAttachTest suite.

    };

}  // namespace

// FIXME: I am really not sure what this test was supposed to check - I think it's leftover from another test and
// is actually covered by key_reset tests at this point. Double check?
TEST_F(RevokeRegenAttachTest, check_revoke_regen_attach) {
    PEP_STATUS status = PEP_STATUS_OK;

    output_stream << "creating own id for : ";
    char *uniqname = strdup("AAAAtestuser@testdomain.org");
    srandom(time(NULL));
    for(int i=0; i < 4;i++)
        uniqname[i] += random() & 0xf;

    output_stream << uniqname << "\n";
    pEp_identity * me = new_identity(uniqname, NULL, PEP_OWN_USERID, "Test User");
    free(uniqname);
    myself(session, me);

    output_stream << "generated fingerprint \n";
    output_stream << me->fpr << "\n";

    const char *prev_fpr = strdup(me->fpr);

    output_stream << "revoke \n";

    key_mistrusted(session, me);

    output_stream << "re-generated fingerprint \n";
    free(me->fpr);
    me->fpr = NULL;
    status = myself(session, me);
    ASSERT_OK;
    output_stream << me->fpr << "\n";

    ASSERT_NOTNULL(me->fpr);
    ASSERT_STRNE(me->fpr, prev_fpr);
    output_stream << "New fpr is: " << me->fpr;

    me->fpr = NULL;
    me->comm_type = PEP_ct_unknown;
    myself(session, me);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    identity_list *to = new_identity_list(new_identity("pep.test.alice@pep-project.org", NULL, "42", "pEp Test Alice (test key don't use)"));
    status = set_fpr_preserve_ident(session, to->ident, alice_fpr, false);

    message *msg = new_message(PEP_dir_outgoing);
    ASSERT_NOTNULL(msg);
    msg->from = me;
    msg->to = to;
    msg->shortmsg = strdup("hello, world");
    output_stream << "message created.\n";

    output_stream << "encrypting message as MIME multipart…\n";
    message *enc_msg;
    output_stream << "calling encrypt_message()\n";
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);
    output_stream << "message encrypted.\n";

    output_stream << msg->attachments->filename;
    ASSERT_STREQ(msg->attachments->filename, "file://sender_key.asc");

    free_message(msg);
    free_message(enc_msg);
}
