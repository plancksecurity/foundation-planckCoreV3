// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "pEp_internal.h"
#include "TestUtilities.h"
#include "message.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for Engine463Test
    class Engine463Test : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            Engine463Test() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~Engine463Test() override {
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
            // Objects declared here can be used by all tests in the Engine463Test suite.

    };

}  // namespace


TEST_F(Engine463Test, check_engine_463_no_own_key) {
    const string claudio_keys = slurp("test_keys/priv/notfound-alt-pub_and_private.asc");
    const string fake_schleuder_key = slurp("test_keys/pub/fake-schleuder.asc");

    PEP_STATUS status = import_key(session, claudio_keys.c_str(), claudio_keys.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, fake_schleuder_key.c_str(), fake_schleuder_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);

    // Ok, bring in message, decrypt, and see what happens.
    const string msg = slurp("test_mails/notfound-alt.msg");

    char* decrypted_msg = NULL;
    stringlist_t* keylist_used = nullptr;
    char* modified_src = NULL;

    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    ASSERT_OK;
}

TEST_F(Engine463Test, check_engine_463_sender_expired_and_renewed) {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");
    ASSERT_TRUE(ok);

    const char* inq_fpr = "8E8D2381AE066ABE1FEE509821BA977CA4728718";
    pEp_identity* inquisitor = new_identity("inquisitor@darthmama.org", NULL, NULL, "Lady Claire Trevelyan");
    PEP_STATUS status = set_fpr_preserve_ident(session, inquisitor, inq_fpr, false);
    ASSERT_OK;

    // Ok, so I want to make sure we make an entry, so I'll try to decrypt the message WITH
    // the expired key:
    const string msg = slurp("test_mails/ENGINE-463-attempt-numero-dos.eml");

    char* decrypted_msg = NULL;
    stringlist_t* keylist_used = nullptr;
    char* modified_src = NULL;

    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    ASSERT_EQ(status , PEP_DECRYPTED);

    free(decrypted_msg);
    decrypted_msg = NULL;
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");
    ASSERT_TRUE(ok);

    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", NULL, NULL, "Lady Claire Trevelyan");

    status = identity_rating(session, expired_inquisitor, &rating);
    ASSERT_OK;
    ASSERT_EQ(rating , PEP_rating_reliable);

    flags = 0;

    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    ASSERT_NOTNULL(decrypted_msg);
    ASSERT_OK;
    ASSERT_EQ(rating , PEP_rating_reliable);

    free_identity(expired_inquisitor);

}

 TEST_F(Engine463Test, check_engine_463_reply_recip_expired_and_renewed) {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");
    ASSERT_TRUE(ok);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    pEp_identity* alice_from = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Cooper");

    PEP_STATUS status = set_own_key(session, alice_from, alice_fpr);
    ASSERT_OK;

    const char* inq_fpr = "8E8D2381AE066ABE1FEE509821BA977CA4728718";
    pEp_identity* inquisitor = new_identity("inquisitor@darthmama.org", NULL, NULL, "Lady Claire Trevelyan");
    status = set_fpr_preserve_ident(session, inquisitor, inq_fpr, false);
    ASSERT_OK;

    // Ok, so I want to make sure we make an entry, so I'll try to decrypt the message WITH
    // the expired key:
    const string msg = slurp("test_mails/ENGINE-463-attempt-numero-dos.eml");

    char* decrypted_msg = NULL;
    stringlist_t* keylist_used = nullptr;
    char* modified_src = NULL;

    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = MIME_decrypt_message(session, msg.c_str(), msg.size(), &decrypted_msg, &keylist_used, &rating, &flags, &modified_src);
    ASSERT_EQ(status , PEP_DECRYPTED);

    free(decrypted_msg);
    decrypted_msg = NULL;
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");
    ASSERT_TRUE(ok);

    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", NULL, NULL, "Lady Claire Trevelyan");
    message* msg2 = new_message(PEP_dir_outgoing);

    msg2->from = alice_from;
    msg2->to = new_identity_list(expired_inquisitor);
    msg2->shortmsg = strdup("Blah!");
    msg2->longmsg = strdup("Blahblahblah!");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    status = outgoing_message_rating(session, msg2, &rating);
    ASSERT_OK;
    ASSERT_EQ(rating , PEP_rating_reliable);

    free_message(msg2);
}
