#include <stdlib.h>
#include <string>
#include <cstring>

#include "internal_format.h"

#include "TestUtilities.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>

extern "C" {
    PEP_STATUS set_receiverRating(PEP_SESSION session, message *msg, PEP_rating rating);
    PEP_STATUS get_receiverRating(PEP_SESSION session, message *msg, PEP_rating *rating);
}

namespace {

	//The fixture for ReceiverRatingTest
    class ReceiverRatingTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            ReceiverRatingTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~ReceiverRatingTest() override {
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
            // Objects declared here can be used by all tests in the ReceiverRatingTest suite.

    };

}  // namespace

TEST_F(ReceiverRatingTest, check_internal_format) {
    // a message from me, Alice, to myself

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                "pep.test.alice@pep-project.org", alice_fpr,
                PEP_OWN_USERID, "Alice in Wonderland", NULL, true
            );
    ASSERT_EQ(status , PEP_STATUS_OK);

    message* msg = new_message(PEP_dir_outgoing);
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    status = myself(session, alice);
    ASSERT_EQ(status , PEP_STATUS_OK);
    pEp_identity* alice2 = identity_dup(alice);

    msg->to = new_identity_list(identity_dup(alice));
    msg->from = identity_dup(alice);
    msg->shortmsg = strdup("Yo Mama!");
    msg->longmsg = strdup("Look at my hot new sender fpr field!");

    // encrypt this message

    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_EQ(status , PEP_STATUS_OK);
    
    // decrypt this message
    
    message *dec_msg = NULL;
    stringlist_t *keylist = NULL;
    PEP_decrypt_flags_t flags = 0;

    enc_msg->recv_by = identity_dup(alice);
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &flags);
    ASSERT_EQ(status, PEP_STATUS_OK);
    PEP_rating rating = dec_msg->rating;
    ASSERT_STREQ(msg->shortmsg, dec_msg->shortmsg);
    ASSERT_STREQ(msg->longmsg, dec_msg->longmsg);
    ASSERT_EQ(rating, PEP_rating_trusted_and_anonymized);
    
    bloblist_t *as = dec_msg->attachments;
    ASSERT_STREQ(as->mime_type, "application/pEp.sync");

    // test if receiver rating can be evaluated
    free_stringlist(keylist);
    message *dec_msg2 = NULL;
    dec_msg->recv_by = identity_dup(alice);
    status = decrypt_message(session, dec_msg, &dec_msg2, &keylist, &flags);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    rating = dec_msg->rating; // FIXME: positron: maybe it was dec_msg2.  If it fails, I am not terribly surprised.
    ASSERT_EQ(rating, PEP_rating_trusted_and_anonymized);

    // this must be repeatable
    free_stringlist(keylist);
    dec_msg->recv_by = identity_dup(alice);
    status = decrypt_message(session, dec_msg, &dec_msg2, &keylist, &flags);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    rating = dec_msg->rating; // FIXME: positron: maybe it was dec_msg2.  If it fails, I am not terribly surprised.
    ASSERT_EQ(rating, PEP_rating_trusted_and_anonymized);

    free_stringlist(keylist);
    free_identity(alice);
    free_message(msg);
    free_message(enc_msg);
    free_message(dec_msg);
    free_message(dec_msg2);
}

