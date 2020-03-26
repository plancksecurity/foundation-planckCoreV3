// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include "test_util.h"
#include "TestConstants.h"

#include "pEpEngine.h"

#include "mime.h"


#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for IOS1664Test
    class IOS1664Test : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            IOS1664Test() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~IOS1664Test() override {
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
                engine->prep(NULL, NULL, init_files);

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
            // Objects declared here can be used by all tests in the IOS1664Test suite.

    };

}  // namespace


TEST_F(IOS1664Test, check_i_o_s1664) {
    string email = slurp("test_mails/0.47.eml");
    ASSERT_FALSE(email.empty());

    message* message_mail = NULL;
    bool raise_att;

    PEP_STATUS status = _mime_decode_message_internal(email.c_str(), email.size(), &message_mail, &raise_att);
    ASSERT_EQ(status , PEP_STATUS_OK && message_mail);

    // create own identity here, because we want to reply, before we start.
    pEp_identity* me = new_identity("android01@peptest.ch", NULL, PEP_OWN_USERID, NULL);
    status = myself(session, me);

    ASSERT_EQ(status , PEP_STATUS_OK && me->fpr != NULL && me->fpr[0] != '\0');

    // Ok, now read the message
    message* read_message = NULL;
    stringlist_t* keylist;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, message_mail, &read_message, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_UNENCRYPTED);

    pEp_identity* you = new_identity("superxat@gmail.com", NULL, NULL, NULL);

    // N.B. while obviously it would be better to write the test expecting us to
    // accept the key, I'm actually testing that we don't get the wrong status
    // based on the presumption of rejection

    message* out_msg = new_message(PEP_dir_outgoing);
    out_msg->from = me;
    out_msg->to = new_identity_list(you);
    out_msg->shortmsg = strdup("Hussidente 2020!");
    out_msg->longmsg = strdup("A Huss in every office!");

    status = identity_rating(session, out_msg->from, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating , PEP_rating_trusted_and_anonymized);
    status = identity_rating(session, out_msg->to->ident, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating , PEP_rating_reliable);

    status = outgoing_message_rating(session, out_msg, &rating);
    ASSERT_EQ(rating , PEP_rating_reliable);

}
