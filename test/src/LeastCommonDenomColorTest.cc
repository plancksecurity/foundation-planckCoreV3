// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"
#include "TestUtilities.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for LeastCommonDenomColorTest
    class LeastCommonDenomColorTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            LeastCommonDenomColorTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~LeastCommonDenomColorTest() override {
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
            // Objects declared here can be used by all tests in the LeastCommonDenomColorTest suite.

    };

}  // namespace


TEST_F(LeastCommonDenomColorTest, check_least_common_denom_color) {

    const char* mailfile = "test_mails/Test_Message_JSON-21_Color_Problems.eml";

    // import keys
    const string keytextkey1 = slurp("test_keys/pub/banmeonce-0x07B29090_pub.asc");
    const string keytextkey2 = slurp("test_keys/pub/banmetwice-0x4080C3E7_pub.asc");
    const string keytextkey3 = slurp("test_keys/pub/pep.never.me.test-0x79C11D1D_pub.asc");
    const string keytextkey4 = slurp("test_keys/priv/pep.never.me.test-0x79C11D1D_priv.asc");

    PEP_STATUS statuskey1 = import_key(session, keytextkey1.c_str(), keytextkey1.length(), NULL);
    PEP_STATUS statuskey2 = import_key(session, keytextkey2.c_str(), keytextkey2.length(), NULL);
    PEP_STATUS statuskey3 = import_key(session, keytextkey3.c_str(), keytextkey3.length(), NULL);
    PEP_STATUS statuskey4 = import_key(session, keytextkey4.c_str(), keytextkey4.length(), NULL);

    /*
    banmeonce@kgrothoff.org|9F371BACD583EE26347899F21CCE13DE07B29090
    banmetwice@kgrothoff.org|84A33862CC664EA1086B7E94ADF10A134080C3E7
    pep.never.me.test@kgrothoff.org|8314EF2E19278F9800527EA887601BD579C11D1D
    */

    pEp_identity * sender = new_identity("pep.never.me.test@kgrothoff.org", NULL, "TOFU_pep.never.me.test@kgrothoff.org", "pEp Never Me Test");
    sender->me = false;
    PEP_STATUS status = update_identity(session, sender);
    ASSERT_OK;
    free(sender->fpr);
    sender->fpr = strdup("8314EF2E19278F9800527EA887601BD579C11D1D");
    status = set_identity(session, sender);
    ASSERT_OK;

    // reset the trust on both keys before we start
    pEp_identity * recip1 = new_identity("banmeonce@kgrothoff.org", NULL, "TOFU_banmeonce@kgrothoff.org", "Ban Me Once");
    recip1->me = false;
    status = update_identity(session, recip1);
    free(recip1->fpr);
    recip1->fpr = strdup("9F371BACD583EE26347899F21CCE13DE07B29090");
    status = set_identity(session, recip1);
    ASSERT_OK;
    key_reset_trust(session, recip1);

    pEp_identity * recip2 = new_identity("banmetwice@kgrothoff.org", NULL, "TOFU_banmetwice@kgrothoff.org", "Ban Me Twice");
    recip2->me = false;
    status = update_identity(session, recip2);
    free(recip2->fpr);
    recip2->fpr = strdup("84A33862CC664EA1086B7E94ADF10A134080C3E7");
    status = set_identity(session, recip2);
    ASSERT_OK;
    key_reset_trust(session, recip2);

    const string mailtext = slurp(mailfile);

    // trust_personal_key(session, you);
    //
    // status = update_identity(session, you);

    message* msg_ptr = nullptr;
    message* dest_msg = nullptr;
    stringlist_t* keylist = nullptr;
    PEP_decrypt_flags_t flags;

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);

    flags = 0;
    status = decrypt_message_2(session, msg_ptr, &dest_msg, &keylist, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dest_msg);
    PEP_rating rating = dest_msg->rating;
    /* message is signed and no recip is mistrusted... */
    ASSERT_EQ(color_from_rating(rating) , PEP_color_yellow);

    output_stream << "shortmsg: " << dest_msg->shortmsg << endl << endl;
    output_stream << "longmsg: " << dest_msg->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (dest_msg->longmsg_formatted ? dest_msg->longmsg_formatted : "(empty)") << endl << endl;

    PEP_rating decrypt_rating = rating;

    /* re-evaluate rating, counting on optional fields */
    status = re_evaluate_message_rating(session, dest_msg, NULL, PEP_rating_undefined, &rating);
    ASSERT_OK;
    ASSERT_EQ(color_from_rating(rating) , PEP_color_yellow);

    /* re-evaluate rating, without optional fields */
    status = re_evaluate_message_rating(session, dest_msg, keylist, decrypt_rating, &rating);
    ASSERT_OK;
    ASSERT_EQ(color_from_rating(rating) , PEP_color_yellow);

    /* Ok, now mistrust one recip */
    key_mistrusted(session, recip2);

    /* re-evaluate rating, counting on optional fields */
    status = re_evaluate_message_rating(session, dest_msg, NULL, PEP_rating_undefined, &rating);
    ASSERT_OK;
    ASSERT_EQ(color_from_rating(rating) , PEP_color_red);

    /* re-evaluate rating, without optional fields */
    status = re_evaluate_message_rating(session, dest_msg, keylist, decrypt_rating, &rating);
    ASSERT_OK;
    ASSERT_EQ(color_from_rating(rating) , PEP_color_red);

    free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    msg_ptr = nullptr;
    dest_msg = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    flags = 0;
    status = decrypt_message_2(session, msg_ptr, &dest_msg, &keylist, &flags);

    output_stream << "shortmsg: " << dest_msg->shortmsg << endl << endl;
    output_stream << "longmsg: " << dest_msg->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (dest_msg->longmsg_formatted ? dest_msg->longmsg_formatted : "(empty)") << endl << endl;
    rating = dest_msg->rating;

    /* message is signed and no recip is mistrusted... */
    ASSERT_EQ(color_from_rating(rating) , PEP_color_red);

    free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    msg_ptr = nullptr;
    dest_msg = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

}
