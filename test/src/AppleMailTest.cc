// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()
#include "platform.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"
#include "test_util.h" // for slurp()
#include "TestConstants.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for AppleMailTest
    class AppleMailTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            AppleMailTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~AppleMailTest() override {
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
            // Objects declared here can be used by all tests in the AppleMailTest suite.

    };

}  // namespace


TEST_F(AppleMailTest, check_apple_mail_text_signed_encrypted) {

    const char* mailfile = "test_mails/Text_AppleMail.eml";

    const string keytextkey1 = slurp("test_keys/pub/darthmama.asc");
    const string keytextkey2 = slurp("test_keys/priv/applemail_recip_priv.asc");
    const string keytextkey3 = slurp("test_keys/pub/applemail_recip_pub.asc");

    PEP_STATUS statuskey1 = import_key(session, keytextkey1.c_str(), keytextkey1.length(), NULL);
    PEP_STATUS statuskey2 = import_key(session, keytextkey2.c_str(), keytextkey2.length(), NULL);
    PEP_STATUS statuskey3 = import_key(session, keytextkey3.c_str(), keytextkey3.length(), NULL);

    const string mailtext = slurp(mailfile);
    pEp_identity * me = new_identity("applemail_recip@darthmama.org", "5668C4BA76A87874CEAB50710401383F39CB6DB8", PEP_OWN_USERID, "Applemail McRecipient");
    me->me = true;
    PEP_STATUS status = set_own_key(session, me, "5668C4BA76A87874CEAB50710401383F39CB6DB8");

    pEp_identity * you = new_identity("krista@darthmama.org", NULL, "NOT_ME", "Krista Bennett");
    you->me = false;
    status = update_identity(session, you);

    trust_personal_key(session, you);

    status = update_identity(session, you);

    message* msg_ptr = nullptr;
    message* dest_msg = nullptr;
    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    message* final_ptr = nullptr;
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(msg_ptr, nullptr);

    update_identity(session, msg_ptr->from);
    update_identity(session, msg_ptr->to->ident);

    final_ptr = msg_ptr;

    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_EQ(color_from_rating(rating) , PEP_color_green);

    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);
}

TEST_F(AppleMailTest, check_apple_mail_html_signed_encrypted) {

    // Start state copy
    // N.B. As part of breaking up formerly monolith tests into individual tests, I've copied state setup from the
    // original functions into many functions. It should, when there's time, either be refactored (if necessary for this
    // test) or removed (if not).
    const string keytextkey1 = slurp("test_keys/pub/darthmama.asc");
    const string keytextkey2 = slurp("test_keys/priv/applemail_recip_priv.asc");
    const string keytextkey3 = slurp("test_keys/pub/applemail_recip_pub.asc");

    PEP_STATUS statuskey1 = import_key(session, keytextkey1.c_str(), keytextkey1.length(), NULL);
    PEP_STATUS statuskey2 = import_key(session, keytextkey2.c_str(), keytextkey2.length(), NULL);
    PEP_STATUS statuskey3 = import_key(session, keytextkey3.c_str(), keytextkey3.length(), NULL);

    pEp_identity * me = new_identity("applemail_recip@darthmama.org", "5668C4BA76A87874CEAB50710401383F39CB6DB8", PEP_OWN_USERID, "Applemail McRecipient");
    me->me = true;
    PEP_STATUS status = set_own_key(session, me, "5668C4BA76A87874CEAB50710401383F39CB6DB8");

    pEp_identity * you = new_identity("krista@darthmama.org", NULL, "NOT_ME", "Krista Bennett");
    you->me = false;
    status = update_identity(session, you);

    trust_personal_key(session, you);

    status = update_identity(session, you);

    // End state copy

    message* msg_ptr = nullptr;
    message* dest_msg = nullptr;
    message* final_ptr = nullptr;
    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    const char* mailfile2 = "test_mails/HTML_AppleMail.eml";
    const string mailtext2 = slurp(mailfile2);

    status = mime_decode_message(mailtext2.c_str(), mailtext2.length(), &msg_ptr, NULL);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(msg_ptr, nullptr);
    final_ptr = msg_ptr;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_EQ(color_from_rating(rating) , PEP_color_green);

    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
}
