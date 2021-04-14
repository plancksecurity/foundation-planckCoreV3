// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring> // for strcmp()

#include "test_util.h"
#include "TestConstants.h"

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "blacklist.h"
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for BlacklistAcceptNewKeyTest
    class BlacklistAcceptNewKeyTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            BlacklistAcceptNewKeyTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~BlacklistAcceptNewKeyTest() override {
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
            // Objects declared here can be used by all tests in the BlacklistAcceptNewKeyTest suite.

    };

}  // namespace


TEST_F(BlacklistAcceptNewKeyTest, check_blacklist_accept_new_key) {

    // blacklist test code

    output_stream << "blacklist only key for identity / add key / check which key is used" << endl;

    // 2797 65A2 FEB5 B7C7 31B8  61D9 3E4C EFD9 F7AF 4684 - this is the blacklisted key in blacklisted_pub.asc

    /* read the key into memory */
    const string keytext = slurp("test_keys/pub/blacklisted_pub.asc");

    /* import it into pep */
    PEP_STATUS status7 = import_key(session, keytext.c_str(), keytext.length(), NULL);

    const char* bl_fpr_1 = "279765A2FEB5B7C731B861D93E4CEFD9F7AF4684";
    bool is_blacklisted = false;

    pEp_identity* blacklisted_identity = new_identity("blacklistedkeys@kgrothoff.org",
                                                      bl_fpr_1,
                                                      NULL,
                                                      "Blacklist Keypair");
    PEP_STATUS status8 = _update_identity(session, blacklisted_identity, true);
    PEP_STATUS status9 = blacklist_add(session, bl_fpr_1);
    PEP_STATUS status10 = blacklist_is_listed(session, bl_fpr_1, &is_blacklisted);
    ASSERT_TRUE(is_blacklisted);
    PEP_STATUS status11 = _update_identity(session, blacklisted_identity, true);
    ASSERT_EQ(status11 , PEP_STATUS_OK);
    ASSERT_STREQ(bl_fpr_1, blacklisted_identity->fpr);

    bool id_def, us_def, addr_def;
    status11 = get_valid_pubkey(session, blacklisted_identity,
                                &id_def, &us_def, &addr_def, true, true);
    ASSERT_EQ(blacklisted_identity->comm_type , PEP_ct_unknown);

    if (!(blacklisted_identity->fpr))
        output_stream << "OK! blacklisted_identity->fpr is empty. Yay!" << endl;
    else
        output_stream << "Not OK. blacklisted_identity->fpr is " << blacklisted_identity->fpr << "." << endl
             << "Expected it to be empty." << endl;
    ASSERT_TRUE(blacklisted_identity->fpr == NULL || blacklisted_identity->fpr[0] == '\0');

    /* identity is blacklisted. Now let's read in a message which contains a new key for that ID. */

    const char* new_key = "634FAC4417E9B2A5DC2BD4AAC4AEEBBE7E62701B";
    const string mailtext = slurp("test_mails/blacklist_new_key_attached.eml");
    pEp_identity * me1 = new_identity("blacklist_test@kgrothoff.org", NULL, PEP_OWN_USERID, "Blacklisted Key Message Recipient");

    PEP_STATUS status = _update_identity(session, me1, true);
    message* msg_ptr = nullptr;
    message* dest_msg = nullptr;
    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);

    PEP_STATUS status12 = get_valid_pubkey(session, blacklisted_identity,
                                           &id_def, &us_def, &addr_def, true, true);

    ASSERT_STRCASEEQ(blacklisted_identity->fpr, new_key);

    PEP_STATUS status13 = blacklist_delete(session, bl_fpr_1);
    PEP_STATUS status14 = _update_identity(session, blacklisted_identity, true);

    free_message(msg_ptr);
    free_message(dest_msg);
    free_stringlist(keylist);
}
