// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <string>
#include <iostream>
#include <vector>
#include <cstring> // for strcmp()
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"
#include "TestUtilities.h"

#include "pEpEngine.h"
#include "pEp_internal.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for LeastColorGroupTest
    class LeastColorGroupTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            LeastColorGroupTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~LeastColorGroupTest() override {
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
            // Objects declared here can be used by all tests in the LeastColorGroupTest suite.

    };

}  // namespace


TEST_F(LeastColorGroupTest, check_least_color_group) {

    const char* mailfile = "test_mails/color_test.eml";

    const std::vector<const char*> keynames = {
                              "test_keys/priv/pep.color.test.P-0x3EBE215C_priv.asc",
                              "test_keys/pub/pep.color.test.H-0xD17E598E_pub.asc",
                              "test_keys/pub/pep.color.test.L-0xE9CDB4CE_pub.asc",
                              "test_keys/pub/pep.color.test.P-0x3EBE215C_pub.asc",
                              "test_keys/pub/pep.color.test.V-0x71FC6D28_pub.asc"
                          };

    for (auto name : keynames) {
        output_stream << "\t read keyfile \"" << name << "\"..." << std::endl;
        const string keytextkey = slurp(name);
        PEP_STATUS statuskey = import_key(session, keytextkey.c_str(), keytextkey.length(), NULL);
        ASSERT_EQ(statuskey , PEP_TEST_KEY_IMPORT_SUCCESS);
    }

    output_stream << "\t read keyfile mailfile \"" << mailfile << "\"..." << std::endl;
    const string mailtext = slurp(mailfile);
    output_stream << "\t All files read successfully." << std::endl;

    pEp_identity * me1 = new_identity("pep.color.test.P@kgrothoff.org",
                                      "7EE6C60C68851954E1797F81EA59715E3EBE215C",
                                      PEP_OWN_USERID, "Pep Color Test P (recip)");
    me1->me = true;
    PEP_STATUS status = myself(session, me1);

    pEp_identity * sender1 = new_identity("pep.color.test.V@kgrothoff.org",
                                          NULL, "TOFU_pep.color.test.V@kgrothoff.org",
                                          "Pep Color Test V (sender)");

    status = set_fpr_preserve_ident(session, sender1, "AFC019B22E2CC61F13F285BF179B9DF271FC6D28", false);
    ASSERT_OK;
    status = update_identity(session, sender1);
    ASSERT_OK;
    status = trust_personal_key(session, sender1);
    ASSERT_OK;
    status = update_identity(session, sender1);
    ASSERT_OK;
    
    message* msg_ptr = nullptr;
    message* dest_msg = nullptr;
    message* final_ptr = nullptr;
    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;
    output_stream << "rating: " << rating << endl << endl;
    output_stream << "keys used: " << endl;

    int i = 0;
    for (stringlist_t* k = keylist; k; k = k->next) {
        if (i == 0)
            output_stream << "\t Signer (key 0):\t" << k->value << endl;
        else
            output_stream << "\t #" << i << ":\t" << k->value << endl;
        i++;
    }

//    free_identity(me1);
    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);
}
