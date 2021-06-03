// This file is under GNU General Public License 3.0
// see LICENSE.txt

// FIXME: the private key tests should be combined

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "mime.h"
#include "message_api.h"
#include "keymanagement.h"
#include "TestUtilities.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for DecryptAttachPrivateKeyTrustedTest
    class DecryptAttachPrivateKeyTrustedTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            DecryptAttachPrivateKeyTrustedTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~DecryptAttachPrivateKeyTrustedTest() override {
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
            // Objects declared here can be used by all tests in the DecryptAttachPrivateKeyTrustedTest suite.

    };

}  // namespace


TEST_F(DecryptAttachPrivateKeyTrustedTest, check_decrypt_attach_private_key_trusted) {

    const char* own_uid = PEP_OWN_USERID;

    output_stream << "Importing keys..." << endl;

    string input_key;
    const char* main_addr = "priv-key-import-test-main@darthmama.cool";
    pEp_identity* main_me = NULL;
    const char* fpr_main_me = "13A9F97964A2B52520CAA40E51BCA783C065A213";
    pEp_identity* same_addr_same_uid = NULL;
    const char* fpr_same_addr_same_uid = "8AB616A3BD51DEF714B5E688EFFB540C3276D2E5";

    PEP_STATUS status = PEP_STATUS_OK;

    // key for main own user
    //
    // 13A9F97964A2B52520CAA40E51BCA783C065A213
    input_key = slurp("test_keys/pub/priv-key-import-test-main_0-0xC065A213_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);

    input_key = slurp("test_keys/priv/priv-key-import-test-main_0-0xC065A213_priv.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);

    // ensure there's no private key - doesn't work in automated tests, sadly. Uncommon when running script manually.
    bool has_priv = false;

    // key with same address and user_id
    // 8AB616A3BD51DEF714B5E688EFFB540C3276D2E5
    input_key = slurp("test_keys/pub/priv-key-import-test-main_0-0x3276D2E5_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);


    output_stream << "Setting up own identity with default key " << fpr_main_me << endl;
    // Own identity with default key etc
    main_me = new_identity(main_addr, fpr_main_me, own_uid, "PrivateKey Import Test");
    status = set_own_key(session, main_me, fpr_main_me);
    ASSERT_EQ(status, PEP_STATUS_OK);

    ASSERT_STREQ(main_me->fpr, fpr_main_me);
    output_stream << "Done!" << endl << endl;

    output_stream << "Setting up sender identities and resetting key trust." << endl;
    output_stream << "Same address, same user_id - address: " << main_addr << ", user_id: " << own_uid << ", fpr: " << fpr_same_addr_same_uid << endl;
    same_addr_same_uid = new_identity(main_addr, fpr_same_addr_same_uid, own_uid, "PrivateKey Import Test");
    ASSERT_TRUE(status == PEP_STATUS_OK || status == PEP_CANNOT_FIND_IDENTITY);
    ASSERT_NE(same_addr_same_uid->comm_type & PEP_ct_confirmed, PEP_ct_confirmed);

    status = key_reset_trust(session, same_addr_same_uid);

    output_stream << "Done!" << endl << endl;

    output_stream << "Reading in message..." << endl;

    string encoded_text = slurp("test_mails/priv_key_attach.eml");

    output_stream << "Starting test..." << endl;
    // Case 1:
    // Same address, same user_id, untrusted
    output_stream << "decrypt with attached private key: Same address, same user_id, trusted" << endl;
    char* decrypted_text = NULL;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    char* modified_src = NULL;

    output_stream << "Trusting own key for " << same_addr_same_uid->user_id << " and " << same_addr_same_uid->fpr << endl;
    status = trust_own_key(session, same_addr_same_uid);
    output_stream << "Status is " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_STATUS_OK);
    free(decrypted_text);
    decrypted_text = NULL;

    status = get_trust(session, same_addr_same_uid);
    output_stream << tl_ct_string(same_addr_same_uid->comm_type) << endl;

    ASSERT_EQ(same_addr_same_uid->comm_type, PEP_ct_pEp);

    flags = 0;
    status = MIME_decrypt_message(session, encoded_text.c_str(),
                                  encoded_text.size(), &decrypted_text,
                                  &keylist_used, &rating, &flags,
                                  &modified_src);

    status = get_trust(session, same_addr_same_uid);
    ASSERT_EQ(same_addr_same_uid->comm_type, PEP_ct_pEp);

    flags = 0;
    status = MIME_decrypt_message(session, encoded_text.c_str(),
                                  encoded_text.size(), &decrypted_text,
                                  &keylist_used, &rating, &flags,
                                  &modified_src);

    output_stream << "Status: " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_STATUS_OK);

    output_stream << decrypted_text << endl;

    has_priv = false;
    status = contains_priv_key(session, fpr_same_addr_same_uid, &has_priv);
    ASSERT_TRUE(has_priv);
    output_stream << "Private key was also imported." << endl;

    output_stream << "PASS!" << endl;

    // FIXME: rework this in new framework
    status = key_reset_trust(session, main_me);
    status = key_reset_trust(session, same_addr_same_uid);
}
