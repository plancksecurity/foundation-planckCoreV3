// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "mime.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for EncryptAttachPrivateKeyTest
    class EncryptAttachPrivateKeyTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            EncryptAttachPrivateKeyTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~EncryptAttachPrivateKeyTest() override {
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
            // Objects declared here can be used by all tests in the EncryptAttachPrivateKeyTest suite.

    };

}  // namespace


TEST_F(EncryptAttachPrivateKeyTest, check_encrypt_attach_private_key) {

    const char* own_uid = PEP_OWN_USERID;
    const char* diff_uid_0 = "TASTY_TEST_UID_0";
    const char* diff_uid_1 = "TASTY_TEST_UID_1";

    output_stream << "Importing keys..." << endl;

    string input_key;
    const char* main_addr = "priv-key-import-test-main@darthmama.cool";
    pEp_identity* main_me = NULL;
    const char* fpr_main_me = "8AB616A3BD51DEF714B5E688EFFB540C3276D2E5";
    pEp_identity* same_addr_same_uid = NULL;
    const char* fpr_same_addr_same_uid = "359DD8AC87D1F5E4304D08338D7185F180C8CD87";

    pEp_identity* same_addr_diff_uid = NULL;
    const char* fpr_same_addr_diff_uid = "B044B83639E292283A3F6E14C2E64B520B74809C";

    const char* diff_addr_0 = "priv-key-import-test-other_0@darthmama.cool";
    pEp_identity* diff_addr_same_uid = NULL;
    const char* fpr_diff_addr_same_uid = "C52911EBA0D34B0F549594A15A7A363BD11252C9";

    const char* diff_addr_1 = "priv-key-import-test-other_1@darthmama.cool";
    pEp_identity* diff_addr_diff_uid = NULL;
    const char* fpr_diff_addr_diff_uid = "567212EFB8A3A76B1D32B9565F45BEA9C785F20A";

    PEP_STATUS status = PEP_STATUS_OK;

    // key for main own user
    // 8AB616A3BD51DEF714B5E688EFFB540C3276D2E5
    input_key = slurp("test_keys/pub/priv-key-import-test-main_0-0x3276D2E5_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);

    input_key = slurp("test_keys/priv/priv-key-import-test-main_0-0x3276D2E5_priv.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);

    // key with same address and user_id (initially untrusted, then trusted)
    // 359DD8AC87D1F5E4304D08338D7185F180C8CD87
    input_key = slurp("test_keys/pub/priv-key-import-test-main_1-0x80C8CD87_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);

    // key with same address and to have different (non-aliased) user_id (initially untrusted, then trusted)
    // B044B83639E292283A3F6E14C2E64B520B74809C
    input_key = slurp("test_keys/pub/priv-key-import-test-main_2-0x0B74809C_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);

    // key with different address to have same user_id (initially untrusted, then trusted)
    // C52911EBA0D34B0F549594A15A7A363BD11252C9
    input_key = slurp("test_keys/pub/priv-key-import-test-other_0-0xD11252C9_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);

    // key with different address to have different user_id (initially untrusted, then trusted)
    // 567212EFB8A3A76B1D32B9565F45BEA9C785F20A
    input_key = slurp("test_keys/pub/priv-key-import-test-other_1-0xC785F20A_pub.asc");
    status = import_key(session, input_key.c_str(), input_key.length(), NULL);
    ASSERT_EQ(status, PEP_TEST_KEY_IMPORT_SUCCESS);
    output_stream << "Done!" << endl << endl;

    output_stream << "Setting up own identity with default key " << fpr_main_me << endl;
    // Own identity with default key etc
    main_me = new_identity(main_addr, fpr_main_me, own_uid, "PrivateKey Import Test");
    status = set_own_key(session, main_me, fpr_main_me);
    ASSERT_EQ(status, PEP_STATUS_OK);

    ASSERT_STREQ(main_me->fpr, fpr_main_me);
    output_stream << "Done!" << endl << endl;

    output_stream << "Setting up recipient identities and resetting key trust." << endl;
    output_stream << "#1: same address, same user_id - address: " << main_addr << ", user_id: " << own_uid << ", fpr: " << fpr_same_addr_same_uid << endl;
    // Identity with same address and user_id - the fpr here will be ignored in update_identity and friends.
    same_addr_same_uid = new_identity(main_addr, fpr_same_addr_same_uid, own_uid, "PrivateKey Import Test");
    status = key_reset_trust(session, same_addr_same_uid);
    ASSERT_TRUE(status == PEP_STATUS_OK || status == PEP_CANNOT_FIND_IDENTITY);
    ASSERT_STREQ(same_addr_same_uid->fpr, fpr_same_addr_same_uid);

    // Identity with same address and different user_id
    output_stream << "#2: same address, different user_id - address: " << main_addr << ", user_id: " << diff_uid_0 << ", fpr: " << fpr_same_addr_diff_uid << endl;
    same_addr_diff_uid = new_identity(main_addr, fpr_same_addr_diff_uid, diff_uid_0, "PrivateKey Import Test");
    ASSERT_NE(same_addr_diff_uid, nullptr);
    status = key_reset_trust(session, same_addr_diff_uid);
    ASSERT_TRUE(status == PEP_STATUS_OK || status == PEP_CANNOT_FIND_IDENTITY);
    ASSERT_STREQ(same_addr_diff_uid->fpr, fpr_same_addr_diff_uid);

    // Identity with diff address and same user_id
    output_stream << "#3: different address, same user_id - address: " << diff_addr_0 << ", user_id: " << own_uid << ", fpr: " << fpr_diff_addr_same_uid << endl;
    diff_addr_same_uid = new_identity(diff_addr_0, fpr_diff_addr_same_uid, own_uid, "PrivateKey Import Test");
    ASSERT_NE(diff_addr_same_uid, nullptr);
    status = key_reset_trust(session, diff_addr_same_uid);
    ASSERT_TRUE(status == PEP_STATUS_OK || status == PEP_CANNOT_FIND_IDENTITY);
    ASSERT_STREQ(diff_addr_same_uid->fpr, fpr_diff_addr_same_uid);

    // Identity with different address and different user_id
    output_stream << "#4: different address, different user_id - address: " << diff_addr_1 << ", user_id: " << diff_uid_1 << ", fpr: " << fpr_diff_addr_diff_uid << endl;
    diff_addr_diff_uid = new_identity(diff_addr_1, fpr_diff_addr_diff_uid, diff_uid_1, "PrivateKey Import Test");
    ASSERT_NE(diff_addr_diff_uid, nullptr);
    status = key_reset_trust(session, diff_addr_diff_uid);
    ASSERT_TRUE(status == PEP_STATUS_OK || status == PEP_CANNOT_FIND_IDENTITY);
    ASSERT_STREQ(diff_addr_diff_uid->fpr, fpr_diff_addr_diff_uid);
    output_stream << "Done!" << endl << endl;

    message* msg_same_addr_same_uid = new_message(PEP_dir_outgoing);
    msg_same_addr_same_uid->from = main_me;
    msg_same_addr_same_uid->shortmsg = strdup("Greetings, humans!");
    msg_same_addr_same_uid->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    msg_same_addr_same_uid->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    message* msg_same_addr_diff_uid = message_dup(msg_same_addr_same_uid);
    message* msg_diff_addr_same_uid = message_dup(msg_same_addr_same_uid);
    message* msg_diff_addr_diff_uid = message_dup(msg_same_addr_same_uid);

    output_stream << "Starting tests..." << endl;
    // Case 1:
    // Same address, same user_id, untrusted
    output_stream << "Case 1: Same address, same user_id, untrusted" << endl;
    ASSERT_NE(msg_same_addr_same_uid, nullptr);
    identity_list* to_list = new_identity_list(same_addr_same_uid);
    msg_same_addr_same_uid->to = to_list;
    message* enc_same_addr_same_uid_untrusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_same_addr_same_uid,
                                              &enc_same_addr_same_uid_untrusted,
                                              fpr_same_addr_same_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    output_stream << "Case 1 Status: " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    output_stream << "PASS!" << endl;

    // Case 2:
    // Same address, same_user_id, trusted
    output_stream << "Case 2: Same address, same user_id, trusted" << endl;
    status = trust_own_key(session, same_addr_same_uid);
    output_stream << "Trust personal key for " << same_addr_same_uid << " gives status " << tl_status_string(status) << " (" << status << ")" << endl;
    ASSERT_EQ(status, PEP_STATUS_OK);
    message* enc_same_addr_same_uid_trusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_same_addr_same_uid,
                                              &enc_same_addr_same_uid_trusted,
                                              fpr_same_addr_same_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    output_stream << "Case 2 Status: " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_STATUS_OK);
    output_stream << "PASS!" << endl;

    // Case 3:
    // Different address, same user_id, untrusted
    output_stream << "Case 3: Different address, same user_id, untrusted" << endl;
    ASSERT_NE(msg_diff_addr_same_uid, nullptr);
    identity_list* to_list_1 = new_identity_list(diff_addr_same_uid);
    msg_diff_addr_same_uid->to = to_list_1;
    message* enc_diff_addr_same_uid_untrusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_diff_addr_same_uid,
                                              &enc_diff_addr_same_uid_untrusted,
                                              fpr_diff_addr_same_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    output_stream << "Case 3 Status: " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    output_stream << "PASS!" << endl;

    // Case 4:
    // Different address, same user_id, trusted
    output_stream << "Case 4: Different address, same user_id, trusted" << endl;
    status = trust_own_key(session, diff_addr_same_uid);
    ASSERT_EQ(status, PEP_STATUS_OK);
    message* enc_diff_addr_same_uid_trusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_diff_addr_same_uid,
                                              &enc_diff_addr_same_uid_trusted,
                                              fpr_diff_addr_same_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    output_stream << "Case 4 Status: " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    output_stream << "PASS!" << endl;

    // Case 5:
    // Same address, different user_id, untrusted
    output_stream << "Case 5: Same address, different user_id, untrusted" << endl;
    ASSERT_NE(msg_same_addr_diff_uid, nullptr);
    identity_list* to_list_2 = new_identity_list(same_addr_diff_uid);
    msg_same_addr_diff_uid->to = to_list_2;
    message* enc_same_addr_diff_uid_untrusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_same_addr_diff_uid,
                                              &enc_same_addr_diff_uid_untrusted,
                                              fpr_same_addr_diff_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    output_stream << "Case 5 Status: " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    output_stream << "PASS!" << endl;

    // Case 6:
    // Same address, different user_id, trusted
    output_stream << "Case 6: Same address, different user_id, trusted" << endl;
    status = trust_personal_key(session, same_addr_diff_uid);
    ASSERT_EQ(status, PEP_STATUS_OK);
    message* enc_same_addr_diff_uid_trusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_same_addr_diff_uid,
                                              &enc_same_addr_diff_uid_untrusted,
                                              fpr_same_addr_diff_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    output_stream << "Case 6 Status: " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    output_stream << "PASS!" << endl;

    // Case 7:
    // Different address, different user_id, untrusted
    output_stream << "Case 7: Different address, different user_id, untrusted" << endl;
    ASSERT_NE(msg_diff_addr_diff_uid, nullptr);
    identity_list* to_list_3 = new_identity_list(diff_addr_diff_uid);
    msg_diff_addr_diff_uid->to = to_list_3;
    message* enc_diff_addr_diff_uid_untrusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_diff_addr_diff_uid,
                                              &enc_diff_addr_diff_uid_untrusted,
                                              fpr_diff_addr_diff_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    output_stream << "Case 7 Status: " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    output_stream << "PASS!" << endl;

    // Case 8:
    // Different address, different user_id, trusted
    output_stream << "Case 8: Different address, different user_id, trusted" << endl;
    status = trust_personal_key(session, diff_addr_diff_uid);
    ASSERT_EQ(status, PEP_STATUS_OK);
    message* enc_diff_addr_diff_uid_trusted = NULL;
    status = encrypt_message_and_add_priv_key(session,
                                              msg_diff_addr_diff_uid,
                                              &enc_diff_addr_diff_uid_trusted,
                                              fpr_diff_addr_diff_uid,
                                              PEP_enc_PGP_MIME,
                                              0);

    output_stream << "Case 8 Status: " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    output_stream << "PASS!" << endl;

    output_stream << "Correctly encrypted message:" << endl << endl;
    char* encrypted_msg_text = NULL;
    mime_encode_message(enc_same_addr_same_uid_trusted, false, &encrypted_msg_text, false);
    output_stream << encrypted_msg_text << endl << endl;

    // FIXME: Free all the damned things
}
