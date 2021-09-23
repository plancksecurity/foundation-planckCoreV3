// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <string>

#include <assert.h>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "TestUtilities.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for MessageNullFromTest
    class MessageNullFromTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            
            // You can remove any or all of the following functions if its body
            // is empty.
            MessageNullFromTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~MessageNullFromTest() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            void import_alice_pub() {
                const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
                PEP_STATUS status = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
                assert(status == PEP_TEST_KEY_IMPORT_SUCCESS);
            }

            void import_bob_pair_and_set_own() {
                const string bob_pub_key = slurp("test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
                const string bob_priv_key = slurp("test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc");
                PEP_STATUS status = import_key(session, bob_pub_key.c_str(), bob_pub_key.length(), NULL);
                assert(status == PEP_TEST_KEY_IMPORT_SUCCESS);
                status = import_key(session, bob_priv_key.c_str(), bob_priv_key.length(), NULL);
                assert(status == PEP_TEST_KEY_IMPORT_SUCCESS);
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
                import_bob_pair_and_set_own();
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
            // Objects declared here can be used by all tests in the MessageNullFromTest suite.

    };

}  // namespace


TEST_F(MessageNullFromTest, check_message_null_from_no_header_key_unencrypted) {
    string null_from_msg = slurp("test_files/432_no_from_2.eml");
    output_stream << null_from_msg << endl;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;
    message* enc_msg = string_to_msg(null_from_msg);
    message* dec_msg = NULL;
    ASSERT_NOTNULL(enc_msg);
    PEP_STATUS status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &flags);
    ASSERT_EQ(status , PEP_UNENCRYPTED);
}

TEST_F(MessageNullFromTest, check_message_null_from_header_key_unencrypted) {
    string null_from_msg = slurp("test_files/432_no_from.eml");
    output_stream << null_from_msg << endl;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;
    message* enc_msg = string_to_msg(null_from_msg);
    message* dec_msg = NULL;
    ASSERT_NOTNULL(enc_msg);
    PEP_STATUS status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &flags);
    ASSERT_EQ(status , PEP_UNENCRYPTED);
}

TEST_F(MessageNullFromTest, check_message_null_from_encrypted_not_signed) {
    import_alice_pub();
    message* plaintext_msg = NULL;
    PEP_STATUS status = vanilla_read_file_and_decrypt(session, &plaintext_msg, "test_files/432_no_from_encrypted_not_signed.eml");
    ASSERT_EQ(status , PEP_DECRYPTED);
    ASSERT_NOTNULL(plaintext_msg);
    free_message(plaintext_msg);
}

TEST_F(MessageNullFromTest, check_message_null_from_encrypted_and_signed) {
    import_alice_pub();
    message* plaintext_msg = NULL;
    PEP_STATUS status = vanilla_read_file_and_decrypt(session, &plaintext_msg, "test_files/432_no_from_encrypted_and_signed.eml");
    ASSERT_OK;
    ASSERT_NOTNULL(plaintext_msg);
}
