// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "platform.h"

#include "test_util.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for KeyeditTest
    class KeyeditTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            KeyeditTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~KeyeditTest() override {
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

            const char* alice_filename = "test_keys/alice-no-passwords.pgp";
            const char* alice_pub_filename = "test_keys/pub/alice-0x2A649B9F_pub.asc";
            const char* bob_filename = "test_keys/bob-primary-with-password-bob-subkey-without.pgp";
            const char* carol_filename = "test_keys/carol-subkeys-password-carol.pgp";
            const char* david_filename = "test_keys/david-encryption-subkey-password-encrypt-signing-subkey-password-sign.pgp";
            const char* erwin_filename = "test_keys/erwin-primary-encrypted-erwin-subkey-unencrypted.pgp";
            const char* alice_fpr = "03AF88F728B8E9AADA7F370BD41801C62A649B9F";
            const char* bob_fpr = "5C76378A62B04CF3F41BEC8D4940FC9FA1878736";
            const char* carol_fpr = "A5B3473EA7CBB5DF7A4F595A8883DC4BCD8BAC06";
            const char* david_fpr = "7F72E4B27C6161455CD9C50FE7A05D7BF3FF4E19";
            const char* erwin_fpr = "A34048189F0067DF0006FB28CBD7CFBCC0FA7F97";

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the KeyeditTest suite.

    };

}  // namespace


TEST_F(KeyeditTest, check_keyedit) {

    // generate test key

    output_stream << "\ngenerating key for keyedit test\n";
    pEp_identity *identity = new_identity(
            "expire@dingens.org",
            NULL,
            "423",
            "expire test key"
        );
    ASSERT_NOTNULL(identity);
    PEP_STATUS generate_status = generate_keypair(session, identity);
    output_stream << "generate_keypair() exits with " << generate_status << "\n";
    ASSERT_EQ(generate_status, PEP_STATUS_OK);
    output_stream << "generated key is " << identity->fpr << "\n";

    string key(identity->fpr);
    free_identity(identity);

    // keyedit test code

    time_t now = time(NULL);
    output_stream << "Time is " << now << endl;
    timestamp *ts = new_timestamp(now);
    ts->tm_year += 2;

    output_stream << "key shall expire on " << asctime(ts) << "\n";

    PEP_STATUS status2 = renew_key(session, key.c_str(), ts);
    output_stream << "renew_key() exited with " << status2 << "\n";
    ASSERT_EQ(status2, PEP_STATUS_OK);
    free_timestamp(ts);

    output_stream << "key renewed.\n";

    output_stream << "key will be revoked\n";
    PEP_STATUS status3 = revoke_key(session, key.c_str(), "revoke test");
    output_stream << "revoke_key() exited with " << status3 << "\n";
    ASSERT_EQ(status3, PEP_STATUS_OK);

    output_stream << "key revoked.\n";

    // Because pEp's policy is never to delete keys from the keyring and delete_keypair
    // though gnupg makes responding to a dialog mandatory under Debian, we will not test
    // this anymore.

    // output_stream << "deleting key pair " << key.c_str() << "\n";
    // PEP_STATUS delete_status = delete_keypair(session, key.c_str());
    // output_stream << "delete_keypair() exits with " << delete_status << "\n";
    // ASSERT_EQ(delete_status , PEP_STATUS_OK);
}

TEST_F(KeyeditTest, check_renew_key_correct_passphrase) {
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    config_passphrase(session, "bob");

    time_t now = time(NULL);
    output_stream << "Time is " << now << endl;
    timestamp *ts = new_timestamp(now);
    ts->tm_year += 2;

    status = renew_key(session, bob_fpr, ts);
    ASSERT_EQ(status, PEP_STATUS_OK);            
}

TEST_F(KeyeditTest, check_renew_key_needs_passphrase) {
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);

    time_t now = time(NULL);
    output_stream << "Time is " << now << endl;
    timestamp *ts = new_timestamp(now);
    ts->tm_year += 2;

    status = renew_key(session, bob_fpr, ts);
    ASSERT_EQ(status, PEP_PASSPHRASE_REQUIRED);

}

TEST_F(KeyeditTest, check_renew_key_wrong_passphrase) {
    ASSERT_TRUE(slurp_and_import_key(session, bob_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, bob_fpr, &found_key);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    config_passphrase(session, "julio");

    time_t now = time(NULL);
    output_stream << "Time is " << now << endl;
    timestamp *ts = new_timestamp(now);
    ts->tm_year += 2;

    status = renew_key(session, bob_fpr, ts);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);    
}
