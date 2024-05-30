#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "TestUtilities.h"
#include "TestConstants.h"
#include "Engine.h"
#include <fstream>

#include <gtest/gtest.h>

namespace {

	// Tests for RFC-16 Passphrase Handling
    class PassphraseHandlingTest : public ::testing::Test {
        public:
            Engine *engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            PassphraseHandlingTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~PassphraseHandlingTest() override {
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

                // Try to speed up key generation.
                PEP_STATUS status = config_cipher_suite(session, PEP_CIPHER_SUITE_RSA2K);
                ASSERT_EQ(status, PEP_STATUS_OK);

                // own identity without key passphrase
                tyrell_identity = new_identity(tyrell_no_passphrase_email,
                    NULL,
                    PEP_OWN_USERID,
                    tyrell_no_passphrase_username);
                ASSERT_NOTNULL(tyrell_identity);
                status = myself(session, tyrell_identity);
                ASSERT_EQ(status, PEP_STATUS_OK);

                // own identity with key passphrase 1
                status = config_passphrase_for_new_keys(session, true, tyrell_passphrase_1);
                ASSERT_EQ(status, PEP_STATUS_OK);
                tyrell_identity_passphrase_1 = new_identity(tyrell_passphrase_email_1,
                    NULL,
                    PEP_OWN_USERID,
                    tyrell_passphrase_username_1);
                ASSERT_NOTNULL(tyrell_identity_passphrase_1);
                status = myself(session, tyrell_identity_passphrase_1);
                ASSERT_EQ(status, PEP_STATUS_OK);

                // own identity with key passphrase 2
                status = config_passphrase_for_new_keys(session, true, tyrell_passphrase_2);
                ASSERT_EQ(status, PEP_STATUS_OK);
                tyrell_identity_passphrase_2 = new_identity(tyrell_passphrase_email_2,
                    NULL,
                    PEP_OWN_USERID,
                    tyrell_passphrase_username_2);
                ASSERT_NOTNULL(tyrell_identity_passphrase_2);
                status = myself(session, tyrell_identity_passphrase_2);
                ASSERT_EQ(status, PEP_STATUS_OK);

                status = config_passphrase_for_new_keys(session, false, NULL);
                ASSERT_EQ(status, PEP_STATUS_OK);
            }

            void TearDown() override {
                free_identity(tyrell_identity);
                free_identity(tyrell_identity_passphrase_1);

                // Code here will be called immediately after each test (right
                // before the destructor).
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }
            
            const char *tyrell_no_passphrase_email = "tyrell@example.com";
            const char *tyrell_no_passphrase_username = "Eldon Tyrell (no passphrase)";

            const char *tyrell_passphrase_email_1 = "tyrell_passphrase_1@example.com";
            const char *tyrell_passphrase_username_1 = "Eldon Tyrell (passphrase 1)";

            const char *tyrell_passphrase_email_2 = "tyrell_passphrase_2@example.com";
            const char *tyrell_passphrase_username_2 = "Eldon Tyrell (passphrase 2)";

            const char *tyrell_passphrase_1 = "blarg1";
            const char *tyrell_passphrase_2 = "blarg2";

            pEp_identity *tyrell_identity;
            pEp_identity *tyrell_identity_passphrase_1;
            pEp_identity *tyrell_identity_passphrase_2;
            
        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the PassphraseHandlingTest suite.
    };

}  // namespace

TEST_F(PassphraseHandlingTest, has_passphrase_no_passphrase) {
    bool passphrase_bool = false;
    PEP_STATUS status = has_passphrase(session, tyrell_no_passphrase_email, &passphrase_bool);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_FALSE(passphrase_bool);
}

TEST_F(PassphraseHandlingTest, has_passphrase_passphrase) {
    bool passphrase_bool = false;
    PEP_STATUS status = has_passphrase(session, tyrell_passphrase_email_1, &passphrase_bool);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(passphrase_bool);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_one_identity_passphrase_required) {
    stringpair_list_t *accounts_passphrases = new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, ""));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_EQ(string{errors->value}, string{tyrell_passphrase_email_1});

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_one_identity_no_passphrase_required) {
    stringpair_list_t *accounts_passphrases = new_stringpair_list(new_stringpair(tyrell_no_passphrase_email, ""));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase) {
    stringpair_list_t *accounts_passphrases = new_stringpair_list(new_stringpair(tyrell_no_passphrase_email, ""));
    stringpair_list_add(accounts_passphrases, new_stringpair(tyrell_no_passphrase_email, tyrell_passphrase_1));
    ASSERT_EQ(stringpair_list_length(accounts_passphrases), 2);

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_unknown_account) {
    const char *email = "completely_bogus@example.com";
    stringpair_list_t *accounts_passphrases = new_stringpair_list(new_stringpair(email, ""));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_CANNOT_FIND_IDENTITY);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_EQ(string{errors->value}, string{email});

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_unknown_accounts) {
    const char *email = "completely_bogus@example.com";
    stringpair_list_t *accounts_passphrases = new_stringpair_list(new_stringpair(email, ""));
    stringpair_list_add(accounts_passphrases, new_stringpair("bogus2@example.com", ""));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_CANNOT_FIND_IDENTITY);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_EQ(string{errors->value}, string{email});

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_empty_account) {
    const char *email = "completely_bogus@example.com";
    stringpair_list_t *accounts_passphrases = new_stringpair_list(new_stringpair(email, ""));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_CANNOT_FIND_IDENTITY);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_EQ(string{errors->value}, string{email});

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_all) {
    stringpair_list_t *accounts_passphrases = new_stringpair_list(new_stringpair(tyrell_no_passphrase_email, ""));
    stringpair_list_add(accounts_passphrases, new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases, new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_2));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_mixed) {
    stringpair_list_t *accounts_passphrases = new_stringpair_list(new_stringpair(tyrell_no_passphrase_email, ""));
    stringpair_list_add(accounts_passphrases, new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_2));
    stringpair_list_add(accounts_passphrases, new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_1));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 2);
    ASSERT_EQ(string{errors->value}, string{tyrell_passphrase_email_1});

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, manage_passphrase_happy_path) {
    const char *new_passphrase = "new_blarg";

    stringpair_list_t *accounts_passphrases_1 = new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases_1, new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_2));

    stringlist_t *errors = NULL;
    PEP_STATUS status = manage_passphrase(session, accounts_passphrases_1, new_passphrase, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    errors = NULL;
    status = unlock_keys_with_passphrase(session, accounts_passphrases_1, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 2);

    free_stringpair_list(accounts_passphrases_1);

    stringpair_list_t *accounts_passphrases_2 = new_stringpair_list(new_stringpair(tyrell_no_passphrase_email, ""));
    stringpair_list_add(accounts_passphrases_2, new_stringpair(tyrell_passphrase_email_1, new_passphrase));
    stringpair_list_add(accounts_passphrases_2, new_stringpair(tyrell_passphrase_email_2, new_passphrase));

    free_stringlist(errors);
    errors = NULL;
    status = unlock_keys_with_passphrase(session, accounts_passphrases_2, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_2);
}
