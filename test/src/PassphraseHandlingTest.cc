#include <cstring>
#include <stdlib.h>
#include <string>

#include "Engine.h"
#include "TestConstants.h"
#include "TestUtilities.h"
#include "pEpEngine.h"
#include "pEp_internal.h"
#include <fstream>

#include <gtest/gtest.h>

using std::string;
using std::vector;
using std::tuple;

namespace {

// Tests for RFC-16 Passphrase Handling
class PassphraseHandlingTest : public ::testing::Test
{
  public:
    Engine *engine;
    PEP_SESSION session;

  protected:
    // You can remove any or all of the following functions if its body
    // is empty.
    PassphraseHandlingTest()
    {
        // You can do set-up work for each test here.
        test_suite_name =
          ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
        test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
        test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
    }

    ~PassphraseHandlingTest() override
    {
        // You can do clean-up work that doesn't throw exceptions here.
    }

    // If the constructor and destructor are not enough for setting up
    // and cleaning up each test, you can define the following methods:

    void SetUp() override
    {
        // Code here will be called immediately after the constructor (right
        // before each test).

        // Leave this empty if there are no files to copy to the home directory path
        std::vector<std::pair<std::string, std::string>> init_files =
          std::vector<std::pair<std::string, std::string>>();

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

        // own identity without key passphrase 1
        tyrell_identity_1 = new_identity(
          tyrell_no_passphrase_email_1, NULL, PEP_OWN_USERID, tyrell_no_passphrase_username_1);
        ASSERT_NOTNULL(tyrell_identity_1);
        status = myself(session, tyrell_identity_1);
        ASSERT_EQ(status, PEP_STATUS_OK);

        // own identity without key passphrase 2
        tyrell_identity_2 = new_identity(
          tyrell_no_passphrase_email_2, NULL, PEP_OWN_USERID, tyrell_no_passphrase_username_2);
        ASSERT_NOTNULL(tyrell_identity_2);
        status = myself(session, tyrell_identity_2);
        ASSERT_EQ(status, PEP_STATUS_OK);

        // set up generation passphrases
        vector<tuple<string, string>> account_passphrases{
          {tyrell_passphrase_email_1, tyrell_passphrase_1},
          {tyrell_passphrase_email_2, tyrell_passphrase_2},
          {tyrell_passphrase_email_3, tyrell_passphrase_3}
        };
        status = configure_account_passphrases(session, account_passphrases);
        ASSERT_EQ(status, PEP_STATUS_OK);

        // own identity with key passphrase 1
        tyrell_identity_passphrase_1 = new_identity(
          tyrell_passphrase_email_1, NULL, PEP_OWN_USERID, tyrell_passphrase_username_1);
        ASSERT_NOTNULL(tyrell_identity_passphrase_1);
        status = myself(session, tyrell_identity_passphrase_1);
        ASSERT_EQ(status, PEP_STATUS_OK);

        // own identity with key passphrase 2
        tyrell_identity_passphrase_2 = new_identity(
          tyrell_passphrase_email_2, NULL, PEP_OWN_USERID, tyrell_passphrase_username_2);
        ASSERT_NOTNULL(tyrell_identity_passphrase_2);
        status = myself(session, tyrell_identity_passphrase_2);
        ASSERT_EQ(status, PEP_STATUS_OK);

        // own identity with key passphrase 3
        tyrell_identity_passphrase_3 = new_identity(
          tyrell_passphrase_email_3, NULL, PEP_OWN_USERID, tyrell_passphrase_username_3);
        ASSERT_NOTNULL(tyrell_identity_passphrase_3);
        status = myself(session, tyrell_identity_passphrase_3);
        ASSERT_EQ(status, PEP_STATUS_OK);

        status = config_passphrase_for_new_keys(session, false, NULL);
        ASSERT_EQ(status, PEP_STATUS_OK);
    }

    void TearDown() override
    {
        free_identity(tyrell_identity_1);
        free_identity(tyrell_identity_passphrase_1);

        // Code here will be called immediately after each test (right
        // before the destructor).
        engine->shut_down();
        delete engine;
        engine = NULL;
        session = NULL;
    }

    const char *tyrell_no_passphrase_email_1 = "tyrell_1@example.com";
    const char *tyrell_no_passphrase_username_1 = "Eldon Tyrell 1 (no passphrase)";

    const char *tyrell_no_passphrase_email_2 = "tyrell_2@example.com";
    const char *tyrell_no_passphrase_username_2 = "Eldon Tyrell 2 (no passphrase)";

    const char *tyrell_passphrase_email_1 = "tyrell_passphrase_1@example.com";
    const char *tyrell_passphrase_username_1 = "Eldon Tyrell (passphrase 1)";

    const char *tyrell_passphrase_email_2 = "tyrell_passphrase_2@example.com";
    const char *tyrell_passphrase_username_2 = "Eldon Tyrell (passphrase 2)";

    const char *tyrell_passphrase_email_3 = "tyrell_passphrase_3@example.com";
    const char *tyrell_passphrase_username_3 = "Eldon Tyrell (passphrase 3)";

    const char *tyrell_passphrase_1 = "blarg1";
    const char *tyrell_passphrase_2 = "blarg2";
    const char *tyrell_passphrase_3 = "blarg3";

    pEp_identity *tyrell_identity_1;
    pEp_identity *tyrell_identity_2;
    pEp_identity *tyrell_identity_passphrase_1;
    pEp_identity *tyrell_identity_passphrase_2;
    pEp_identity *tyrell_identity_passphrase_3;

  private:
    const char *test_suite_name;
    const char *test_name;
    string test_path;
    // Objects declared here can be used by all tests in the PassphraseHandlingTest suite.
};

} // namespace

TEST_F(PassphraseHandlingTest, has_passphrase_no_passphrase)
{
    bool passphrase_bool = false;
    PEP_STATUS status = has_passphrase(session, tyrell_no_passphrase_email_1, &passphrase_bool);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_FALSE(passphrase_bool);
}

TEST_F(PassphraseHandlingTest, has_passphrase_passphrase)
{
    bool passphrase_bool = false;
    PEP_STATUS status = has_passphrase(session, tyrell_passphrase_email_1, &passphrase_bool);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(passphrase_bool);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_one_identity_passphrase_required)
{
    stringpair_list_t *accounts_passphrases =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, ""));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_EQ(string{ errors->value }, string{ tyrell_passphrase_email_1 });

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_one_identity_no_passphrase_required)
{
    stringpair_list_t *accounts_passphrases =
      new_stringpair_list(new_stringpair(tyrell_no_passphrase_email_1, ""));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase)
{
    stringpair_list_t *accounts_passphrases =
      new_stringpair_list(new_stringpair(tyrell_no_passphrase_email_1, ""));
    stringpair_list_add(accounts_passphrases,
                        new_stringpair(tyrell_no_passphrase_email_1, tyrell_passphrase_1));
    ASSERT_EQ(stringpair_list_length(accounts_passphrases), 2);

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_unknown_account)
{
    const char *email = "completely_bogus@example.com";
    stringpair_list_t *accounts_passphrases = new_stringpair_list(new_stringpair(email, ""));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_CANNOT_FIND_IDENTITY);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_EQ(string{ errors->value }, string{ email });

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_unknown_accounts)
{
    const char *email = "completely_bogus@example.com";
    stringpair_list_t *accounts_passphrases = new_stringpair_list(new_stringpair(email, ""));
    stringpair_list_add(accounts_passphrases, new_stringpair("bogus2@example.com", ""));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_CANNOT_FIND_IDENTITY);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_EQ(string{ errors->value }, string{ email });

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_empty_account)
{
    const char *email = "completely_bogus@example.com";
    stringpair_list_t *accounts_passphrases = new_stringpair_list(new_stringpair(email, ""));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_CANNOT_FIND_IDENTITY);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_EQ(string{ errors->value }, string{ email });

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_all)
{
    stringpair_list_t *accounts_passphrases =
      new_stringpair_list(new_stringpair(tyrell_no_passphrase_email_1, ""));
    stringpair_list_add(accounts_passphrases,
                        new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_2));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, unlock_keys_with_passphrase_mixed)
{
    stringpair_list_t *accounts_passphrases =
      new_stringpair_list(new_stringpair(tyrell_no_passphrase_email_1, ""));
    stringpair_list_add(accounts_passphrases,
                        new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_2));
    stringpair_list_add(accounts_passphrases,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_1));

    stringlist_t *errors = NULL;
    PEP_STATUS status = unlock_keys_with_passphrase(session, accounts_passphrases, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 2);
    ASSERT_EQ(string{ errors->value }, string{ tyrell_passphrase_email_1 });

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases);
}

TEST_F(PassphraseHandlingTest, manage_passphrase_happy_path)
{
    const char *new_passphrase = "new_blarg";

    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_2));

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

    stringpair_list_t *accounts_passphrases_2 =
      new_stringpair_list(new_stringpair(tyrell_no_passphrase_email_1, ""));
    stringpair_list_add(accounts_passphrases_2,
                        new_stringpair(tyrell_passphrase_email_1, new_passphrase));
    stringpair_list_add(accounts_passphrases_2,
                        new_stringpair(tyrell_passphrase_email_2, new_passphrase));

    free_stringlist(errors);
    errors = NULL;
    status = unlock_keys_with_passphrase(session, accounts_passphrases_2, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_2);
}

TEST_F(PassphraseHandlingTest, manage_passphrase_wrong_old_passphrase)
{
    const char *new_passphrase = "new_blarg";

    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_1));

    stringlist_t *errors = NULL;
    PEP_STATUS status = manage_passphrase(session, accounts_passphrases_1, new_passphrase, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_EQ(string{ errors->value }, string{ tyrell_passphrase_email_2 });

    free_stringlist(errors);
    errors = NULL;
    status = unlock_keys_with_passphrase(session, accounts_passphrases_1, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_EQ(string{ errors->value }, string{ tyrell_passphrase_email_2 });

    stringpair_list_t *accounts_passphrases_2 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases_2,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_1));

    free_stringlist(errors);
    errors = NULL;
    status = unlock_keys_with_passphrase(session, accounts_passphrases_2, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_EQ(string{ errors->value }, string{ tyrell_passphrase_email_2 });

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_1);
    free_stringpair_list(accounts_passphrases_2);
}

TEST_F(PassphraseHandlingTest, manage_passphrase_wrong_old_passphrases)
{
    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_2));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_1));

    stringlist_t *errors = NULL;
    PEP_STATUS status =
      manage_passphrase(session, accounts_passphrases_1, "doesn't matter anyways", &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 2);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_1);
}

TEST_F(PassphraseHandlingTest, manage_passphrase_no_original_passphrase)
{
    const char *new_passphrase = "new_blarg";

    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases_1, new_stringpair(tyrell_no_passphrase_email_1, ""));

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

    stringpair_list_t *accounts_passphrases_2 =
      new_stringpair_list(new_stringpair(tyrell_no_passphrase_email_1, new_passphrase));
    stringpair_list_add(accounts_passphrases_2,
                        new_stringpair(tyrell_passphrase_email_1, new_passphrase));

    free_stringlist(errors);
    errors = NULL;
    status = unlock_keys_with_passphrase(session, accounts_passphrases_2, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_2);
}

TEST_F(PassphraseHandlingTest, manage_passphrase_remove_passphrase)
{
    // Empty passphrase means "remove it", and also unset any passphrase when verifying.
    const char *new_passphrase = "";

    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));

    stringlist_t *errors = NULL;
    // Empty new passphrase -> Passphrase gets removed.
    PEP_STATUS status = manage_passphrase(session, accounts_passphrases_1, new_passphrase, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringpair_list(accounts_passphrases_1);
    // Empty passphrase -> The "unlock" check is done _without_ passphrase set.
    accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, new_passphrase));
    free_stringlist(errors);
    errors = NULL;
    status = unlock_keys_with_passphrase(session, accounts_passphrases_1, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_1);
}

TEST_F(PassphraseHandlingTest, manage_passphrase_multi)
{
    const char *new_passphrase_1 = "new_blarg_1";
    const char *new_passphrase_2 = "new_blarg_2";

    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_no_passphrase_email_1, ""));
    stringpair_list_add(accounts_passphrases_1, new_stringpair(tyrell_no_passphrase_email_2, ""));

    stringlist_t *errors = NULL;
    PEP_STATUS status =
      manage_passphrase(session, accounts_passphrases_1, new_passphrase_1, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    errors = NULL;
    status = unlock_keys_with_passphrase(session, accounts_passphrases_1, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 2);

    stringpair_list_t *accounts_passphrases_2 =
      new_stringpair_list(new_stringpair(tyrell_no_passphrase_email_1, new_passphrase_1));
    stringpair_list_add(accounts_passphrases_2,
                        new_stringpair(tyrell_no_passphrase_email_2, new_passphrase_1));

    free_stringlist(errors);
    errors = NULL;
    status = unlock_keys_with_passphrase(session, accounts_passphrases_2, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    errors = NULL;
    status = manage_passphrase(session, accounts_passphrases_2, new_passphrase_2, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    errors = NULL;
    status = unlock_keys_with_passphrase(session, accounts_passphrases_2, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 2);

    stringpair_list_t *accounts_passphrases_3 =
      new_stringpair_list(new_stringpair(tyrell_no_passphrase_email_1, new_passphrase_2));
    stringpair_list_add(accounts_passphrases_3,
                        new_stringpair(tyrell_no_passphrase_email_2, new_passphrase_2));

    free_stringlist(errors);
    errors = NULL;
    status = unlock_keys_with_passphrase(session, accounts_passphrases_3, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    errors = NULL;
    status = manage_passphrase(session, accounts_passphrases_3, "", &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    errors = NULL;
    status = unlock_keys_with_passphrase(session, accounts_passphrases_1, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_1);
    free_stringpair_list(accounts_passphrases_2);
    free_stringpair_list(accounts_passphrases_3);
}

TEST_F(PassphraseHandlingTest, public_keys_stay_passphrase_less)
{
    const char *new_passphrase_1 = "new_blarg_1";
    const char *new_passphrase_2 = "new_blarg_2";

    // Set a passphrase on an own identity.

    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_no_passphrase_email_1, ""));

    stringlist_t *errors = NULL;
    PEP_STATUS status =
      manage_passphrase(session, accounts_passphrases_1, new_passphrase_1, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    errors = NULL;

    // Set a passphrase on another own identity.
    // Note that we never need it again for _encrypting to_ that identity.

    stringpair_list_t *accounts_passphrases_2 =
      new_stringpair_list(new_stringpair(tyrell_no_passphrase_email_2, ""));

    status = manage_passphrase(session, accounts_passphrases_2, new_passphrase_2, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(stringlist_length(errors), 0);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_1);
    free_stringpair_list(accounts_passphrases_2);

    // Have to provide that for signing.
    config_passphrase(session, new_passphrase_1);

    message *msg = new_message(PEP_dir_outgoing);
    msg->from = identity_dup(tyrell_identity_1);
    msg->to = new_identity_list(tyrell_identity_2);
    msg->shortmsg = strdup("short message");
    msg->longmsg = strdup("long message");

    message *encrypted_msg = NULL;
    PEP_STATUS encrypt_status = encrypt_message(
      session, msg, NULL, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_default);
    ASSERT_EQ(encrypt_status, PEP_STATUS_OK);

    config_passphrase(session, NULL);

    message *decrypted_msg = NULL;
    stringlist_t *keylist = NULL;
    PEP_decrypt_flags_t decrypt_flags = 0;
    PEP_STATUS decrypt_status =
      decrypt_message_2(session, encrypted_msg, &decrypted_msg, &keylist, &decrypt_flags);
    ASSERT_EQ(decrypt_status, PEP_PASSPHRASE_REQUIRED);

    free_message(decrypted_msg);
    decrypted_msg = NULL;
    free_stringlist(keylist);
    keylist = NULL;
    decrypt_flags = 0;

    // Need either of the secret keys for decryption.
    config_passphrase(session, new_passphrase_1);

    decrypt_status =
      decrypt_message_2(session, encrypted_msg, &decrypted_msg, &keylist, &decrypt_flags);
    ASSERT_EQ(decrypt_status, PEP_STATUS_OK);

    free_message(decrypted_msg);
    free_stringlist(keylist);

    // Need either of the secret keys for decryption.
    config_passphrase(session, new_passphrase_2);

    decrypt_status =
      decrypt_message_2(session, encrypted_msg, &decrypted_msg, &keylist, &decrypt_flags);
    ASSERT_EQ(decrypt_status, PEP_STATUS_OK);

    free_message(msg);
    free_message(encrypted_msg);
    free_message(decrypted_msg);
    free_stringlist(keylist);
}

TEST_F(PassphraseHandlingTest, manage_passphrase_first_incorrect)
{
    const char *new_passphrase = "new_blarg_1";

    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, "not correct"));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_2));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_3, tyrell_passphrase_3));

    stringlist_t *errors = NULL;
    PEP_STATUS status = manage_passphrase(session, accounts_passphrases_1, new_passphrase, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_NOTNULL(errors->value);

    string wrong_email = string{ errors->value };
    string expected = string{ tyrell_passphrase_email_1 };
    ASSERT_EQ(expected, wrong_email);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_1);
}

TEST_F(PassphraseHandlingTest, manage_passphrase_middle_incorrect)
{
    const char *new_passphrase = "new_blarg_1";

    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_2, "not correct"));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_3, tyrell_passphrase_3));

    stringlist_t *errors = NULL;
    PEP_STATUS status = manage_passphrase(session, accounts_passphrases_1, new_passphrase, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_NOTNULL(errors->value);

    string wrong_email = string{ errors->value };
    string expected = string{ tyrell_passphrase_email_2 };
    ASSERT_EQ(expected, wrong_email);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_1);
}

TEST_F(PassphraseHandlingTest, manage_passphrase_last_incorrect)
{
    const char *new_passphrase = "new_blarg_1";

    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_2));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_3, "not correct"));

    stringlist_t *errors = NULL;
    PEP_STATUS status = manage_passphrase(session, accounts_passphrases_1, new_passphrase, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_NOTNULL(errors->value);

    string wrong_email = string{ errors->value };
    string expected = string{ tyrell_passphrase_email_3 };
    ASSERT_EQ(expected, wrong_email);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_1);
}

TEST_F(PassphraseHandlingTest, all_or_nothing_first_incorrect)
{
    const char *new_passphrase = "new_blarg_1";

    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1,  "not correct"));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_2));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_3, tyrell_passphrase_3));

    stringlist_t *errors = NULL;
    PEP_STATUS status = manage_passphrase(session, accounts_passphrases_1, new_passphrase, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_NOTNULL(errors->value);

    string wrong_email = string{ errors->value };
    string expected = string{ tyrell_passphrase_email_1 };
    ASSERT_EQ(expected, wrong_email);

    free_stringlist(errors);
    errors = NULL;

    // check that no passphrase has been changed

    stringpair_list_t *accounts_passphrases_unlock =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases_unlock,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_2));
    stringpair_list_add(accounts_passphrases_unlock,
                        new_stringpair(tyrell_passphrase_email_3, tyrell_passphrase_3));

    status = unlock_keys_with_passphrase(session, accounts_passphrases_unlock, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NULL(errors);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_1);
}

TEST_F(PassphraseHandlingTest, all_or_nothing_middle_incorrect)
{
    const char *new_passphrase = "new_blarg_1";

    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_2, "not correct"));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_3, tyrell_passphrase_3));

    stringlist_t *errors = NULL;
    PEP_STATUS status = manage_passphrase(session, accounts_passphrases_1, new_passphrase, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_NOTNULL(errors->value);

    string wrong_email = string{ errors->value };
    string expected = string{ tyrell_passphrase_email_2 };
    ASSERT_EQ(expected, wrong_email);

    free_stringlist(errors);
    errors = NULL;

    // check that no passphrase has been changed

    stringpair_list_t *accounts_passphrases_unlock =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases_unlock,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_2));
    stringpair_list_add(accounts_passphrases_unlock,
                        new_stringpair(tyrell_passphrase_email_3, tyrell_passphrase_3));

    status = unlock_keys_with_passphrase(session, accounts_passphrases_unlock, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NULL(errors);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_1);
}

TEST_F(PassphraseHandlingTest, all_or_nothing_last_incorrect)
{
    const char *new_passphrase = "new_blarg_1";

    stringpair_list_t *accounts_passphrases_1 =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_2));
    stringpair_list_add(accounts_passphrases_1,
                        new_stringpair(tyrell_passphrase_email_3, "not correct"));

    stringlist_t *errors = NULL;
    PEP_STATUS status = manage_passphrase(session, accounts_passphrases_1, new_passphrase, &errors);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_EQ(stringlist_length(errors), 1);
    ASSERT_NOTNULL(errors->value);

    string wrong_email = string{ errors->value };
    string expected = string{ tyrell_passphrase_email_3 };
    ASSERT_EQ(expected, wrong_email);

    free_stringlist(errors);
    errors = NULL;

    // check that no passphrase has been changed

    stringpair_list_t *accounts_passphrases_unlock =
      new_stringpair_list(new_stringpair(tyrell_passphrase_email_1, tyrell_passphrase_1));
    stringpair_list_add(accounts_passphrases_unlock,
                        new_stringpair(tyrell_passphrase_email_2, tyrell_passphrase_2));
    stringpair_list_add(accounts_passphrases_unlock,
                        new_stringpair(tyrell_passphrase_email_3, tyrell_passphrase_3));

    status = unlock_keys_with_passphrase(session, accounts_passphrases_unlock, &errors);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NULL(errors);

    free_stringlist(errors);
    free_stringpair_list(accounts_passphrases_1);
}
