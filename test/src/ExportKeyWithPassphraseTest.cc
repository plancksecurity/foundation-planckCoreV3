// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <cstring>
#include <stdlib.h>
#include <string>

#include "TestConstants.h"
#include "TestUtilities.h"

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "Engine.h"

#include <gtest/gtest.h>

using namespace std;

namespace {

// The fixture for ExportKeyWithPassphraseTest
class ExportKeyWithPassphraseTest : public ::testing::Test
{
  public:
    Engine *engine;
    PEP_SESSION session;

  protected:
    // You can remove any or all of the following functions if its body
    // is empty.
    ExportKeyWithPassphraseTest()
    {
        // You can do set-up work for each test here.
        test_suite_name =
          ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
        test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
        test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
    }

    ~ExportKeyWithPassphraseTest() override
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

        // Try to speed up key generation.
        PEP_STATUS status = config_cipher_suite(session, PEP_CIPHER_SUITE_RSA2K);
        ASSERT_EQ(status, PEP_STATUS_OK);

        // Engine is up. Keep on truckin'
    }

    void TearDown() override
    {
        // Code here will be called immediately after each test (right
        // before the destructor).

        // While it would be nice to have this in the destructor, it can throw exceptions, so it's
        // here.
        engine->shut_down();
        delete engine;
        engine = NULL;
        session = NULL;
    }

    bool has_passphrase(string fingerprint)
    {
        PEP_STATUS status = probe_encrypt(session, fingerprint.c_str());

        if (status == PEP_PASSPHRASE_REQUIRED) {
            return true;
        } else {
            return false;
        }
    }

    void reset_core()
    {
        TearDown();
        SetUp();
    }

  private:
    const char *test_suite_name;
    const char *test_name;
    string test_path;
    // Objects declared here can be used by all tests in the ExportKeyTest suite.
};

} // namespace

TEST_F(ExportKeyWithPassphraseTest, export_key_with_passphrase_fail)
{
    // Own identity with passphrase
    const char *email = "someone@example.com";
    const char *username = "someone";
    pEp_identity *own = new_identity(email, nullptr, PEP_OWN_USERID, username);

    const char *passphrase = "pass";
    PEP_STATUS status = configure_account_passphrases(session, { { email, passphrase } });
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = myself(session, own);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // remove knowledge about a passphrase
    status = configure_account_passphrases(session, { { email, "" } });
    ASSERT_EQ(status, PEP_STATUS_OK);

    char *key_data = nullptr;
    size_t key_size = 0;

    // Export should fail
    status = export_secret_key(session, own->fpr, &key_data, &key_size);
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
    ASSERT_NULL(key_data);
    ASSERT_EQ(key_size, 0);
}

TEST_F(ExportKeyWithPassphraseTest, export_passphrase_less_key_with_passphrase)
{
    const char *email = "someone@example.com";
    const char *username = "someone";
    pEp_identity *own = new_identity(email, nullptr, PEP_OWN_USERID, username);

    PEP_STATUS status = myself(session, own);
    ASSERT_EQ(status, PEP_STATUS_OK);

    string fpr{ own->fpr };

    ASSERT_FALSE(has_passphrase(fpr));

    const char *passphrase = "pass";
    status = configure_account_passphrases(session, { { email, passphrase } });
    ASSERT_EQ(status, PEP_STATUS_OK);

    char *key_data = nullptr;
    size_t key_size = 0;

    // Implementation should detect that the key is not passphrase-protected,
    // and put a passphrase on the result.
    status = export_secret_key(session, own->fpr, &key_data, &key_size);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(key_data);
    ASSERT_GT(key_size, 0);

    reset_core();

    identity_list *identities = nullptr;
    identity_list *private_identities = nullptr;
    stringlist_t *imported_keys = nullptr;
    uint64_t changed_keys = 0;
    status = import_key_with_fpr_return(
      session, key_data, key_size, &identities, &private_identities, &imported_keys, &changed_keys);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);

    ASSERT_TRUE(has_passphrase(fpr));

    free_identity(own);
    free(key_data);
}

TEST_F(ExportKeyWithPassphraseTest, export_key_with_passphrase)
{
    const char *email = "someone@example.com";
    const char *username = "someone";
    pEp_identity *own = new_identity(email, nullptr, PEP_OWN_USERID, username);

    const char *passphrase = "pass";
    PEP_STATUS status = configure_account_passphrases(session, { { email, passphrase } });
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = myself(session, own);
    ASSERT_EQ(status, PEP_STATUS_OK);

    string fpr{ own->fpr };

    ASSERT_TRUE(has_passphrase(fpr));

    char *key_data = nullptr;
    size_t key_size = 0;

    status = export_secret_key(session, own->fpr, &key_data, &key_size);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(key_data);
    ASSERT_GT(key_size, 0);

    reset_core();

    identity_list *identities = nullptr;
    identity_list *private_identities = nullptr;
    stringlist_t *imported_keys = nullptr;
    uint64_t changed_keys = 0;
    status = import_key_with_fpr_return(
      session, key_data, key_size, &identities, &private_identities, &imported_keys, &changed_keys);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);

    ASSERT_TRUE(has_passphrase(fpr));

    free_identity(own);
    free(key_data);
}

TEST_F(ExportKeyWithPassphraseTest, export_old_key_with_passphrase)
{
    const char *email = "someone@example.com";
    const char *username = "someone";
    pEp_identity *own1 = new_identity(email, nullptr, PEP_OWN_USERID, username);

    const char *passphrase = "pass";
    PEP_STATUS status = configure_account_passphrases(session, { { email, passphrase } });
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = myself(session, own1);
    ASSERT_EQ(status, PEP_STATUS_OK);

    string fpr1{ own1->fpr };

    ASSERT_TRUE(has_passphrase(fpr1));

    status = config_passphrase_for_new_keys(session, true, passphrase);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = config_passphrase(session, passphrase);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status, PEP_STATUS_OK);

    pEp_identity *own2 = new_identity(email, nullptr, PEP_OWN_USERID, username);
    status = myself(session, own2);
    ASSERT_EQ(status, PEP_STATUS_OK);

    string fpr2{ own2->fpr };
    ASSERT_NE(fpr1, fpr2);

    bool fpr1_found = false;
    bool fpr2_found = false;
    identity_list *all_own_identities = NULL;
    status = own_identities_retrieve(session, &all_own_identities);
    ASSERT_EQ(status, PEP_STATUS_OK);
    for (identity_list *current = all_own_identities; current && current->ident;
         current = current->next) {
        if (current->ident->fpr && current->ident->address) {
            if (!strcmp(current->ident->fpr, fpr1.c_str())) {
                fpr1_found = true;
            } else if (!strcmp(current->ident->fpr, fpr2.c_str())) {
                fpr2_found = true;
            }
        }
    }

    char *key_data = nullptr;
    size_t key_size = 0;

    status = export_secret_key(session, fpr1.c_str(), &key_data, &key_size);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(key_data);
    ASSERT_GT(key_size, 0);

    reset_core();

    identity_list *identities = nullptr;
    identity_list *private_identities = nullptr;
    stringlist_t *imported_keys = nullptr;
    uint64_t changed_keys = 0;
    status = import_key_with_fpr_return(
      session, key_data, key_size, &identities, &private_identities, &imported_keys, &changed_keys);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);

    ASSERT_TRUE(has_passphrase(fpr1));

    free_identity(own1);
    free_identity(own2);
    free(key_data);
}
