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

  private:
    const char *test_suite_name;
    const char *test_name;
    string test_path;
    // Objects declared here can be used by all tests in the ExportKeyTest suite.
};

} // namespace

TEST_F(ExportKeyWithPassphraseTest, check_export_passphrase_less_key_with_passphrase)
{
    const char *email = "someone@example.com";
    const char *username = "someone";
    pEp_identity *own = new_identity(email, nullptr, PEP_OWN_USERID, username);

    PEP_STATUS status = myself(session, own);
    ASSERT_EQ(PEP_STATUS_OK, status);

    string fpr1{own->fpr};

    const char *passphrase = "pass";

    status = configure_account_passphrases(session, {{email, passphrase}});
    ASSERT_EQ(PEP_STATUS_OK, status);

    char *key_data = nullptr;
    size_t key_size = 0;

    // Implementation should detect that the key is not passphrase-protected,
    // and put a passphrase on the result.
    status = export_secret_key(session, own->fpr, &key_data, &key_size);
    ASSERT_EQ(PEP_STATUS_OK, status);

    status = key_reset_all_own_keys(session);
    ASSERT_EQ(PEP_STATUS_OK, status);
    free(own->fpr);
    own->fpr = nullptr;
    status = myself(session, own);
    ASSERT_EQ(PEP_STATUS_OK, status);

    string fpr2{own->fpr};
    ASSERT_NE(fpr1, fpr2);

    identity_list *identities = nullptr;
    status = import_key(session, key_data, key_size, &identities);
    ASSERT_NE(PEP_STATUS_OK, status);
    ASSERT_NE(PEP_KEY_IMPORTED, status);

    free_identity(own);
    free(key_data);
}