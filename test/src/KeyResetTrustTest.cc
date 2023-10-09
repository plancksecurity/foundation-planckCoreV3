// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <iostream>
#include <stdlib.h>
#include <string.h>

#include <gtest/gtest.h>

#include "Engine.h"
#include "TestUtilities.h"

#include "key_reset.h"
#include "keymanagement.h"
#include "pEpEngine_internal.h"
#include "pEp_internal.h"
#include "platform.h"

namespace {

// The fixture
class KeyResetTrustTest : public ::testing::Test
{
  public:
    Engine *engine;
    PEP_SESSION session;

  protected:
    // You can remove any or all of the following functions if its body
    // is empty.
    KeyResetTrustTest()
    {
        // You can do set-up work for each test here.
        test_suite_name =
          ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
        test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
        test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
    }

    ~KeyResetTrustTest() override
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
    }

    void TearDown() override
    {
        // Code here will be called immediately after each test (right
        // before the destructor).
        engine->shut_down();
        delete engine;
        engine = NULL;
        session = NULL;
    }

  private:
    const char *test_suite_name;
    const char *test_name;
    string test_path;
    // Objects declared here can be used by all tests in the LogSignTest suite.
};

} // namespace

TEST_F(KeyResetTrustTest, basic_trust_reset_cycle)
{
    // create an own identity
    pEp_identity *deckard_own = new_identity("deckard@example.com", NULL, PEP_OWN_USERID, "Rick Deckard");
    ASSERT_NOTNULL(deckard_own);
    PEP_STATUS status = myself(session, deckard_own);
    ASSERT_TRUE(deckard_own->me);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(deckard_own->fpr);
    ASSERT_EQ(deckard_own->major_ver, PEP_ENGINE_VERSION_MAJOR);
    ASSERT_EQ(deckard_own->minor_ver, PEP_ENGINE_VERSION_MINOR);

    // import partner key
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/tyrell.asc"));

    // partner data
    const char *fpr_partner = "7A60C123B027A26648B0EFBA5847167BE968FBF7";
    const char *userid_partner = "tyrell_id";
    const char *address_partner = "tyrell@example.com";
    const char *name_partner = "Eldon Tyrell";

    // create partner identity
    pEp_identity *tyrell_partner = new_identity(address_partner, fpr_partner, userid_partner, name_partner);
    ASSERT_NOTNULL(tyrell_partner);
    ASSERT_STREQ(tyrell_partner->fpr, fpr_partner);
    tyrell_partner->me = false;
    status = set_identity(session, tyrell_partner);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(tyrell_partner->fpr, fpr_partner);
    status = set_as_pEp_user(session, tyrell_partner);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = update_identity(session, tyrell_partner);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(tyrell_partner->fpr, fpr_partner);

    status = trust_personal_key(session, tyrell_partner);
    ASSERT_EQ(status, PEP_STATUS_OK);

    free_identity(deckard_own);
    free_identity(tyrell_partner);
}