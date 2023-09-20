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
#include "platform.h"
#include "pEpEngine_internal.h"

namespace {

// The fixture
class ResetPartnerKeyWhenAlsoOwnTest : public ::testing::Test
{
  public:
    Engine *engine;
    PEP_SESSION session;

  protected:
    // You can remove any or all of the following functions if its body
    // is empty.
    ResetPartnerKeyWhenAlsoOwnTest()
    {
        // You can do set-up work for each test here.
        test_suite_name =
          ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
        test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
        test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
    }

    ~ResetPartnerKeyWhenAlsoOwnTest() override
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

TEST_F(ResetPartnerKeyWhenAlsoOwnTest, do_not_remove)
{
  slurp_and_import_key(session, "test_keys/tyrell.asc");

  const char *fpr = "7A60C123B027A26648B0EFBA5847167BE968FBF7";
  const char *address = "tyrell@example.com";
  const char *name = "Eldon Tyrell";

  // create the own identity
  pEp_identity *tyrell_own = new_identity(address, fpr, PEP_OWN_USERID, name);
  ASSERT_NOTNULL(tyrell_own);

  // configure the own identity
  tyrell_own->me = true;
  set_own_key(session, tyrell_own, fpr);
  ASSERT_NOTNULL(tyrell_own->fpr);
  PEP_STATUS status = set_as_pEp_user(session, tyrell_own);
  ASSERT_EQ(status, PEP_STATUS_OK);
  status = set_protocol_version(session, tyrell_own, PEP_ENGINE_VERSION_MAJOR, PEP_ENGINE_VERSION_MINOR);
  ASSERT_EQ(status, PEP_STATUS_OK);

  // nil some parts
  free(tyrell_own->fpr);
  tyrell_own->fpr = NULL;
  tyrell_own->major_ver = 0;
  tyrell_own->minor_ver = 0;

  // check myself
  status = myself(session, tyrell_own);
  ASSERT_EQ(status, PEP_STATUS_OK);
  ASSERT_NOTNULL(tyrell_own->fpr);
  ASSERT_EQ(tyrell_own->major_ver, PEP_ENGINE_VERSION_MAJOR);
  ASSERT_EQ(tyrell_own->minor_ver, PEP_ENGINE_VERSION_MINOR);

  // create the partner identity
  pEp_identity *tyrell_partner = identity_dup(tyrell_own);
  ASSERT_NOTNULL(tyrell_partner);

  // configure the partner
  tyrell_partner->me = false;
  free(tyrell_partner->fpr);
  tyrell_partner->fpr = NULL;
  free(tyrell_partner->user_id);
  tyrell_partner->user_id = "tofu_tyrell";
  status = set_as_pEp_user(session, tyrell_partner);
  ASSERT_EQ(status, PEP_STATUS_OK);
  status = set_protocol_version(session, tyrell_partner, PEP_ENGINE_VERSION_MAJOR, PEP_ENGINE_VERSION_MINOR);
  ASSERT_EQ(status, PEP_STATUS_OK);
  status = set_comm_partner_key(session, tyrell_partner, fpr);
  ASSERT_EQ(status, PEP_STATUS_OK);

  // check the partner identity
  pEp_identity *tyrell_partner_check = identity_dup(tyrell_partner);
  free(tyrell_partner_check->fpr);
  tyrell_partner_check->fpr = NULL;
  tyrell_partner_check->minor_ver = 0;
  tyrell_partner_check->major_ver = 0;
  status = update_identity(session, tyrell_partner_check);
  ASSERT_EQ(status, PEP_STATUS_OK);
  ASSERT_STREQ(tyrell_partner->fpr, tyrell_partner_check->fpr);
  ASSERT_EQ(tyrell_partner->major_ver, tyrell_partner_check->major_ver);
  ASSERT_EQ(tyrell_partner->minor_ver, tyrell_partner_check->minor_ver);
  ASSERT_EQ(tyrell_partner_check->major_ver, PEP_ENGINE_VERSION_MAJOR);
  ASSERT_EQ(tyrell_partner_check->minor_ver, PEP_ENGINE_VERSION_MINOR);

  status = key_reset_identity(session, tyrell_partner, fpr);
  ASSERT_EQ(status, PEP_STATUS_OK);

  pEp_identity *tyrell_own2 = new_identity(address, NULL, PEP_OWN_USERID, name);
  ASSERT_NOTNULL(tyrell_own2);
  status = myself(session, tyrell_own2);
  ASSERT_EQ(status, PEP_STATUS_OK);
  ASSERT_NOTNULL(tyrell_own2->fpr);
  ASSERT_EQ(tyrell_own2->major_ver, PEP_ENGINE_VERSION_MAJOR);
  ASSERT_EQ(tyrell_own2->minor_ver, PEP_ENGINE_VERSION_MINOR);

  // While the private key should not have been deleted, we still
  // changed ours.
  ASSERT_STRNE(tyrell_own2->fpr, fpr);
}