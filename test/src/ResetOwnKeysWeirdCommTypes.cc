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
class ResetOwnKeysWeirdCommTypes : public ::testing::Test
{
  public:
    Engine *engine;
    PEP_SESSION session;

  protected:
    // You can remove any or all of the following functions if its body
    // is empty.
    ResetOwnKeysWeirdCommTypes()
    {
        // You can do set-up work for each test here.
        test_suite_name =
          ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
        test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
        test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
    }

    ~ResetOwnKeysWeirdCommTypes() override
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

TEST_F(ResetOwnKeysWeirdCommTypes, basic)
{
    const char *address = "tyrell@example.com";
    const char *name = "Eldon Tyrell";

    // create the own identity
    pEp_identity *tyrell_own = new_identity(address, NULL, PEP_OWN_USERID, name);
    ASSERT_NOTNULL(tyrell_own);
    PEP_STATUS status = myself(session, tyrell_own);
    ASSERT_NOTNULL(tyrell_own->fpr);
    ASSERT_EQ(tyrell_own->major_ver, PEP_ENGINE_VERSION_MAJOR);
    ASSERT_EQ(tyrell_own->minor_ver, PEP_ENGINE_VERSION_MINOR);

    free_identity(tyrell_own);
}