// This file is under GNU General Public License 3.0
// see LICENSE.txt

#define UPDATE_DATA 1

#include <iostream>
#include <fstream>

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
class MistrustedWhenSignedWithUnknownKey : public ::testing::Test
{
  public:
    Engine *engine;
    PEP_SESSION session;

  protected:
    const string keyfile_priv_bob1 = "test_keys/priv/mwswuk_bob1.asc";
    const string keyfile_pub_bob1 = "test_keys/pub/mwswuk_bob1.asc";
    const string keyfile_priv_bob2 = "test_keys/priv/mwswuk_bob2.asc";
    const string keyfile_pub_bob2 = "test_keys/pub/mwswuk_bob2.asc";

    const string keyfile_priv_alice = "test_keys/priv/mwswuk_alice.asc";
    const string keyfile_pub_alice = "test_keys/pub/mwswuk_alice.asc";

    const string mailfile_hello_message = "test_mails/mwswuk_hello.eml";
    const string mailfile_encrypted_message_1 = "test_mails/mwswuk_encrypted_1.eml";
    const string mailfile_encrypted_message_2 = "test_mails/mwswuk_encrypted_2.eml";

    // Alice
    const char *address_alice = "alice@example.com";
    const char *name_alice = "Alice in wonderland";
    const string fpr_alice = "8C44BC1E06160A180121ADB52C21958990B3C080";

    // Bob
    const char *address_bob = "bob.builder@example.com";
    const char *name_bob = "Bob the builder";
    const string fpr_bob_1 = "D65E1EA3714FFAAE2410D3B454BD5263B050F3D1";
    const string fpr_bob_2 = "E12AE4ABAD52CFD360D7A71C4EDB7911C9C6610A";

    // Identities
    pEp_identity* alice = NULL;
    pEp_identity* bob = NULL;

    // You can remove any or all of the following functions if its body
    // is empty.
    MistrustedWhenSignedWithUnknownKey()
    {
        // You can do set-up work for each test here.
        test_suite_name =
          ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
        test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
        test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
    }

    ~MistrustedWhenSignedWithUnknownKey() override
    {
        // You can do clean-up work that doesn't throw exceptions here.
    }

    // If the constructor and destructor are not enough for setting up
    // and cleaning up each test, you can define the following methods:

    void SetUp() override;
    void TearDown() override;

    message *slurp_message_file_into_struct(const std::string& filename);

  private:
    const char *test_suite_name;
    const char *test_name;
    string test_path;
};

void MistrustedWhenSignedWithUnknownKey::SetUp()
{
    // Code here will be called immediately after the constructor (right
    // before each test).

    // Get a new test Engine.
    engine = new Engine(test_path);
    ASSERT_NOTNULL(engine);

    // Leave this empty if there are no files to copy to the home directory path
    auto init_files = std::vector<std::pair<std::string, std::string>>();

    // Ok, let's initialize test directories etc.
    engine->prep(NULL, NULL, NULL, init_files);

    // Ok, try to start this bugger.
    engine->start();
    ASSERT_NOTNULL(engine->session);
    session = engine->session;

    // Engine is up. Keep on truckin'

    PEP_STATUS status;

    status = set_up_ident_from_scratch(
        session,
        keyfile_pub_alice.c_str(),
        address_alice,
        fpr_alice.c_str(),
        address_alice,
        name_alice,
        &alice,
        false
    );

    ASSERT_EQ(status, PEP_STATUS_OK);
}

void MistrustedWhenSignedWithUnknownKey::TearDown()
{
    // Code here will be called immediately after each test (right
    // before the destructor).
    engine->shut_down();
    delete engine;
    engine = NULL;
    session = NULL;
}

message *MistrustedWhenSignedWithUnknownKey::slurp_message_file_into_struct(const std::string& filename)
{
    message *msg = slurp_message_file_into_struct(filename.c_str());

    // An app is required to call `update_identity`/`myself` on _all_ identities
    // in a `message` struct before providing it to most core functions.
    // Try to uphold this in the test environment.
    auto to_identity = msg->to->ident;
    if (to_identity) {
        std::string address{to_identity->address};
        if (address == address_bob) {
            to_identity->me = true;
        }
    }

    return msg;
}

} // namespace

TEST_F(MistrustedWhenSignedWithUnknownKey, create_hello_mail)
{
}