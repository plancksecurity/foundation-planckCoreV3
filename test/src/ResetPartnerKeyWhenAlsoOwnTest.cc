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
    const char *address = "tyrell@example.com";
    const char *name = "Eldon Tyrell";
    const char *message_subject = "short message";
    const char *message_text = "long message";

    // create the own identity
    pEp_identity *tyrell_own = new_identity(address, NULL, PEP_OWN_USERID, name);
    ASSERT_NOTNULL(tyrell_own);
    PEP_STATUS status = myself(session, tyrell_own);
    ASSERT_NOTNULL(tyrell_own->fpr);
    ASSERT_EQ(tyrell_own->major_ver, PEP_ENGINE_VERSION_MAJOR);
    ASSERT_EQ(tyrell_own->minor_ver, PEP_ENGINE_VERSION_MINOR);

    // encrypt a message
    message *msg = new_message(PEP_dir_outgoing);
    msg->from = identity_dup(tyrell_own);
    identity_list *tos = new_identity_list(identity_dup(tyrell_own));
    msg->to = tos;
    msg->shortmsg = strdup(message_subject);
    msg->longmsg = strdup(message_text);
    message *msg_encrypted = NULL;
    status = encrypt_message(session, msg, NULL, &msg_encrypted, PEP_enc_PEP, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(msg_encrypted);
    ASSERT_STRNE(msg_encrypted->shortmsg, msg->shortmsg);
    ASSERT_STRNE(msg_encrypted->longmsg, msg->longmsg);

    // create the partner identity
    pEp_identity *tyrell_partner = identity_dup(tyrell_own);
    ASSERT_NOTNULL(tyrell_partner);

    // configure the partner
    tyrell_partner->me = false;
    free(tyrell_partner->user_id);
    tyrell_partner->user_id = strdup("tofu_tyrell");
    status = set_as_pEp_user(session, tyrell_partner);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_protocol_version(
      session, tyrell_partner, PEP_ENGINE_VERSION_MAJOR, PEP_ENGINE_VERSION_MINOR);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // Trick the core into resetting a partner key, that is actually our own.
    // Without counter-measures, this would remove our own private key.
    status = key_reset_identity(session, tyrell_partner, tyrell_partner->fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // Prove we can still decrypt the message, so we still have our original private key.
    // Nothing got deleted from the keyring.
    message *msg_decrypted = NULL;
    PEP_decrypt_flags_t flags_decrypted;
    stringlist_t *keylist = NULL;
    status = decrypt_message_2(session, msg_encrypted, &msg_decrypted, &keylist, &flags_decrypted);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(msg_decrypted->shortmsg, msg->shortmsg);
    ASSERT_STREQ(msg_decrypted->longmsg, msg->longmsg);

    free_message(msg);
    free_message(msg_encrypted);
    free_message(msg_decrypted);

    free_identity(tyrell_own);
    free_identity(tyrell_partner);
}
