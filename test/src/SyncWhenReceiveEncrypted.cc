// This file is under GNU General Public License 3.0
// see LICENSE.txt

#define UPDATE_DATA 0

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

PEP_STATUS SWRE_message_send_callback(message* msg);
PEP_STATUS SWRE_ensure_passphrase_callback(PEP_SESSION session, const char* key);
PEP_STATUS SWRE_notify_handshake_callback(pEp_identity* me, pEp_identity* partner, sync_handshake_signal signal);

static void* SWRE_fake_this;

namespace {

// The fixture
class SyncWhenReceiveEncrypted : public ::testing::Test
{
  public:
    Engine *engine;
    PEP_SESSION session;

    vector<message*> m_queue;
    vector<string> pass_list;

    pEp_identity* signal_check_ident_me = NULL;
    pEp_identity* signal_check_ident_partner = NULL;
    sync_handshake_signal signal = SYNC_NOTIFY_UNDEFINED;

  protected:
    string paramfile = "test_files/swre_params.txt";

    string keyfile_priv_bob = "test_keys/priv/swre_bob.asc";
    string keyfile_priv_alice = "test_keys/priv/swre_alice.asc";

    string keyfile_pub_bob = "test_keys/pub/swre_bob.asc";
    string keyfile_pub_alice = "test_keys/pub/swre_alice.asc";

    string mailfile_hello_message = "test_mails/swre_hello.eml";
    string mailfile_reset_message = "test_mails/swre_reset.eml";

    // Alice
    const char *address_alice = "alice@example.com";
    const char *name_alice = "Alice in wonderland";
    string fpr_alice = "";

    // Bob
    const char *address_bob = "bob.builder@example.com";
    const char *name_bob = "Bob the builder";
    string fpr_bob = "";

    // Bob after reset
    string fpr_bob_reset = "";

    // Identities
    pEp_identity* alice = NULL;
    pEp_identity* bob = NULL;

    // You can remove any or all of the following functions if its body
    // is empty.
    SyncWhenReceiveEncrypted()
    {
        // You can do set-up work for each test here.
        test_suite_name =
          ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
        test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
        test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
    }

    ~SyncWhenReceiveEncrypted() override
    {
        // You can do clean-up work that doesn't throw exceptions here.
    }

    // If the constructor and destructor are not enough for setting up
    // and cleaning up each test, you can define the following methods:

    void SetUp() override;
    void TearDown() override;

#if UPDATE_DATA
    // Write params
    void UpdateParams();
#endif

    // Identity loaders
    PEP_STATUS PrivAlice();
    PEP_STATUS PubAlice();
    PEP_STATUS PrivBob();
    PEP_STATUS PubBob();

    message *slurp_hello_message_file_into_struct();

  private:
    const char *test_suite_name;
    const char *test_name;
    string test_path;
    // Objects declared here can be used by all tests in the LogSignTest suite.
};

void SyncWhenReceiveEncrypted::SetUp()
{
    // Code here will be called immediately after the constructor (right
    // before each test).

    SWRE_fake_this = (void*)this;
    // Leave this empty if there are no files to copy to the home directory path
    std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

    // Get a new test Engine.
    engine = new Engine(test_path);
    ASSERT_NOTNULL(engine);

    // Ok, let's initialize test directories etc.
    engine->prep(&SWRE_message_send_callback, NULL, &SWRE_ensure_passphrase_callback, init_files);

    // Ok, try to start this bugger.
    engine->start();
    ASSERT_NOTNULL(engine->session);
    session = engine->session;

    // Engine is up. Keep on truckin'
    m_queue.clear();
    pass_list.clear();

    // Read params
    ifstream infile(paramfile);
    if(infile.good()) {
        infile >> fpr_alice;
        infile >> fpr_bob;
        infile >> fpr_bob_reset;
    }
    infile.close();
}

void SyncWhenReceiveEncrypted::TearDown()
{
    // Code here will be called immediately after each test (right
    // before the destructor).
    engine->shut_down();
    delete engine;
    engine = NULL;
    session = NULL;
}

#if UPDATE_DATA
void SyncWhenReceiveEncrypted::UpdateParams()
{
    // Read params
    ofstream outfile;
    outfile.open(paramfile);
    outfile << fpr_alice << endl;
    outfile << fpr_bob << endl;
    outfile << fpr_bob_reset << endl;
    outfile.close();
}
#endif

PEP_STATUS SyncWhenReceiveEncrypted::PrivAlice()
{
    PEP_STATUS status;
    status = read_file_and_import_key(
        session,
        keyfile_pub_alice.c_str()
    );
    if(status!=PEP_KEY_IMPORTED) {
        return status;
    }
    status = set_up_ident_from_scratch(
        session,
        keyfile_priv_alice.c_str(),
        address_alice,
        fpr_alice.c_str(),
        PEP_OWN_USERID,
        name_alice,
        &alice,
        true
    );
    return status;
}

PEP_STATUS SyncWhenReceiveEncrypted::PubAlice()
{
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
    return status;
}

PEP_STATUS SyncWhenReceiveEncrypted::PrivBob()
{
    PEP_STATUS status;
    status = read_file_and_import_key(
        session,
        keyfile_pub_bob.c_str()
    );
    if(status!=PEP_KEY_IMPORTED) {
        return status;
    }
    status = set_up_ident_from_scratch(
        session,
        keyfile_priv_bob.c_str(),
        address_bob,
        fpr_bob.c_str(),
        PEP_OWN_USERID,
        name_bob,
        &bob,
        true
    );
    return status;
}

PEP_STATUS SyncWhenReceiveEncrypted::PubBob()
{
    PEP_STATUS status;
    status = set_up_ident_from_scratch(
        session,
        keyfile_pub_bob.c_str(),
        address_bob,
        fpr_bob.c_str(),
        address_bob,
        name_bob,
        &bob,
        false
    );
    return status;
}

message *SyncWhenReceiveEncrypted::slurp_hello_message_file_into_struct()
{
    message *msg = slurp_message_file_into_struct(mailfile_hello_message.c_str());

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

PEP_STATUS SWRE_message_send_callback(message* msg) {
    ((SyncWhenReceiveEncrypted*)SWRE_fake_this)->m_queue.push_back(msg);
    return PEP_STATUS_OK;
}

PEP_STATUS SWRE_ensure_passphrase_callback(PEP_SESSION session, const char* fpr) {
    return config_valid_passphrase(session, fpr, ((SyncWhenReceiveEncrypted*)SWRE_fake_this)->pass_list);
}

PEP_STATUS SWRE_notify_handshake_callback(pEp_identity* me, pEp_identity* partner, sync_handshake_signal signal) {
    if (me && partner && signal == SYNC_NOTIFY_GROUP_INVITATION) {
        ((SyncWhenReceiveEncrypted*)SWRE_fake_this)->signal_check_ident_me = me;
        ((SyncWhenReceiveEncrypted*)SWRE_fake_this)->signal_check_ident_partner = partner;
        ((SyncWhenReceiveEncrypted*)SWRE_fake_this)->signal = signal;
    }
    return PEP_STATUS_OK;
}

TEST_F(SyncWhenReceiveEncrypted, update_alice_ident)
{
    PEP_STATUS status = PEP_STATUS_OK;

    // create test idents
    alice = new_identity(address_alice, NULL, PEP_OWN_USERID, name_alice);
    ASSERT_NOTNULL(alice);
    status = myself(session, alice);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(alice->major_ver, PEP_ENGINE_VERSION_MAJOR);
    ASSERT_EQ(alice->minor_ver, PEP_ENGINE_VERSION_MINOR);

    fpr_alice = alice->fpr;

    ofstream outfile;
    char* keyval = NULL;
    size_t keysize = 0;

#if UPDATE_DATA
    UpdateParams();

    outfile.open(keyfile_pub_alice);
    status = export_key(session, strdup(alice->fpr), &keyval, &keysize);
    EXPECT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(keyval);
    ASSERT_NE(keysize, 0);
    outfile << keyval;
    free(keyval);
    outfile.close();

    outfile.open(keyfile_priv_alice);
    keyval = NULL;
    status = export_secret_key(session,  strdup(alice->fpr), &keyval, &keysize);
    ASSERT_NOTNULL(keyval);
    ASSERT_NE(keysize, 0);
    outfile << endl << keyval;
    outfile.close();
#endif

    free(keyval);
    free_identity(alice);
}

TEST_F(SyncWhenReceiveEncrypted, update_bob_ident)
{
    PEP_STATUS status = PEP_STATUS_OK;

    // create test idents
    bob = new_identity(address_bob, NULL, PEP_OWN_USERID, name_bob);
    ASSERT_NOTNULL(bob);
    status = myself(session, bob);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(bob->major_ver, PEP_ENGINE_VERSION_MAJOR);
    ASSERT_EQ(bob->minor_ver, PEP_ENGINE_VERSION_MINOR);

    ofstream outfile;
    char* keyval = NULL;
    size_t keysize = 0;

    fpr_bob = bob->fpr;

#if UPDATE_DATA
    UpdateParams();

    outfile.open(keyfile_pub_bob);
    status = export_key(session, strdup(bob->fpr), &keyval, &keysize);
    EXPECT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(keyval);
    ASSERT_NE(keysize, 0);
    outfile << keyval;
    outfile.close();

    outfile.open(keyfile_priv_bob);
    free(keyval);
    keyval = NULL;
    status = export_secret_key(session,  strdup(bob->fpr), &keyval, &keysize);
    ASSERT_NOTNULL(keyval);
    ASSERT_NE(keysize, 0);
    outfile << endl << keyval;
    outfile.close();
#endif

    free(keyval);
    free_identity(bob);
}


TEST_F(SyncWhenReceiveEncrypted, create_test_mail)
{
    PEP_STATUS status;

    // create bob as recipient
    status = PubBob();
    ASSERT_EQ(status, PEP_STATUS_OK);

    // create alice as sender
    status = PrivAlice();
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = set_own_key(session, alice, fpr_alice.c_str());
    ASSERT_OK;

    status = myself(session, alice);
    ASSERT_OK;
    ASSERT_NOTNULL(alice->fpr);
    ASSERT_STRCASEEQ(alice->fpr, fpr_alice.c_str());
    ASSERT_TRUE(alice->me);

    // "send" some messages to update the social graph entries
    identity_list* send_idents = new_identity_list(bob);
    status = set_as_pEp_user(session, send_idents->ident);
    ASSERT_OK;

    message* outgoing_msg = new_message(PEP_dir_outgoing);
    ASSERT_NOTNULL(outgoing_msg);
    outgoing_msg->from = alice;
    outgoing_msg->to = send_idents;
    outgoing_msg->shortmsg = strdup("I'm late!\n");
    outgoing_msg->longmsg = strdup("I'm late! For a very important date! No time to say \"hello\", \"goodbye\"!");
    message* enc_outgoing_msg = nullptr;
    status = encrypt_message(session, outgoing_msg, NULL, &enc_outgoing_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_outgoing_msg);

#if UPDATE_DATA
    char* outstring = NULL;
    mime_encode_message(enc_outgoing_msg, false, &outstring, false);
    dump_out(mailfile_hello_message.c_str(), outstring);
    free(outstring);
#endif
    free_message(enc_outgoing_msg);
    free_identity(alice);
    free_identity(bob);
}

// just a reference to make sure that decryption still works AT ALL
TEST_F(SyncWhenReceiveEncrypted, decrypt_test_mail)
{
    PEP_STATUS status;

    // create alice as sender
    status = PubAlice();
    ASSERT_EQ(status, PEP_STATUS_OK);

    // create bob as recipient
    status = PrivBob();
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = myself(session, bob);
    ASSERT_OK;
    ASSERT_NOTNULL(bob->fpr);
    ASSERT_STRCASEEQ(bob->fpr, fpr_bob.c_str());
    ASSERT_TRUE(bob->me);

    message* msg = slurp_hello_message_file_into_struct();
    message* dmsg = NULL;
    stringlist_t* keylist_used = nullptr;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message_2(session, msg, &dmsg, &keylist_used, &flags);
    ASSERT_OK;

    free_identity(bob);
    free_stringlist(keylist_used);
}

TEST_F(SyncWhenReceiveEncrypted, decrypt_test_mail_after_reset)
{
    PEP_STATUS status;

    // create alice as sender
    status = PubAlice();
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = PrivBob();
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = myself(session, bob);
    ASSERT_OK;
    ASSERT_NOTNULL(bob->fpr);
    ASSERT_STRCASEEQ(bob->fpr, fpr_bob.c_str());
    ASSERT_TRUE(bob->me);

    status = key_reset_identity(session, bob, bob->fpr);
    ASSERT_OK;
    status = myself(session, bob);
    fpr_bob_reset = bob->fpr;
#if UPDATE_DATA
    UpdateParams();
#endif

    message* msg = slurp_hello_message_file_into_struct();
    message* dmsg = NULL;
    stringlist_t* keylist_used = nullptr;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message_2(session, msg, &dmsg, &keylist_used, &flags);
    ASSERT_OK;

	ASSERT_EQ(m_queue.size(), 1);

#if UPDATE_DATA
    ofstream outfile;
    for (vector<message*>::iterator it = m_queue.begin(); it != m_queue.end(); it++) {
        message* curr_sent_msg = *it;
        outfile.open(mailfile_reset_message);
        char* msg_txt = NULL;
        mime_encode_message(curr_sent_msg, false, &msg_txt, false);
        outfile << msg_txt;
        outfile.close();
    }
#endif

    free_identity(bob);
    free_stringlist(keylist_used);
}

TEST_F(SyncWhenReceiveEncrypted, check_identity_after_reset)
{
    PEP_STATUS status;
    // create alice as recipient
    status = PrivAlice();
    ASSERT_EQ(status, PEP_STATUS_OK);
    // create bob as sender
    status = PubBob();
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_STREQ(bob->fpr, fpr_bob.c_str());
    message* msg = slurp_message_file_into_struct(mailfile_reset_message.c_str());
    message* dmsg = NULL;
    stringlist_t* keylist_used = nullptr;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message_2(session, msg, &dmsg, &keylist_used, &flags);
    ASSERT_OK;
    status = update_identity(session, bob);
    ASSERT_STREQ(bob->fpr, fpr_bob_reset.c_str());
}
