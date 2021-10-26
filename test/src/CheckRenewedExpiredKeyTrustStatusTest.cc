// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "pEpEngine_internal.h"

#include "TestUtilities.h"


#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for CheckRenewedExpiredKeyTrustStatusTest
    class CheckRenewedExpiredKeyTrustStatusTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            CheckRenewedExpiredKeyTrustStatusTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~CheckRenewedExpiredKeyTrustStatusTest() override {
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
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the CheckRenewedExpiredKeyTrustStatusTest suite.

    };

}  // namespace


// This is what happens if we receive a key renewal (e.g. by mail) before ever updating the OpenPGP identity after expiration. 
TEST_F(CheckRenewedExpiredKeyTrustStatusTest, check_renewed_expired_key_trust_status_OpenPGP_no_update) {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");
    ASSERT_TRUE(ok);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    pEp_identity* alice_from = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Cooper");

    PEP_STATUS status = set_own_key(session, alice_from, alice_fpr);
    ASSERT_OK;

    const char* inq_fpr =  "8E8D2381AE066ABE1FEE509821BA977CA4728718";
    // KEY ELECTION: It is clear that leaving an address we have a key for as a TOFU address is going to continue to have implications in the 
    //               event that usernames differ. Here, we're losing the key that has been set for this identity. I am not sure we want this.
    //    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", NULL, "TOFU_inquisitor@darthmama.org", "Lady Claire Trevelyan");
    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", NULL, "INQUISITOR", "Lady Claire Trevelyan");

    status = set_fpr_preserve_ident(session, expired_inquisitor, inq_fpr, false);
    ASSERT_OK;

    // Ok, so I want to make sure we make an entry, so I'll try to decrypt the message WITH
    // the expired key:
    const string msg = slurp("test_mails/ENGINE-463-attempt-numero-dos.eml");

    char* decrypted_msg = NULL;
    stringlist_t* keylist = NULL;

    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    message* dec_msg = NULL;
    message* enc_msg = NULL;
    status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_OK;

    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_DECRYPTED); // ???

    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");
    ASSERT_TRUE(ok);

    message* msg2 = new_message(PEP_dir_outgoing);

    msg2->from = alice_from;
    msg2->to = new_identity_list(expired_inquisitor);
    msg2->shortmsg = strdup("Blah!");
    msg2->longmsg = strdup("Blahblahblah!");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    // We don't keep OpenPGP expired keys. We'll have to receive the new one via mail.
    status = outgoing_message_rating(session, msg2, &rating);
    ASSERT_OK;
    ASSERT_EQ(rating, PEP_rating_reliable);
}

// If we updated an OpenPGP identity in the meantime, we will have removed the key. Too bad.
TEST_F(CheckRenewedExpiredKeyTrustStatusTest, check_renewed_expired_key_trust_status_OpenPGP_with_update) {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");
    ASSERT_TRUE(ok);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    pEp_identity* alice_from = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Cooper");

    PEP_STATUS status = set_own_key(session, alice_from, alice_fpr);
    ASSERT_OK;

    const char* inq_fpr =  "8E8D2381AE066ABE1FEE509821BA977CA4728718";
    // KEY ELECTION: It is clear that leaving an address we have a key for as a TOFU address is going to continue to have implications in the 
    //               event that usernames differ. Here, we're losing the key that has been set for this identity. I am not sure we want this.
    //    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", NULL, "TOFU_inquisitor@darthmama.org", "Lady Claire Trevelyan");
    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", NULL, "INQUISITOR", "Lady Claire Trevelyan");

    status = set_fpr_preserve_ident(session, expired_inquisitor, inq_fpr, false);
    ASSERT_OK;

    // Ok, so I want to make sure we make an entry, so I'll try to decrypt the message WITH
    // the expired key:
    const string msg = slurp("test_mails/ENGINE-463-attempt-numero-dos.eml");

    status = update_identity(session, expired_inquisitor);
    ASSERT_EQ(status, PEP_STATUS_OK); // We don't need to be informed that there's now no key - update_identity not having one is enough
    ASSERT_NULL(expired_inquisitor->fpr);
    ASSERT_EQ(expired_inquisitor->comm_type, PEP_ct_key_not_found);

    char* decrypted_msg = NULL;
    stringlist_t* keylist = NULL;

    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    message* dec_msg = NULL;
    message* enc_msg = NULL;
    status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_OK;

    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_DECRYPTED); // ???

    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");
    ASSERT_TRUE(ok);

    message* msg2 = new_message(PEP_dir_outgoing);

    msg2->from = alice_from;
    msg2->to = new_identity_list(expired_inquisitor);
    msg2->shortmsg = strdup("Blah!");
    msg2->longmsg = strdup("Blahblahblah!");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    // We don't keep OpenPGP expired keys. We'll have to receive the new one via mail.
    status = outgoing_message_rating(session, msg2, &rating);
    ASSERT_OK;
    ASSERT_EQ(rating, PEP_rating_reliable);

    status = update_identity(session, expired_inquisitor);
    ASSERT_EQ(status, PEP_STATUS_OK); // We don't need to be informed that there's now no key - update_identity not having one is enough
    ASSERT_NE(expired_inquisitor->fpr, nullptr);
    ASSERT_STREQ(expired_inquisitor->fpr, inq_fpr);
    ASSERT_EQ(expired_inquisitor->comm_type, PEP_ct_OpenPGP_unconfirmed);
}

// If we updated an OpenPGP identity in the meantime, we will have removed the key. Too bad.
// Trust will have to be redone.
TEST_F(CheckRenewedExpiredKeyTrustStatusTest, check_renewed_expired_key_trust_status_trusted_user_OpenPGP) {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");
    ASSERT_TRUE(ok);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    pEp_identity* alice_from = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Cooper");

    PEP_STATUS status = set_own_key(session, alice_from, alice_fpr);
    ASSERT_OK;

    const char* inquisitor_fpr = "8E8D2381AE066ABE1FEE509821BA977CA4728718";
    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", "8E8D2381AE066ABE1FEE509821BA977CA4728718", "INQUISITOR", "Lady Claire Trevelyan");

    status = set_fpr_preserve_ident(session, expired_inquisitor, inquisitor_fpr, false);
    ASSERT_OK;

    PEP_comm_type key_ct;
    status = get_key_rating(session, inquisitor_fpr, &key_ct);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(key_ct, PEP_ct_key_expired);

    status = set_identity(session, expired_inquisitor);
    ASSERT_OK;
    expired_inquisitor->comm_type = PEP_ct_OpenPGP; // confirmed
    status = set_trust(session, expired_inquisitor);
    ASSERT_OK;
    status = get_trust(session, expired_inquisitor);
    ASSERT_EQ(expired_inquisitor->comm_type , PEP_ct_OpenPGP);

    // Ok, now update_identity - we'll discover it's expired
    status = update_identity(session, expired_inquisitor);
    ASSERT_EQ(status , PEP_STATUS_OK); // Key is expired, but we don't return it. So... byebye.
    PEP_comm_type ct = expired_inquisitor->comm_type;
    ASSERT_EQ(ct , PEP_ct_key_not_found);
    ASSERT_NULL(expired_inquisitor->fpr);

    expired_inquisitor->fpr = strdup(inquisitor_fpr);
    status = get_trust(session, expired_inquisitor);
    ct = expired_inquisitor->comm_type;
    ASSERT_OK;
    ASSERT_EQ(ct , PEP_ct_key_expired_but_confirmed);

    // Ok, so I want to make sure we make an entry, so I'll try to decrypt the message WITH
    // the expired key:
    const string msg = slurp("test_mails/ENGINE-463-attempt-numero-dos.eml");

    char* decrypted_msg = NULL;
    stringlist_t* keylist = NULL;
//    char* modified_src = NULL;

    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    message* dec_msg = NULL;
    message* enc_msg = NULL;
    status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_OK;

    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_DECRYPTED); // ???

    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");
    ASSERT_TRUE(ok);

    pEp_identity* expired_inquisitor1 = new_identity("inquisitor@darthmama.org", NULL, "INQUISITOR", "Lady Claire Trevelyan");

    status = update_identity(session, expired_inquisitor1);
    ASSERT_OK;
    ASSERT_STREQ(expired_inquisitor1->fpr, inquisitor_fpr);
    ASSERT_EQ(expired_inquisitor1->comm_type, PEP_ct_OpenPGP);
    status = get_trust(session, expired_inquisitor1);
    ASSERT_OK;
    ASSERT_EQ(expired_inquisitor1->comm_type, PEP_ct_OpenPGP);

    message* msg2 = new_message(PEP_dir_outgoing);

    msg2->from = alice_from;
    msg2->to = new_identity_list(expired_inquisitor1);
    msg2->shortmsg = strdup("Blah!");
    msg2->longmsg = strdup("Blahblahblah!");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    status = outgoing_message_rating(session, msg2, &rating);
    ASSERT_OK;
    ASSERT_EQ(rating, PEP_rating_trusted);

    free_message(msg2);

}

TEST_F(CheckRenewedExpiredKeyTrustStatusTest, check_renewed_expired_key_trust_status_pEp_user) {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");
    ASSERT_TRUE(ok);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    pEp_identity* alice_from = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Cooper");

    PEP_STATUS status = set_own_key(session, alice_from, alice_fpr);
    ASSERT_OK;

    const char* inquisitor_fpr = "8E8D2381AE066ABE1FEE509821BA977CA4728718";
    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", "8E8D2381AE066ABE1FEE509821BA977CA4728718", "TOFU_inquisitor@darthmama.org", "Lady Claire Trevelyan");
    status = set_identity(session, expired_inquisitor);
    ASSERT_OK;
    expired_inquisitor->comm_type = PEP_ct_pEp_unconfirmed;
    status = set_trust(session, expired_inquisitor);
    ASSERT_OK;

    bool pEp_user = false;
    status = is_pEp_user(session, expired_inquisitor, &pEp_user);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(pEp_user);

    // Ok, so I want to make sure we make an entry, so I'll try to decrypt the message WITH
    // the expired key:
    const string msg = slurp("test_mails/ENGINE-463-attempt-numero-dos.eml");

    char* decrypted_msg = NULL;
    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    message* dec_msg = NULL;
    message* enc_msg = NULL;
    status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_OK;

    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_DECRYPTED);

    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");
    ASSERT_TRUE(ok);

    pEp_identity* expired_inquisitor1 = new_identity("inquisitor@darthmama.org", NULL, NULL, "Lady Claire Trevelyan");
    message* msg2 = new_message(PEP_dir_outgoing);

    msg2->from = alice_from;
    msg2->to = new_identity_list(expired_inquisitor1);
    msg2->shortmsg = strdup("Blah!");
    msg2->longmsg = strdup("Blahblahblah!");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    status = outgoing_message_rating(session, msg2, &rating);
    ASSERT_OK;
    ASSERT_EQ(rating , PEP_rating_reliable);

    status = get_trust(session, expired_inquisitor);
    ASSERT_EQ(expired_inquisitor1->comm_type , PEP_ct_pEp_unconfirmed);
    free_message(msg2);
}

TEST_F(CheckRenewedExpiredKeyTrustStatusTest, check_renewed_expired_key_trust_status_trusted_pEp_user) {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    ASSERT_TRUE(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");
    ASSERT_TRUE(ok);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    pEp_identity* alice_from = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Cooper");

    PEP_STATUS status = set_own_key(session, alice_from, alice_fpr);
    ASSERT_OK;

    const char* inquisitor_fpr = "8E8D2381AE066ABE1FEE509821BA977CA4728718";
    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", "8E8D2381AE066ABE1FEE509821BA977CA4728718", "TOFU_inquisitor@darthmama.org", "Lady Claire Trevelyan");
    status = set_identity(session, expired_inquisitor);
    ASSERT_OK;
    expired_inquisitor->comm_type = PEP_ct_pEp; // confirmed
    status = set_trust(session, expired_inquisitor);
    ASSERT_OK;
    status = get_trust(session, expired_inquisitor);
    ASSERT_EQ(expired_inquisitor->comm_type , PEP_ct_pEp);

    bool pEp_user = false;
    status = is_pEp_user(session, expired_inquisitor, &pEp_user);
    ASSERT_OK;
    ASSERT_TRUE(pEp_user);

    // Ok, now update_identity - we'll discover it's expired
    status = update_identity(session, expired_inquisitor);
    ASSERT_OK; // key is expired, but we don't return it, so we're OK.
    PEP_comm_type ct = expired_inquisitor->comm_type;
    ASSERT_EQ(ct, PEP_ct_key_not_found);
    ASSERT_NULL(expired_inquisitor->fpr);

    expired_inquisitor->fpr = strdup(inquisitor_fpr);
    status = get_trust(session, expired_inquisitor);
    ct = expired_inquisitor->comm_type;
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(ct, PEP_ct_key_expired_but_confirmed);

    // Ok, so I want to make sure we make an entry, so I'll try to decrypt the message WITH
    // the expired key:
    message* decrypted_msg = NULL;
    status = vanilla_read_file_and_decrypt(session, &decrypted_msg, "test_mails/ENGINE-463-attempt-numero-dos.eml");
    ASSERT_EQ(status , PEP_DECRYPTED);

    free_message(decrypted_msg);

    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc");
    ASSERT_TRUE(ok);

    pEp_identity* expired_inquisitor1 = new_identity("inquisitor@darthmama.org", NULL, NULL, "Lady Claire Trevelyan");

    status = update_identity(session, expired_inquisitor1);
    ASSERT_OK;
    status = get_trust(session, expired_inquisitor1);
    ASSERT_EQ(expired_inquisitor1->comm_type, PEP_ct_pEp);

    message* msg2 = new_message(PEP_dir_outgoing);
    PEP_rating rating = PEP_rating_undefined;

    msg2->from = alice_from;
    msg2->to = new_identity_list(expired_inquisitor1);
    msg2->shortmsg = strdup("Blah!");
    msg2->longmsg = strdup("Blahblahblah!");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    status = outgoing_message_rating(session, msg2, &rating);
    ASSERT_OK;
    ASSERT_GE(rating, PEP_rating_trusted);

    free_message(msg2);
}
