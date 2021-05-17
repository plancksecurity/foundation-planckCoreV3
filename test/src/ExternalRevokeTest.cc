// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cstring>
#include <time.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include "mime.h"
#include "message_api.h"
#include "test_util.h"

#include "pEpEngine.h"
#include "pEp_internal.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for ExternalRevokeTest
    class ExternalRevokeTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            ExternalRevokeTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~ExternalRevokeTest() override {
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
            // Objects declared here can be used by all tests in the ExternalRevokeTest suite.

    };

}  // namespace


TEST_F(ExternalRevokeTest, check_external_revoke) {

    PEP_STATUS status = PEP_STATUS_OK;

#ifndef NETPGP
    char* fprs[2];

    const string fenris_pub_key = slurp("test_keys/pub/pep.test.fenris-0x4F3D2900_pub.asc");
    const string fenris_priv_key = slurp("test_keys/priv/pep.test.fenris-0x4F3D2900_priv.asc");

    ASSERT_NE(fenris_pub_key.length() , 0);
    ASSERT_NE(fenris_priv_key.length() , 0);

    PEP_STATUS statuspub = import_key(session, fenris_pub_key.c_str(), fenris_pub_key.length(), NULL);
    PEP_STATUS statuspriv = import_key(session, fenris_priv_key.c_str(), fenris_priv_key.length(), NULL);
    ASSERT_EQ(statuspub , PEP_TEST_KEY_IMPORT_SUCCESS);
    ASSERT_EQ(statuspriv , PEP_TEST_KEY_IMPORT_SUCCESS);

    // Create sender ID

    pEp_identity * me = new_identity("pep.test.fenris@thisstilldoesntwork.lu", "0969FA229DF21C832A64A04711B1B9804F3D2900", PEP_OWN_USERID, "Fenris Hawke");
    status = myself(session, me);

    // Create key
    output_stream << "Creating new id for : ";
    char *uniqname = strdup("AAAAtestuser@testdomain.org");
    srandom(time(NULL));
    for(int i=0; i < 4;i++)
        uniqname[i] += random() & 0xf;

    output_stream << uniqname << "\n";
    pEp_identity * recip1 = new_identity(uniqname, NULL, NULL, "Test User");

    status = generate_keypair(session, recip1);
    ASSERT_OK;

    output_stream << "Generated fingerprint ";
    output_stream << recip1->fpr << "\n";

    fprs[0] = strdup(recip1->fpr);

    output_stream << endl << "*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*" << endl;
    output_stream << "Trust and revoke single key, ensure trust changes, then generate new key and ensure rating is correct." << endl;
    output_stream << "*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*" << endl << endl;

    output_stream << endl << "---------------------------------------------------------" << endl;
    output_stream << "1a. Encrypt message for trusted partner." << endl;
    output_stream << "---------------------------------------------------------" << endl << endl;

    output_stream << "Trusting personal key for " << uniqname << endl;
    recip1->me = false;
    // Trust it
    status = update_identity(session, recip1);
    ASSERT_OK;
    status = set_fpr_preserve_ident(session, recip1, fprs[0], true);
    ASSERT_OK;
    status = update_identity(session, recip1);
    ASSERT_OK;
    ASSERT_STREQ(recip1->fpr, fprs[0]);
    status = trust_personal_key(session, recip1);
    ASSERT_OK;
    status = update_identity(session, recip1);
    ASSERT_OK;
    
    // TODO: Check trust?
    output_stream << "Done! Trusted personal key with fpr " << recip1->fpr << " for " << uniqname << endl;

    const char* r1_userid = (recip1->user_id ? strdup(recip1->user_id) : NULL);


    // encrypt something to the key
    output_stream << "Creating message…\n";
    identity_list* to_list = new_identity_list(identity_dup(recip1)); // to bob
    message* outgoing_msg = new_message(PEP_dir_outgoing);
    ASSERT_NOTNULL(outgoing_msg);
    outgoing_msg->from = identity_dup(me);
    outgoing_msg->to = to_list;
    outgoing_msg->shortmsg = strdup("Greetings, humans!");
    outgoing_msg->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    output_stream << "Message created.\n";

    message* encrypted_outgoing_msg = NULL;

    output_stream << "Encrypting message to " << uniqname << "…\n";
    status = encrypt_message(session, outgoing_msg, NULL, &encrypted_outgoing_msg, PEP_enc_PGP_MIME, 0);
    output_stream << "Encrypted message with status " << tl_status_string(status) << endl;
    // check status
    ASSERT_OK;
    ASSERT_NOTNULL(encrypted_outgoing_msg);

    output_stream << "Checking message recipient comm_type from message." << endl;
    // check comm_type
    output_stream << "comm_type: " << tl_ct_string(encrypted_outgoing_msg->to->ident->comm_type) << endl;
    ASSERT_EQ(encrypted_outgoing_msg->to->ident->comm_type , PEP_ct_OpenPGP);

    status = get_trust(session, recip1);

    output_stream << "Recip's trust DB comm_type = "  << tl_ct_string(recip1->comm_type) << endl;
    ASSERT_EQ(recip1->comm_type , PEP_ct_OpenPGP); // FIXME: PEP_ct_pEp???

    // decrypt message
    free_message(outgoing_msg);
    outgoing_msg = NULL;

    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;

    output_stream << endl << "---------------------------------------------------------" << endl;
    output_stream << "1b. Decrypt message that was encrypted for trusted partner." << endl;
    output_stream << "---------------------------------------------------------" << endl << endl;

    flags = 0;
    output_stream << "Decrypting message." << endl;
    status = decrypt_message(session, encrypted_outgoing_msg, &outgoing_msg, &keylist, &rating, &flags);
    output_stream << "Decrypted message with status " << tl_status_string(status) << endl;
    ASSERT_OK;
    ASSERT_EQ(rating , PEP_rating_trusted);

    // check rating
    output_stream << "Rating of decrypted message to trusted recip: " << tl_rating_string(rating) << endl;
    ASSERT_EQ(rating , PEP_rating_trusted); // FIXME: trusted and anonymised?

    // check comm_type
    status = get_trust(session, recip1);

    output_stream << "Recip's trust DB comm_type = " << tl_ct_string(recip1->comm_type) << endl;
    ASSERT_EQ(recip1->comm_type , PEP_ct_OpenPGP); // FIXME: PEP_ct_pEp???

    output_stream << endl << "---------------------------------------------------------" << endl;
    output_stream << "2a. Revoke key for (currently) trusted partner." << endl;
    output_stream << "---------------------------------------------------------" << endl << endl;
    // externally revoke key
    // (note - as of 23.5.17, revoke_key() doesn't touch the trust db, just the keyring, so we can do this)

    output_stream << "Revoking key." << endl;
    status = update_identity(session, recip1);
    status = revoke_key(session, recip1->fpr, "encrypt_for_identity_test");
    output_stream << "Status of revocation call for " << recip1->fpr << " is "<< tl_status_string(status) << endl;

    // free messages
    free_message(outgoing_msg);
    free_message(encrypted_outgoing_msg);
    outgoing_msg = NULL;
    encrypted_outgoing_msg = NULL;

    // encrypt something to the key
    output_stream << "creating message…\n";
    to_list = new_identity_list(identity_dup(recip1)); // to bob
    outgoing_msg = new_message(PEP_dir_outgoing);
    ASSERT_NOTNULL(outgoing_msg);
    outgoing_msg->from = identity_dup(me);
    outgoing_msg->to = to_list;
    outgoing_msg->shortmsg = strdup("Greetings, humans!");
    outgoing_msg->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    output_stream << "message created.\n";

    encrypted_outgoing_msg = NULL;
    message* decrypted_msg = NULL;

    output_stream << endl << "---------------------------------------------------------" << endl;
    output_stream << "2b. Encrypt message for recip whose key has been externally revoked in the keyring, not the app." << endl;
    output_stream << "---------------------------------------------------------" << endl << endl;


    status = encrypt_message(session, outgoing_msg, NULL, &encrypted_outgoing_msg, PEP_enc_PGP_MIME, 0);
    output_stream << "Encryption returns with status " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    ASSERT_NULL(encrypted_outgoing_msg);
    status = update_identity(session, recip1);
    ASSERT_EQ(recip1->comm_type, PEP_ct_key_not_found);

    output_stream << endl << "---------------------------------------------------------" << endl;
    output_stream << "2c. Check trust of recip, whose only key has been revoked, once an encryption attempt has been made." << endl;
    output_stream << "---------------------------------------------------------" << endl << endl;

    ASSERT_NULL(recip1->fpr);
    recip1->fpr = fprs[0];
    status = get_trust(session, recip1);
    recip1->fpr = NULL;

    output_stream << "Recip's trust DB comm_type = " << tl_ct_string(recip1->comm_type) << endl;
    ASSERT_TRUE(recip1->comm_type == PEP_ct_unknown || recip1->comm_type == PEP_ct_key_revoked);

    free_message(decrypted_msg);
    free_message(outgoing_msg);
    outgoing_msg = NULL;
    decrypted_msg = NULL;

    output_stream << endl << "---------------------------------------------------------" << endl;
    output_stream << "3a. Generate new key, but don't explicitly trust it." << endl;
    output_stream << "---------------------------------------------------------" << endl << endl;

    // now: generate new key
    free(recip1->fpr);
    recip1->fpr = NULL;
    status = generate_keypair(session, recip1);

    output_stream << "Generated fingerprint \n";
    output_stream << recip1->fpr << "\n";
    fprs[1] = strdup(recip1->fpr);

    // try again
    output_stream << endl << "---------------------------------------------------------" << endl;
    output_stream << "3b. Try to send something to the email address of our revoked friend, make sure we can't encrypt (no key yet)." << endl;
    output_stream << "---------------------------------------------------------" << endl << endl;

    // encrypt something to the key
    output_stream << "Creating message…\n";

    // output_stream << "First, update identity though!\n";
    // status = update_identity(session, recip1);
    to_list = new_identity_list(identity_dup(recip1)); // to bob
    outgoing_msg = new_message(PEP_dir_outgoing);
    ASSERT_NOTNULL(outgoing_msg);
    outgoing_msg->from = identity_dup(me);
    outgoing_msg->to = to_list;
    outgoing_msg->shortmsg = strdup("Greetings, humans!");
    outgoing_msg->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    output_stream << "Message created.\n";

    status = encrypt_message(session, outgoing_msg, NULL, &encrypted_outgoing_msg, PEP_enc_PGP_MIME, 0);
    PEP_comm_type ct = (encrypted_outgoing_msg ? encrypted_outgoing_msg->to->ident->comm_type : outgoing_msg->to->ident->comm_type);


    // CHECK STATUS???
    output_stream << "Encryption returns with status " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_UNENCRYPTED);

    // check comm_type
    output_stream << "comm_type: " << tl_ct_string(ct) << endl;
    ASSERT_EQ(ct, PEP_ct_key_not_found);

    status = get_trust(session, recip1);
    ASSERT_EQ(recip1->comm_type, PEP_ct_unknown);

    free_message(outgoing_msg);

    // try again
    output_stream << endl << "---------------------------------------------------------" << endl;
    output_stream << "3c. Try to send something to the email address of our revoked friend, make sure a new key is used to encrypt." << endl;
    output_stream << "---------------------------------------------------------" << endl << endl;

    status = update_identity(session, recip1);
    ASSERT_OK;
    status = set_fpr_preserve_ident(session, recip1, fprs[1], true);
    ASSERT_OK;
//    status = update_identity(session, recip1);
//    ASSERT_OK;
//    ASSERT_STREQ(recip1->fpr, fprs[1]);

    // encrypt something to the key
    output_stream << "Creating message…\n";

    // output_stream << "First, update identity though!\n";
    // status = update_identity(session, recip1);
    to_list = new_identity_list(identity_dup(recip1)); // to bob
    outgoing_msg = new_message(PEP_dir_outgoing);
    ASSERT_NOTNULL(outgoing_msg);
    outgoing_msg->from = identity_dup(me);
    outgoing_msg->to = to_list;
    outgoing_msg->shortmsg = strdup("Greetings, humans!");
    outgoing_msg->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    output_stream << "Message created.\n";

    status = encrypt_message(session, outgoing_msg, NULL, &encrypted_outgoing_msg, PEP_enc_PGP_MIME, 0);
    ct = (encrypted_outgoing_msg ? encrypted_outgoing_msg->to->ident->comm_type : outgoing_msg->to->ident->comm_type);


    // CHECK STATUS???
    output_stream << "Encryption returns with status " << tl_status_string(status) << endl;

    // check comm_type
    output_stream << "comm_type: " << tl_ct_string(ct) << endl;
    ASSERT_EQ(ct, PEP_ct_OpenPGP_unconfirmed);
    status = update_identity(session, recip1);
    ASSERT_OK;
    status = get_trust(session, recip1);
    ASSERT_OK;

//    output_stream << "Recip's trust DB comm_type (should be unknown, as we're using a keyring-only key, not in DB) = "  << tl_ct_string(recip1->comm_type) << endl;
    output_stream << "Recip's trust DB comm_type (should PEP_ct_OpenPGP_unconfirmed), as we now record this when using update_identity on no-default idents = "  << tl_ct_string(recip1->comm_type) << endl;
    ASSERT_EQ(recip1->comm_type, PEP_ct_OpenPGP_unconfirmed);

    output_stream << endl << "---------------------------------------------------------" << endl;
    output_stream << "3d. Decrypt... that... message!" << endl;
    output_stream << "---------------------------------------------------------" << endl << endl;


    flags = 0;
    status = decrypt_message(session, encrypted_outgoing_msg, &decrypted_msg, &keylist, &rating, &flags);
    output_stream << "Decryption returns with status " << tl_status_string(status) << endl;
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(decrypted_msg);

    // check rating
    output_stream << "Rating of decrypted message to trusted recip: " << tl_rating_string(rating) << endl;
    ASSERT_EQ(rating, PEP_rating_reliable);

    status = update_identity(session, decrypted_msg->to->ident);
    ct = (decrypted_msg ? decrypted_msg->to->ident->comm_type : outgoing_msg->to->ident->comm_type);

    output_stream << "comm_type: " << tl_ct_string(ct) << endl;
    ASSERT_EQ(ct, PEP_ct_OpenPGP_unconfirmed);
    status = update_identity(session, recip1);
    ASSERT_OK;
    status = get_trust(session, recip1);
    ASSERT_OK;
//    output_stream << "Recip's trust DB comm_type (should be unknown - there's nothing in the DB) = "  << tl_ct_string(recip1->comm_type) << endl;
    output_stream << "Recip's trust DB comm_type (should be PEP_ct_OpenPGP_unconfirmed, as we now store it.) = "  << tl_ct_string(recip1->comm_type) << endl;
    ASSERT_EQ(recip1->comm_type, PEP_ct_OpenPGP_unconfirmed);

    free_message(encrypted_outgoing_msg);
    free_message(decrypted_msg);
    free_message(outgoing_msg);
    outgoing_msg = NULL;
    decrypted_msg = NULL;
    encrypted_outgoing_msg = NULL;

    free_identity(me);
    free_identity(recip1);
    free(uniqname);

    free(fprs[0]);
    free(fprs[1]);

#else
    output_stream << "Sorry, test is not defined for NETPGP at this time." << endl;

#endif
}
