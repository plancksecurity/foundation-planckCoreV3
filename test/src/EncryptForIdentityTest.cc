// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <unistd.h>
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>

#include "pEpEngine.h"
#include "mime.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for EncryptForIdentityTest
    class EncryptForIdentityTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            EncryptForIdentityTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~EncryptForIdentityTest() override {
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
                ASSERT_NE(engine, nullptr);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NE(engine->session, nullptr);
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
            // Objects declared here can be used by all tests in the EncryptForIdentityTest suite.

    };

}  // namespace


TEST_F(EncryptForIdentityTest, check_encrypt_for_identity) {

    // message_api test code

    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string alice_priv_key = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    const string gabrielle_pub_key = slurp("test_keys/pub/pep-test-gabrielle-0xE203586C_pub.asc");
    const string bella_pub_key = slurp("test_keys/pub/pep.test.bella-0xAF516AAE_pub.asc");

    PEP_STATUS statuspub = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    PEP_STATUS statuspriv = import_key(session, alice_priv_key.c_str(), alice_priv_key.length(), NULL);
    ASSERT_EQ(statuspub, PEP_TEST_KEY_IMPORT_SUCCESS);
    ASSERT_EQ(statuspriv, PEP_TEST_KEY_IMPORT_SUCCESS);

    statuspub = import_key(session, gabrielle_pub_key.c_str(), gabrielle_pub_key.length(), NULL);
    ASSERT_EQ(statuspub, PEP_TEST_KEY_IMPORT_SUCCESS);
    statuspub = import_key(session, bella_pub_key.c_str(), bella_pub_key.length(), NULL);
    ASSERT_EQ(statuspub, PEP_TEST_KEY_IMPORT_SUCCESS);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    const char* gabrielle_fpr = "906C9B8349954E82C5623C3C8C541BD4E203586C";
    const char* bella_fpr = "5631BF1357326A02AA470EEEB815EF7FA4516AAE";
    const char* nobody_fpr = "1111111111111111111111111111111111111111";

    output_stream << "creating message…\n";
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Test");
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test");

    alice->me = true;

    PEP_STATUS mystatus = set_own_key(session, alice, alice_fpr);
    ASSERT_EQ(mystatus, PEP_STATUS_OK);

    mystatus = set_identity_flags(session, alice, PEP_idf_org_ident);
    ASSERT_EQ(mystatus , PEP_STATUS_OK);

    mystatus = myself(session, alice);
    ASSERT_EQ(alice->flags, alice->flags & PEP_idf_org_ident);

    identity_list* to_list = new_identity_list(bob); // to bob
    message* outgoing_message = new_message(PEP_dir_outgoing);
    ASSERT_NE(outgoing_message, nullptr);
    outgoing_message->from = alice;
    outgoing_message->to = to_list;
    outgoing_message->shortmsg = strdup("Greetings, humans!");
    outgoing_message->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_message->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    output_stream << "message created.\n";

    char* encoded_text = nullptr;
    PEP_STATUS status = mime_encode_message(outgoing_message, false, &encoded_text, false);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(encoded_text, nullptr);

    output_stream << "decrypted:\n\n";
    output_stream << encoded_text << "\n";

    free(encoded_text);

    message* encrypted_msg = nullptr;
    output_stream << "calling encrypt_message_for_identity()\n";
    status = encrypt_message_for_self(session, alice, outgoing_message, NULL, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    output_stream << "encrypt_message() returns " << tl_status_string(status) << '.' << endl;
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(encrypted_msg, nullptr);
    output_stream << "message encrypted.\n";

    status = mime_encode_message(encrypted_msg, false, &encoded_text, false);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(encoded_text, nullptr);

    output_stream << "encrypted:\n\n";
    output_stream << encoded_text << "\n";

    message* decoded_msg = nullptr;
    status = mime_decode_message(encoded_text, strlen(encoded_text), &decoded_msg, NULL);
    ASSERT_EQ(status, PEP_STATUS_OK);
    const string string3 = encoded_text;

    unlink("tmp/msg_encrypt_for_self.asc");
    ofstream outFile3("tmp/msg_encrypt_for_self.asc");
    outFile3.write(string3.c_str(), string3.size());
    outFile3.close();

    message* decrypted_msg = nullptr;
    stringlist_t* keylist_used = nullptr;

    PEP_rating rating;
    PEP_decrypt_flags_t flags;

    flags = 0;
    status = decrypt_message(session, encrypted_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    ASSERT_NE(decrypted_msg, nullptr);
    ASSERT_NE(keylist_used, nullptr);
    ASSERT_NE(rating, 0);
    ASSERT_TRUE(status == PEP_DECRYPTED && rating == PEP_rating_unreliable);
    PEP_comm_type ct = encrypted_msg->from->comm_type;
    ASSERT_TRUE(ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed);

    output_stream << "keys used:\n";

    int i = 0;

    for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next, i++)
    {
        if (i == 0) {
            ASSERT_STRCASEEQ("",kl4->value);
        }
        else {
            output_stream << "\t " << kl4->value << endl;
            ASSERT_STRCASEEQ("4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", kl4->value);
            output_stream << "Encrypted for Alice! Yay! It worked!" << endl;
        }
        ASSERT_LT(i , 2);
    }
    output_stream << "Encrypted ONLY for Alice! Test passed. Move along. These are not the bugs you are looking for." << endl;

    output_stream << "freeing messages…\n";
    free_message(encrypted_msg);
    free_message(decrypted_msg);
    free_stringlist (keylist_used);
    output_stream << "done.\n";

    output_stream << "Now encrypt for self with extra keys." << endl;
    stringlist_t* extra_keys = new_stringlist(gabrielle_fpr);
    stringlist_add(extra_keys, bella_fpr);
    encrypted_msg = NULL;
    decrypted_msg = NULL;
    keylist_used = NULL;

    output_stream << "calling encrypt_message_for_identity()\n";
    status = encrypt_message_for_self(session, alice, outgoing_message, extra_keys, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    output_stream << "encrypt_message() returns " << tl_status_string(status) << '.' << endl;
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(encrypted_msg, nullptr);
    output_stream << "message encrypted.\n";

    flags = 0;
    status = decrypt_message(session, encrypted_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    ASSERT_NE(decrypted_msg, nullptr);
    ASSERT_NE(keylist_used, nullptr);
    ASSERT_NE(rating, 0);
    ASSERT_TRUE(status == PEP_DECRYPTED && rating == PEP_rating_unreliable);
    ct = encrypted_msg->from->comm_type;
    ASSERT_TRUE(ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed);

    output_stream << "keys used:\n";

    for (stringlist_t* incoming_kl = extra_keys; incoming_kl && incoming_kl->value; incoming_kl = incoming_kl->next) {
        bool found = false;
        output_stream << "Encrypted for: ";
        for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next, i++) {
            if (strcasecmp(incoming_kl->value, kl4->value) == 0) {
                output_stream << "\t " << kl4->value;
                found = true;
                break;
            }
        }
        output_stream << endl;
        ASSERT_TRUE(found);
    }
    output_stream << "Encrypted for all the extra keys!" << endl;

    bool found = false;
    for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next)
    {
        if (strcasecmp(alice_fpr, kl4->value) == 0) {
            found = true;
            output_stream << "Encrypted also for Alice! Yay!" << endl;
            break;
        }
    }
    ASSERT_TRUE(found);

    free_message(encrypted_msg);
    encrypted_msg = NULL;
    free_message(decrypted_msg);
    decrypted_msg = NULL;
    free_stringlist(keylist_used);
    keylist_used = NULL;

    output_stream << "Now add a bad fpr." << endl;

    stringlist_add(extra_keys, nobody_fpr);

    output_stream << "calling encrypt_message_for_identity()\n";
    status = encrypt_message_for_self(session, alice, outgoing_message, extra_keys, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    output_stream << "encrypt_message() returns " << tl_status_string(status) << '.' << endl;
    ASSERT_NE(status, PEP_STATUS_OK);

    free_message(outgoing_message);
    outgoing_message = NULL;
    free_message(encrypted_msg);
    encrypted_msg = NULL;
    free_message(decrypted_msg);
    decrypted_msg = NULL;
    free_stringlist(keylist_used);
    keylist_used = NULL;


    output_stream << "*** Now testing MIME_encrypt_for_self ***" << endl;

    alice = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    bob = new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test");

    output_stream << "Reading in alice_bob_encrypt_test_plaintext_mime.eml..." << endl;

    const string mimetext = slurp("test_mails/alice_bob_encrypt_test_plaintext_mime.eml");

    output_stream << "Text read:" << endl;
    output_stream << mimetext.c_str() << endl;
    char* encrypted_mimetext = nullptr;

    output_stream << "Calling MIME_encrypt_message_for_self" << endl;
    status = MIME_encrypt_message_for_self(session, alice, mimetext.c_str(),
                                           mimetext.size(),
                                           NULL,
                                           &encrypted_mimetext,
                                           PEP_enc_PGP_MIME,
                                           PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);

    output_stream << "Encrypted message:" << endl;
    output_stream << encrypted_mimetext << endl;

    output_stream << "Calling MIME_decrypt_message" << endl;

    char* decrypted_mimetext = nullptr;
    free_stringlist(keylist_used);
    keylist_used = nullptr;
    PEP_decrypt_flags_t mimeflags;
    PEP_rating mimerating;
    char* modified_src = NULL;

    mimeflags = 0;
    status = MIME_decrypt_message(session,
                                  encrypted_mimetext,
                                  strlen(encrypted_mimetext),
                                  &decrypted_mimetext,
                                  &keylist_used,
                                  &mimerating,
                                  &mimeflags,
				  &modified_src);

    ASSERT_NE(decrypted_mimetext, nullptr);
    ASSERT_NE(keylist_used, nullptr);
    ASSERT_NE(mimerating, 0);

    ASSERT_TRUE(status == PEP_DECRYPTED && mimerating == PEP_rating_unreliable);

    output_stream << "Decrypted message:" << endl;
    output_stream << decrypted_mimetext << endl;

    output_stream << "keys used:\n";

    i = 0;

    for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next, i++)
    {
        if (i == 0) {
            ASSERT_STRCASEEQ("",kl4->value);
        }
        else {
            output_stream << "\t " << kl4->value << endl;
            ASSERT_STRCASEEQ("4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", kl4->value);
            output_stream << "Encrypted for Alice! Yay! It worked!" << endl;
        }
        ASSERT_LT(i , 2);
    }
    output_stream << "Encrypted ONLY for Alice! Test passed. Move along. These are not the bugs you are looking for." << endl;
}

TEST_F(EncryptForIdentityTest, check_encrypt_for_identity_with_URI) {

    // message_api test code

    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string alice_priv_key = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    const string gabrielle_pub_key = slurp("test_keys/pub/pep-test-gabrielle-0xE203586C_pub.asc");
    const string bella_pub_key = slurp("test_keys/pub/pep.test.bella-0xAF516AAE_pub.asc");

    PEP_STATUS statuspub = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    PEP_STATUS statuspriv = import_key(session, alice_priv_key.c_str(), alice_priv_key.length(), NULL);
    ASSERT_EQ(statuspub, PEP_TEST_KEY_IMPORT_SUCCESS);
    ASSERT_EQ(statuspriv, PEP_TEST_KEY_IMPORT_SUCCESS);

    statuspub = import_key(session, gabrielle_pub_key.c_str(), gabrielle_pub_key.length(), NULL);
    ASSERT_EQ(statuspub, PEP_TEST_KEY_IMPORT_SUCCESS);
    statuspub = import_key(session, bella_pub_key.c_str(), bella_pub_key.length(), NULL);
    ASSERT_EQ(statuspub, PEP_TEST_KEY_IMPORT_SUCCESS);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    const char* gabrielle_fpr = "906C9B8349954E82C5623C3C8C541BD4E203586C";
    const char* bella_fpr = "5631BF1357326A02AA470EEEB815EF7FA4516AAE";
    const char* nobody_fpr = "1111111111111111111111111111111111111111";

    output_stream << "creating message…\n";
    pEp_identity* alice = new_identity("payto://BIC/SYSTEMA", alice_fpr, PEP_OWN_USERID, "Alice Test");
    pEp_identity* bob = new_identity("payto://BIC/SYSTEMB", NULL, "42", "Bob Test");

    alice->me = true;

    PEP_STATUS mystatus = set_own_key(session, alice, alice_fpr);
    ASSERT_EQ(mystatus, PEP_STATUS_OK);

    mystatus = set_identity_flags(session, alice, PEP_idf_org_ident);
    ASSERT_EQ(mystatus , PEP_STATUS_OK);

    mystatus = myself(session, alice);
    ASSERT_EQ(alice->flags, alice->flags & PEP_idf_org_ident);


    identity_list* to_list = new_identity_list(bob); // to bob
    message* outgoing_message = new_message(PEP_dir_outgoing);
    ASSERT_NE(outgoing_message, nullptr);
    outgoing_message->from = alice;
    outgoing_message->to = to_list;
    outgoing_message->shortmsg = strdup("Greetings, humans!");
    outgoing_message->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_message->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    output_stream << "message created.\n";

    char* encoded_text = nullptr;
    PEP_STATUS status = mime_encode_message(outgoing_message, false, &encoded_text, false);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(encoded_text, nullptr);

    output_stream << "decrypted:\n\n";
    output_stream << encoded_text << "\n";

    free(encoded_text);

    message* encrypted_msg = nullptr;
    output_stream << "calling encrypt_message_for_identity()\n";
    status = encrypt_message_for_self(session, alice, outgoing_message, NULL, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    output_stream << "encrypt_message() returns " << tl_status_string(status) << '.' << endl;
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(encrypted_msg, nullptr);
    output_stream << "message encrypted.\n";

    status = mime_encode_message(encrypted_msg, false, &encoded_text, false);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(encoded_text, nullptr);

    output_stream << "encrypted:\n\n";
    output_stream << encoded_text << "\n";

    message* decoded_msg = nullptr;
    status = mime_decode_message(encoded_text, strlen(encoded_text), &decoded_msg, NULL);
    ASSERT_EQ(status, PEP_STATUS_OK);
    const string string3 = encoded_text;

    unlink("tmp/msg_encrypt_for_self.asc");
    ofstream outFile3("tmp/msg_encrypt_for_self.asc");
    outFile3.write(string3.c_str(), string3.size());
    outFile3.close();

    message* decrypted_msg = nullptr;
    stringlist_t* keylist_used = nullptr;

    PEP_rating rating;
    PEP_decrypt_flags_t flags;

    flags = 0;
    status = decrypt_message(session, encrypted_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    ASSERT_NE(decrypted_msg, nullptr);
    ASSERT_NE(keylist_used, nullptr);
    ASSERT_NE(rating, 0);
    ASSERT_TRUE(status == PEP_DECRYPTED && rating == PEP_rating_unreliable);
    PEP_comm_type ct = encrypted_msg->from->comm_type;
    ASSERT_TRUE(ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed);

    output_stream << "keys used:\n";

    int i = 0;

    for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next, i++)
    {
        if (i == 0) {
            ASSERT_STRCASEEQ("",kl4->value);
        }
        else {
            output_stream << "\t " << kl4->value << endl;
            ASSERT_STRCASEEQ("4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", kl4->value);
            output_stream << "Encrypted for Alice! Yay! It worked!" << endl;
        }
        ASSERT_LT(i , 2);
    }
    output_stream << "Encrypted ONLY for Alice! Test passed. Move along. These are not the bugs you are looking for." << endl;

    output_stream << "freeing messages…\n";
    free_message(encrypted_msg);
    free_message(decrypted_msg);
    free_stringlist (keylist_used);
    output_stream << "done.\n";

    output_stream << "Now encrypt for self with extra keys." << endl;
    stringlist_t* extra_keys = new_stringlist(gabrielle_fpr);
    stringlist_add(extra_keys, bella_fpr);
    encrypted_msg = NULL;
    decrypted_msg = NULL;
    keylist_used = NULL;

    output_stream << "calling encrypt_message_for_identity()\n";
    status = encrypt_message_for_self(session, alice, outgoing_message, extra_keys, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    output_stream << "encrypt_message() returns " << tl_status_string(status) << '.' << endl;
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(encrypted_msg, nullptr);
    output_stream << "message encrypted.\n";

    flags = 0;
    status = decrypt_message(session, encrypted_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    ASSERT_NE(decrypted_msg, nullptr);
    ASSERT_NE(keylist_used, nullptr);
    ASSERT_NE(rating, 0);
    ASSERT_TRUE(status == PEP_DECRYPTED && rating == PEP_rating_unreliable);
    ct = encrypted_msg->from->comm_type;
    ASSERT_TRUE(ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed);

    output_stream << "keys used:\n";

    for (stringlist_t* incoming_kl = extra_keys; incoming_kl && incoming_kl->value; incoming_kl = incoming_kl->next) {
        bool found = false;
        output_stream << "Encrypted for: ";
        for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next, i++) {
            if (strcasecmp(incoming_kl->value, kl4->value) == 0) {
                output_stream << "\t " << kl4->value;
                found = true;
                break;
            }
        }
        output_stream << endl;
        ASSERT_TRUE(found);
    }
    output_stream << "Encrypted for all the extra keys!" << endl;

    bool found = false;
    for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next)
    {
        if (strcasecmp(alice_fpr, kl4->value) == 0) {
            found = true;
            output_stream << "Encrypted also for Alice! Yay!" << endl;
            break;
        }
    }
    ASSERT_TRUE(found);

    free_message(encrypted_msg);
    encrypted_msg = NULL;
    free_message(decrypted_msg);
    decrypted_msg = NULL;
    free_stringlist(keylist_used);
    keylist_used = NULL;

    output_stream << "Now add a bad fpr." << endl;

    stringlist_add(extra_keys, nobody_fpr);

    output_stream << "calling encrypt_message_for_identity()\n";
    status = encrypt_message_for_self(session, alice, outgoing_message, extra_keys, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    output_stream << "encrypt_message() returns " << tl_status_string(status) << '.' << endl;
    ASSERT_NE(status, PEP_STATUS_OK);

    free_message(outgoing_message);
    outgoing_message = NULL;
    free_message(encrypted_msg);
    encrypted_msg = NULL;
    free_message(decrypted_msg);
    decrypted_msg = NULL;
    free_stringlist(keylist_used);
    keylist_used = NULL;


    output_stream << "*** Now testing MIME_encrypt_for_self ***" << endl;

    alice = new_identity("payto://BIC/SYSTEMA", NULL, PEP_OWN_USERID, "Alice Test");
    bob = new_identity("payto://BIC/SYSTEMB", NULL, "42", "Bob Test");

    output_stream << "Reading in alice_bob_encrypt_test_plaintext_mime.eml..." << endl;

    const string mimetext = slurp("test_mails/alice_bob_encrypt_test_plaintext_mime.eml");

    output_stream << "Text read:" << endl;
    output_stream << mimetext.c_str() << endl;
    char* encrypted_mimetext = nullptr;

    output_stream << "Calling MIME_encrypt_message_for_self" << endl;
    status = MIME_encrypt_message_for_self(session, alice, mimetext.c_str(),
                                           mimetext.size(),
                                           NULL,
                                           &encrypted_mimetext,
                                           PEP_enc_PGP_MIME,
                                           PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);

    output_stream << "Encrypted message:" << endl;
    output_stream << encrypted_mimetext << endl;

    output_stream << "Calling MIME_decrypt_message" << endl;

    char* decrypted_mimetext = nullptr;
    free_stringlist(keylist_used);
    keylist_used = nullptr;
    PEP_decrypt_flags_t mimeflags;
    PEP_rating mimerating;
    char* modified_src = NULL;

    mimeflags = 0;
    status = MIME_decrypt_message(session,
                                  encrypted_mimetext,
                                  strlen(encrypted_mimetext),
                                  &decrypted_mimetext,
                                  &keylist_used,
                                  &mimerating,
                                  &mimeflags,
				  &modified_src);

    ASSERT_NE(decrypted_mimetext, nullptr);
    ASSERT_NE(keylist_used, nullptr);
    ASSERT_NE(mimerating, 0);

    ASSERT_TRUE(status == PEP_DECRYPTED && mimerating == PEP_rating_unreliable);

    output_stream << "Decrypted message:" << endl;
    output_stream << decrypted_mimetext << endl;

    output_stream << "keys used:\n";

    i = 0;

    for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next, i++)
    {
        if (i == 0) {
            ASSERT_STRCASEEQ("",kl4->value);
        }
        else {
            output_stream << "\t " << kl4->value << endl;
            ASSERT_STRCASEEQ("4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", kl4->value);
            output_stream << "Encrypted for Alice! Yay! It worked!" << endl;
        }
        ASSERT_LT(i , 2);
    }
    output_stream << "Encrypted ONLY for Alice! Test passed. Move along. These are not the bugs you are looking for." << endl;
}
