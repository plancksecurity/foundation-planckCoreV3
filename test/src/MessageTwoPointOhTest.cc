// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "platform.h"
#include "mime.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for MessageTwoPointOhTest
    class MessageTwoPointOhTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            MessageTwoPointOhTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~MessageTwoPointOhTest() override {
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
            // Objects declared here can be used by all tests in the MessageTwoPointOhTest suite.

    };

}  // namespace


TEST_F(MessageTwoPointOhTest, check_message_two_point_oh) {

    PEP_comm_type carol_comm_type = PEP_ct_pEp;

    // message_api test code

    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string alice_priv_key = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    const string carol_pub_key = slurp("test_keys/pub/pep-test-carol-0x42A85A42_pub.asc");
    const string carol_priv_key = slurp("test_keys/priv/pep-test-carol-0x42A85A42_priv.asc");

    PEP_STATUS statuspub = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    PEP_STATUS statuspriv = import_key(session, alice_priv_key.c_str(), alice_priv_key.length(), NULL);
    ASSERT_EQ(statuspub , PEP_TEST_KEY_IMPORT_SUCCESS);
    ASSERT_EQ(statuspriv , PEP_TEST_KEY_IMPORT_SUCCESS);
    statuspub = import_key(session, carol_pub_key.c_str(), carol_pub_key.length(), NULL);
    statuspriv = import_key(session, carol_priv_key.c_str(), carol_priv_key.length(), NULL);
    ASSERT_EQ(statuspub , PEP_TEST_KEY_IMPORT_SUCCESS);
    ASSERT_EQ(statuspriv , PEP_TEST_KEY_IMPORT_SUCCESS);

    output_stream << "creating message…\n";
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", PEP_OWN_USERID, "Alice Test");
    PEP_STATUS alice_status = set_own_key(session, alice, alice->fpr);
    ASSERT_EQ(alice_status, PEP_STATUS_OK);

    pEp_identity* carol = new_identity("pep-test-carol@pep-project.org", NULL, "TOFU_pep-test-carol@pep-project.org", "Carol Test");
    const char* carol_fpr = "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42";
    PEP_STATUS carol_status = set_fpr_preserve_ident(session, carol, carol_fpr, true);
    ASSERT_EQ(carol_status, PEP_STATUS_OK);
    carol_status = update_identity(session, carol);
    ASSERT_EQ(carol_status, PEP_STATUS_OK);

    PEP_STATUS status = update_trust_for_fpr(session, carol->fpr, carol_comm_type);

    PEP_STATUS mystatus = myself(session, alice);
    ASSERT_EQ(mystatus , PEP_STATUS_OK);
    alice_status = update_identity(session, alice);
    alice_status = update_identity(session, carol);
    ASSERT_EQ(alice->comm_type , PEP_ct_pEp);
    ASSERT_EQ(carol->comm_type , carol_comm_type);

    identity_list* to_list = new_identity_list(carol); // to carol
    message* outgoing_message = new_message(PEP_dir_outgoing);
    ASSERT_NOTNULL(outgoing_message);
    outgoing_message->from = alice;
    outgoing_message->to = to_list;
    outgoing_message->shortmsg = strdup("Greetings, humans!");
    outgoing_message->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_message->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
//    outgoing_message->id = strdup("blahblahyourmama@pep-project.org");
    outgoing_message->references = new_stringlist("one-839274982347239847@pep-project.org");
    stringlist_add(outgoing_message->references, "two-dfddffd839274982347239847@pep-project.org");
    stringlist_add(outgoing_message->references, "three-OMGWTFBBQ.edfddffd839274982347239847@pep-project.org");

    output_stream << "message created.\n";

    char* encoded_text = nullptr;
    status = mime_encode_message(outgoing_message, false, &encoded_text, false);
    ASSERT_OK;
    ASSERT_NOTNULL(encoded_text);

    output_stream << "unencrypted:\n\n";
    output_stream << encoded_text << "\n";

    free(encoded_text);

    output_stream << "encrypting message as MIME multipart…\n";
    message* encrypted_msg = nullptr;
    output_stream << "calling encrypt_message\n";
    status = encrypt_message(session, outgoing_message, NULL,
        &encrypted_msg, PEP_enc_PGP_MIME, 0);
    output_stream << "encrypt_message() returns " << tl_status_string(status) << '.' << endl;
    ASSERT_OK;
    ASSERT_NOTNULL(encrypted_msg);
    output_stream << "message encrypted.\n";

    encrypted_msg->enc_format = PEP_enc_none;
    status = mime_encode_message(encrypted_msg, false, &encoded_text, false);
    ASSERT_OK;
    ASSERT_NOTNULL(encoded_text);

    output_stream << "encrypted:\n\n";
    output_stream << encoded_text << "\n";

    char* decrypted_text;

    message* decrypted_msg = nullptr;
    stringlist_t* keylist_used = nullptr;

    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

//    MIME_decrypt_message(session, encoded_text, strlen(encoded_text), &decrypted_text, &keylist_used, &rating, &flags);

//    output_stream << "HEY!" << endl;
//    output_stream << decrypted_text << endl;

    message* decoded_msg = nullptr;
    status = mime_decode_message(encoded_text, strlen(encoded_text), &decoded_msg, NULL);
    ASSERT_OK;
    const string string3 = encoded_text;

    unlink("tmp/msg_2.0.asc");
    ofstream outFile3("tmp/msg_2.0.asc");
    outFile3.write(string3.c_str(), string3.size());
    outFile3.close();

    // message* decrypted_msg = nullptr;
    // stringlist_t* keylist_used = nullptr;
    //
    // PEP_rating rating;
    // PEP_decrypt_flags_t flags;
    //
    stringpair_t* autoconsume = new_stringpair("pEp-auto-consume", "yes");
    stringpair_list_add(encrypted_msg->opt_fields, autoconsume);
    flags = 0;
    status = decrypt_message(session, encrypted_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    ASSERT_NOTNULL(decrypted_msg);
    ASSERT_NOTNULL(keylist_used);
    ASSERT_NE(rating, 0);
    //ASSERT_EQ(status == PEP_STATUS_OK && rating , PEP_rating_reliable);
    //PEP_comm_type ct = encrypted_msg->from->comm_type;
    //ASSERT_EQ(ct , PEP_ct_pEp);

    output_stream << "keys used:\n";

    for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next)
    {
       output_stream << "\t " << kl4->value << endl;
    }

    decrypted_msg->enc_format = PEP_enc_none;
    status = mime_encode_message(decrypted_msg, false, &encoded_text, false);
    ASSERT_OK;
    ASSERT_NOTNULL(encoded_text);
    output_stream << "Decrypted message: " << endl;
    output_stream << encoded_text << endl;

    output_stream << "freeing messages…\n";
    free_message(encrypted_msg);
    free_message(decrypted_msg);
    free_message(outgoing_message);
    output_stream << "done.\n";
}
