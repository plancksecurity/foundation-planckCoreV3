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
#include "test_util.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for MessageApiTest
    class MessageApiTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            MessageApiTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~MessageApiTest() override {
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
            // Objects declared here can be used by all tests in the MessageApiTest suite.

    };

}  // namespace


TEST_F(MessageApiTest, check_message_api) {
    output_stream << "Importing Alice's key " << endl;
    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string alice_priv_key = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    const string bob_pub_key = slurp("test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");

    PEP_STATUS status0 = import_key(session, alice_pub_key.c_str(), alice_pub_key.size(), NULL);
    ASSERT_EQ(status0 , PEP_TEST_KEY_IMPORT_SUCCESS);
    status0 = import_key(session, alice_priv_key.c_str(), alice_priv_key.size(), NULL);
    ASSERT_EQ(status0 , PEP_TEST_KEY_IMPORT_SUCCESS);
    status0 = import_key(session, bob_pub_key.c_str(), bob_pub_key.size(), NULL);
    ASSERT_EQ(status0 , PEP_TEST_KEY_IMPORT_SUCCESS);
    // message_api test code

    output_stream << "creating message…\n";
    pEp_identity * me2 = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    // pEp_identity * me2 = new_identity("test@nokey.plop", NULL, PEP_OWN_USERID, "Test no key");
    me2->me = true;
    identity_list *to2 = new_identity_list(new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test"));
    // identity_list *to2 = new_identity_list(new_identity("still@nokey.blup", NULL, "42", "Still no key"));
    message *msg2 = new_message(PEP_dir_outgoing);
    ASSERT_NE(msg2, nullptr);
    msg2->from = me2;
    msg2->to = to2;
    msg2->shortmsg = strdup("hello, world");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    output_stream << "message created.\n";

    char *text2 = nullptr;
    PEP_STATUS status2 = mime_encode_message(msg2, false, &text2, false);
    ASSERT_EQ(status2 , PEP_STATUS_OK);
    ASSERT_NE(text2, nullptr);

    output_stream << "decrypted:\n\n";
    output_stream << text2 << "\n";

    free(text2);

    output_stream << "encrypting message as MIME multipart…\n";
    message *enc_msg2 = nullptr;
    output_stream << "calling encrypt_message()\n";
    status2 = encrypt_message(session, msg2, NULL, &enc_msg2, PEP_enc_PGP_MIME, 0);
    output_stream << "encrypt_message() returns " << status2 << '.' << endl;
    ASSERT_EQ(status2 , PEP_STATUS_OK);
    ASSERT_NE(enc_msg2, nullptr);
    output_stream << "message encrypted.\n";

    status2 = mime_encode_message(enc_msg2, false, &text2, false);
    ASSERT_EQ(status2 , PEP_STATUS_OK);
    ASSERT_NE(text2, nullptr);

    output_stream << "encrypted:\n\n";
    output_stream << text2 << "\n";

    message *msg3 = nullptr;
    PEP_STATUS status3 = mime_decode_message(text2, strlen(text2), &msg3, NULL);
    ASSERT_EQ(status3 , PEP_STATUS_OK);
    const string string3 = text2;
    //free(text2);

    unlink("tmp/msg4.asc");
    ofstream outFile3("tmp/msg4.asc");
    outFile3.write(string3.c_str(), string3.size());
    outFile3.close();

    message *msg4 = nullptr;
    stringlist_t *keylist4 = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;

    flags = 0;
    PEP_STATUS status4 = decrypt_message(session, enc_msg2, &msg4, &keylist4, &rating, &flags);
    ASSERT_EQ(status4 , PEP_STATUS_OK);
    ASSERT_NE(msg4, nullptr);
    ASSERT_NE(keylist4, nullptr);
    ASSERT_TRUE(rating);
    PEP_comm_type ct = enc_msg2->from->comm_type;
    ASSERT_TRUE(ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed );

    free_stringpair_list(enc_msg2->opt_fields);
    enc_msg2->opt_fields = NULL;

    output_stream << "keys used:";

    for (stringlist_t* kl4 = keylist4; kl4 && kl4->value; kl4 = kl4->next)
    {
        output_stream << " " << kl4->value;
    }
    output_stream << "\n\n";

    free_stringlist(keylist4);

    output_stream << "opening msg_no_key.asc for reading\n";
    ifstream inFile3 ("test_mails/msg_no_key.asc");
    ASSERT_TRUE(inFile3.is_open());

    string text3;

    output_stream << "reading msg_no_key.asc sample\n";
    while (!inFile3.eof()) {
        static string line;
        getline(inFile3, line);
        text3 += line + "\r\n";
    }
    inFile3.close();

    message *msg5 = nullptr;
    PEP_STATUS status5 = mime_decode_message(text3.c_str(), text3.length(), &msg5, NULL);
    ASSERT_EQ(status5 , PEP_STATUS_OK);

    message *msg6 = nullptr;
    stringlist_t *keylist5 = nullptr;
    PEP_rating rating2;
    PEP_decrypt_flags_t flags2;
    flags2 = 0;
    PEP_STATUS status6 = decrypt_message(session, msg5, &msg6, &keylist5, &rating2, &flags2);
    ASSERT_EQ(status6 , PEP_DECRYPT_NO_KEY);
    ASSERT_EQ(msg6 , nullptr);
    ASSERT_EQ(keylist5 , nullptr);
    ASSERT_EQ(rating2 , PEP_rating_have_no_key);
    output_stream << "rating :" << rating2 << "\n";
    free_stringlist(keylist5);

    output_stream << "\nTesting MIME_encrypt_message / MIME_decrypt_message...\n\n";

    output_stream << "opening alice_bob_encrypt_test_plaintext_mime.eml for reading\n";
    ifstream inFile4 ("test_mails/alice_bob_encrypt_test_plaintext_mime.eml");
    ASSERT_TRUE(inFile4.is_open());

    string text4;

    output_stream << "reading alice_bob_encrypt_test_plaintext_mime.eml sample\n";
    while (!inFile4.eof()) {
        static string line;
        getline(inFile4, line);
        text4 += line + "\r\n";
    }
    inFile4.close();

    const char* out_msg_plain = text4.c_str();

//    const char* out_msg_plain = "From: krista@kgrothoff.org\nTo: Volker <vb@pep-project.org>\nSubject: Test\nContent-Type: text/plain; charset=utf-8\nContent-Language: en-US\nContent-Transfer-Encoding:quoted-printable\n\ngaga\n\n";
    char* enc_msg = NULL;
    char* dec_msg = NULL;

    PEP_STATUS status7 = MIME_encrypt_message(session, text4.c_str(), text4.length(), NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
//    PEP_STATUS status7 = MIME_encrypt_message(session, out_msg_plain, strlen(out_msg_plain), NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status7 , PEP_STATUS_OK);

    output_stream << enc_msg << endl;

    string text5 = enc_msg;

    PEP_decrypt_flags_t dec_flags;
    stringlist_t* keys_used;

    dec_flags = 0;
    char* modified_src = NULL;
    PEP_STATUS status8 = MIME_decrypt_message(session, text5.c_str(), text5.length(), &dec_msg, &keys_used, &rating, &dec_flags, &modified_src);
    ASSERT_EQ(status8 , PEP_STATUS_OK);

    output_stream << dec_msg << endl;

    output_stream << "\nTesting encrypt_message() with enc_format = PEP_enc_none\n\n";

    message *msg7 = new_message(PEP_dir_outgoing);
    pEp_identity * me7 = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    identity_list *to7 = new_identity_list(new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test"));
    msg7->from = me7;
    msg7->to = to7;
    msg7->shortmsg = strdup("My Subject");
    msg7->longmsg = strdup("This is some text.\n");

    message *enc7 = nullptr;
    PEP_STATUS status9 = encrypt_message(session, msg7, NULL, &enc7, PEP_enc_none, 0);
	output_stream << "encrypt_message returned " << std::dec << status9 << std::hex << " (0x" << status9 << ")" << std::dec << endl;
    ASSERT_EQ(status9 , PEP_UNENCRYPTED);
    ASSERT_EQ(enc7 , nullptr);
    ASSERT_TRUE(msg7->shortmsg && msg7->longmsg);
    output_stream << msg7->shortmsg << "\n";
    output_stream << msg7->longmsg << "\n";
    ASSERT_STREQ(msg7->shortmsg, "My Subject");
    ASSERT_STREQ(msg7->longmsg, "This is some text.\n");

    output_stream << "\nfreeing messages…\n";
    free_message(msg7);
    free_message(msg6);
    free_message(msg5);
    free_message(msg4);
    free_message(msg3);
    free_message(msg2);
    free_message(enc_msg2);
    output_stream << "done.\n";

    free(enc_msg);
    free(dec_msg);
}
