#include <stdlib.h>
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "TestUtilities.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for AsciiBinary998Test
    class AsciiBinary998Test : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            AsciiBinary998Test() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~AsciiBinary998Test() override {
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
            // Objects declared here can be used by all tests in the AsciiBinary998Test suite.

    };

}  // namespace


TEST_F(AsciiBinary998Test, check_engine_895) {
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* alice = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::ALICE, true, true, true, true, true, true, &alice);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(alice, nullptr);
    status = myself(session, alice);
    char* alicename = strdup(alice->username);

    pEp_identity* alice_is_bob = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::BOB, true, true, true, true, false, true, &alice_is_bob);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(alice_is_bob, nullptr);
    alice_is_bob->user_id = strdup(alice->user_id);
    alice_is_bob->me = true;
    char* bob_key_copy = strdup(alice_is_bob->fpr);

    pEp_identity* alice2 = new_identity(alice->address, NULL, alice->user_id, alice->username);
    pEp_identity* bob = new_identity(alice_is_bob->address, NULL, alice_is_bob->user_id, alice_is_bob->username);
    ASSERT_STRNE(alice->username, alice_is_bob->username);
    char* bobname = strdup(alice_is_bob->username);
    message* cheesy_message = new_message(PEP_dir_outgoing);
    cheesy_message->from = alice2;
    cheesy_message->to = new_identity_list(bob);
    cheesy_message->shortmsg = strdup("This is from Alice, fools.");
    cheesy_message->longmsg = strdup("I am totally not Bob. If I were Bob, I would not be sending messages to myself.");

    int retval = 0;
   
#ifndef WIN32
    struct stat fst;
    retval = stat("test_files/randatt.txt", &fst);
#else
    struct _stat fst;
    retval = _stat("test_files/randatt.txt", &fst);
#endif
   
    ASSERT_EQ(retval, 0);
    size_t data_size = (size_t)(fst.st_size);
    ASSERT_NE(data_size, 0);
    char* data = (char*)calloc(1, data_size);
    char* data_copy = (char*)calloc(1, data_size);
    ifstream data_file("test_files/randatt.txt", ios::in | ios::binary);
   
    data_file.read(data, data_size);
    data_file.close();

    memcpy(data_copy, data, data_size);

    ASSERT_EQ(memcmp(data_copy, data, data_size), 0);

    // First check encrypt and decrypt on their own
    char* ctext = NULL;
    size_t csize = 0;

    stringlist_t* strlist = new_stringlist(alice->fpr);
    stringlist_add(strlist, alice_is_bob->fpr);
    status = encrypt_and_sign(session, strlist, data, data_size, &ctext, &csize);
    ASSERT_OK;
    free_stringlist(strlist);
    strlist = NULL;

    char* ptext = NULL;
    size_t psize = 0;
    status = decrypt_and_verify(session, ctext, csize, NULL, 0, &ptext, &psize, &strlist, NULL);
    ASSERT_EQ(status, PEP_DECRYPTED_AND_VERIFIED);

    ASSERT_EQ(memcmp(ptext, data, data_size), 0);

    cheesy_message->attachments = new_bloblist(data, data_size, "application/octet-stream", "file://randatt.whatever");

    message* enc_msg = NULL;

    status = encrypt_message(session, cheesy_message, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_STREQ(enc_msg->from->username, alicename);
    ASSERT_STREQ(enc_msg->to->ident->username, bobname);

    message* dec_msg = NULL;
    enc_msg->dir = PEP_dir_incoming;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &flags);
    ASSERT_OK;

    ASSERT_EQ(memcmp(data_copy, dec_msg->attachments->value, data_size), 0);
    ASSERT_EQ(data_size, dec_msg->attachments->size);

}

TEST_F(AsciiBinary998Test, check_increasing_attachment_size_mime_encode) {
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* alice = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::ALICE, true, true, true, true, true, true, &alice);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(alice, nullptr);
    status = myself(session, alice);
    char* alicename = strdup(alice->username);

    pEp_identity* alice_is_bob = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::BOB, true, true, true, true, false, true, &alice_is_bob);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(alice_is_bob, nullptr);
    alice_is_bob->user_id = strdup(alice->user_id);
    alice_is_bob->me = true;
    char* bob_key_copy = strdup(alice_is_bob->fpr);

    pEp_identity* alice2 = new_identity(alice->address, NULL, alice->user_id, alice->username);
    pEp_identity* bob = new_identity(alice_is_bob->address, NULL, alice_is_bob->user_id, alice_is_bob->username);
    ASSERT_STRNE(alice->username, alice_is_bob->username);
    char* bobname = strdup(alice_is_bob->username);
    message* cheesy_message = new_message(PEP_dir_outgoing);
    cheesy_message->from = alice2;
    cheesy_message->to = new_identity_list(bob);
    cheesy_message->shortmsg = strdup("This is from Alice, fools.");
    cheesy_message->longmsg = strdup("I am totally not Bob. If I were Bob, I would not be sending messages to myself.");

    string attachment_str = "";

    for (int i = 0; i < 10000; i++) {
        free_bloblist(cheesy_message->attachments);
        cheesy_message->attachments = new_bloblist(strdup(attachment_str.c_str()), i, "application/octet-stream", "random.attachment");
        char* encoded_msg = NULL;
        mime_encode_message(cheesy_message, false, &encoded_msg, false);
        message* decoded_msg = NULL;
        mime_decode_message(encoded_msg, strlen(encoded_msg), &decoded_msg, NULL);
        ASSERT_STREQ(decoded_msg->attachments->value, attachment_str.c_str());
        attachment_str += 'A';
    }
}

TEST_F(AsciiBinary998Test, check_997_strings_in_attachment) {
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* alice = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::ALICE, true, true, true, true, true, true, &alice);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(alice, nullptr);
    status = myself(session, alice);
    char* alicename = strdup(alice->username);

    pEp_identity* alice_is_bob = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::BOB, true, true, true, true, false, true, &alice_is_bob);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(alice_is_bob, nullptr);
    alice_is_bob->user_id = strdup(alice->user_id);
    alice_is_bob->me = true;
    char* bob_key_copy = strdup(alice_is_bob->fpr);

    pEp_identity* alice2 = new_identity(alice->address, NULL, alice->user_id, alice->username);
    pEp_identity* bob = new_identity(alice_is_bob->address, NULL, alice_is_bob->user_id, alice_is_bob->username);
    ASSERT_STRNE(alice->username, alice_is_bob->username);
    char* bobname = strdup(alice_is_bob->username);
    message* cheesy_message = new_message(PEP_dir_outgoing);
    cheesy_message->from = alice2;
    cheesy_message->to = new_identity_list(bob);
    cheesy_message->shortmsg = strdup("This is from Alice, fools.");
    cheesy_message->longmsg = strdup("I am totally not Bob. If I were Bob, I would not be sending messages to myself.");

    string attachment_str = "";

    // Make a bunch of 997 character strings
    string copy_str = "";

    for (int i = 0; i < 998; i++) {
        copy_str += "A";
    }

    for (int i = 0; i < 10; i++)
        attachment_str += copy_str + "\n";

    free_bloblist(cheesy_message->attachments);
    cheesy_message->attachments = new_bloblist(strdup(attachment_str.c_str()), attachment_str.size(), "application/octet-stream", "random.attachment");
    char* encoded_msg = NULL;
    mime_encode_message(cheesy_message, false, &encoded_msg, false);
    cout << encoded_msg;
    message* decoded_msg = NULL;
    mime_decode_message(encoded_msg, strlen(encoded_msg), &decoded_msg, NULL);
    ASSERT_STREQ(decoded_msg->attachments->value, attachment_str.c_str());
}

TEST_F(AsciiBinary998Test, check_big_plaintext_998) {
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* alice = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::ALICE, true, true, true, true, true, true, &alice);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(alice, nullptr);
    status = myself(session, alice);
    char* alicename = strdup(alice->username);

    pEp_identity* alice_is_bob = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::BOB, true, true, true, true, false, true, &alice_is_bob);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(alice_is_bob, nullptr);
    alice_is_bob->user_id = strdup(alice->user_id);
    alice_is_bob->me = true;
    char* bob_key_copy = strdup(alice_is_bob->fpr);

    pEp_identity* alice2 = new_identity(alice->address, NULL, alice->user_id, alice->username);
    pEp_identity* bob = new_identity(alice_is_bob->address, NULL, alice_is_bob->user_id, alice_is_bob->username);
    ASSERT_STRNE(alice->username, alice_is_bob->username);
    char* bobname = strdup(alice_is_bob->username);
    message* cheesy_message = new_message(PEP_dir_outgoing);
    cheesy_message->from = alice2;
    cheesy_message->to = new_identity_list(bob);
    cheesy_message->shortmsg = strdup("This is from Alice, fools.");
    cheesy_message->longmsg = strdup("I am totally not Bob. If I were Bob, I would not be sending messages to myself.");

    string longmsg_str = "";

    for (int i = 0; i < 998; i++) {
        longmsg_str += "K";
    }

    cheesy_message->longmsg = strdup(longmsg_str.c_str());
    char* encoded_msg = NULL;
    mime_encode_message(cheesy_message, false, &encoded_msg, false);
    ASSERT_NE(strstr(encoded_msg, "Content-Transfer-Encoding: 7bit"), nullptr);
}

TEST_F(AsciiBinary998Test, check_big_plaintext_999) {
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* alice = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::ALICE, true, true, true, true, true, true, &alice);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(alice, nullptr);
    status = myself(session, alice);
    char* alicename = strdup(alice->username);

    pEp_identity* alice_is_bob = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::BOB, true, true, true, true, false, true, &alice_is_bob);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(alice_is_bob, nullptr);
    alice_is_bob->user_id = strdup(alice->user_id);
    alice_is_bob->me = true;
    char* bob_key_copy = strdup(alice_is_bob->fpr);

    pEp_identity* alice2 = new_identity(alice->address, NULL, alice->user_id, alice->username);
    pEp_identity* bob = new_identity(alice_is_bob->address, NULL, alice_is_bob->user_id, alice_is_bob->username);
    ASSERT_STRNE(alice->username, alice_is_bob->username);
    char* bobname = strdup(alice_is_bob->username);
    message* cheesy_message = new_message(PEP_dir_outgoing);
    cheesy_message->from = alice2;
    cheesy_message->to = new_identity_list(bob);
    cheesy_message->shortmsg = strdup("This is from Alice, fools.");
    cheesy_message->longmsg = strdup("I am totally not Bob. If I were Bob, I would not be sending messages to myself.");

    string longmsg_str = "";

    for (int i = 0; i < 999; i++) {
        longmsg_str += "K";
    }

    cheesy_message->longmsg = strdup(longmsg_str.c_str());
    char* encoded_msg = NULL;
    mime_encode_message(cheesy_message, false, &encoded_msg, false);
    ASSERT_NE(strstr(encoded_msg, "Content-Transfer-Encoding: quoted-printable"), nullptr);
}


