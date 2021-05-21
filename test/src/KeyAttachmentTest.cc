// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cstring>
#include <vector>
#include <utility>
#include <cassert>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "mime.h"

#include "test_util.h"


#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for KeyAttachmentTest
    class KeyAttachmentTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            KeyAttachmentTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~KeyAttachmentTest() override {
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
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc"));
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/priv/inquisitor-0xA4728718_renewed_priv.asc"));
                // accidentally encrypted the encrypted attachment to alice - this really doesn't matter here tbh
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc"));                
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
            // Objects declared here can be used by all tests in the KeyAttachmentTest suite.

    };

}  // namespace


TEST_F(KeyAttachmentTest, check_key_attach_inline) {
    string msg = slurp("test_mails/Inline PGP test.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_DECRYPTED);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_EQ(dec_msg->attachments , nullptr);
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_key_plus_encr_att_inline) {
    string msg = slurp("test_mails/Inline PGP test - key then already encr attach.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_DECRYPTED);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(dec_msg->attachments, nullptr);
    ASSERT_EQ(dec_msg->attachments->next , nullptr);
    ASSERT_NE(dec_msg->attachments->filename, nullptr);
    // TODO: is there a missing update to resource IDs in decrypt in parts?
    ASSERT_STREQ(dec_msg->attachments->filename, "file://cheese.txt.gpg");
    ASSERT_NE(dec_msg->attachments->mime_type, nullptr);
    ASSERT_STREQ(dec_msg->attachments->mime_type, "application/octet-stream");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_encr_att_plus_key_inline) {
    string msg = slurp("test_mails/Inline PGP Test - encr file then key.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(dec_msg->attachments, nullptr);
    ASSERT_EQ(dec_msg->attachments->next , nullptr);
    ASSERT_NE(dec_msg->attachments->filename, nullptr);
    // TODO: is there a missing update to resource IDs in decrypt in parts?
    ASSERT_STREQ(dec_msg->attachments->filename, "file://cheese.txt.gpg");
    ASSERT_NE(dec_msg->attachments->mime_type, nullptr);
    ASSERT_STREQ(dec_msg->attachments->mime_type, "application/octet-stream");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_key_plus_unencr_att_inline) {
    string msg = slurp("test_mails/Inline PGP test - key then not-yet encr attach.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_DECRYPTED);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(dec_msg->attachments, nullptr);
    ASSERT_EQ(dec_msg->attachments->next , nullptr);
    ASSERT_NE(dec_msg->attachments->filename, nullptr);
    // TODO: is there a missing update to resource IDs in decrypt in parts?
    ASSERT_STREQ(dec_msg->attachments->filename, "file://cheese.txt");
    ASSERT_NE(dec_msg->attachments->mime_type, nullptr);
    ASSERT_STREQ(dec_msg->attachments->mime_type, "application/octet-stream");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_unencr_att_plus_key_inline) {
    string msg = slurp("test_mails/Inline PGP Test - unencr file then key.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(dec_msg->attachments, nullptr);
    ASSERT_EQ(dec_msg->attachments->next , nullptr);
    ASSERT_NE(dec_msg->attachments->filename, nullptr);
    // TODO: is there a missing update to resource IDs in decrypt in parts?
    ASSERT_STREQ(dec_msg->attachments->filename, "file://cheese.txt");
    ASSERT_NE(dec_msg->attachments->mime_type, nullptr);
    ASSERT_STREQ(dec_msg->attachments->mime_type, "application/octet-stream");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

// Inline PGP - many keys with many files.eml
// OpenPGP test - many keys and many files.eml


TEST_F(KeyAttachmentTest, check_many_keys_inline) {
    string msg = slurp("test_mails/Inline PGP test - many keys.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_DECRYPTED);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_EQ(dec_msg->attachments , nullptr);
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_many_keys_w_encr_file_inline) {
    string msg = slurp("test_mails/Inline PGP test - many keys w_ encr file.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(dec_msg->attachments, nullptr);
    ASSERT_EQ(dec_msg->attachments->next , nullptr);
    ASSERT_NE(dec_msg->attachments->filename, nullptr);
    // TODO: is there a missing update to resource IDs in decrypt in parts?
    ASSERT_STREQ(dec_msg->attachments->filename, "file://cheese.txt.gpg");
    ASSERT_NE(dec_msg->attachments->mime_type, nullptr);
    ASSERT_STREQ(dec_msg->attachments->mime_type, "application/octet-stream");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_many_keys_w_unencr_file_inline) {
    string msg = slurp("test_mails/Inline PGP Test - many keys unencr file in middle.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(dec_msg->attachments, nullptr);
    ASSERT_EQ(dec_msg->attachments->next , nullptr);
    ASSERT_NE(dec_msg->attachments->filename, nullptr);
    // TODO: is there a missing update to resource IDs in decrypt in parts?
    ASSERT_STREQ(dec_msg->attachments->filename, "file://barky.txt");
    ASSERT_NE(dec_msg->attachments->mime_type, nullptr);
    ASSERT_STREQ(dec_msg->attachments->mime_type, "application/octet-stream");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_many_keys_with_many_files_inline) {
    string msg = slurp("test_mails/Inline PGP - many keys with many files.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg, nullptr);

    const char* not_pres = "Encrypted attachment not preserved.";
    const char* left_att = "Decryption left attachments it should have deleted.";
    const char* no_fname = "Attachment doesn't have a filename.";
    const char* no_mime = "Attachment doesn't have a MIME type.";

    // pair is filename, mime_type
    vector<pair<string,string>> v =
        {
            {"file://barky.txt","application/octet-stream"},
            {"file://this_is_not_a_key_or_encrypted.asc","application/octet-stream"},
            {"file://this_is_not_a_key_or_encrypted.gpg","application/octet-stream"},
            {"file://CC_BY-SA.txt","application/octet-stream"},
            {"file://Makefile","application/octet-stream"},
            {"file://LICENSE.txt","application/octet-stream"},
            {"file://README.md","application/octet-stream"},
        };

    bloblist_t* curr_att = dec_msg->attachments;
    vector<pair<string,string>>::iterator it = v.begin();

    while (it != v.end()) {
        ASSERT_NE(curr_att, nullptr);
        ASSERT_NE(curr_att->filename, nullptr);
        ASSERT_NE(curr_att->mime_type, nullptr);
        output_stream << (*it).first << endl;
        ASSERT_STREQ(curr_att->filename, (*it).first.c_str());
        ASSERT_STREQ(curr_att->mime_type, (*it).second.c_str());
        it++;
        curr_att = curr_att->next;
    }

    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_key_attach_OpenPGP) {
    string msg = slurp("test_mails/OpenPGP test key attach.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_EQ(dec_msg->attachments , nullptr);
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_key_plus_encr_att_OpenPGP) {
    string msg = slurp("test_mails/OpenPGP PGP test - key then already encr attach.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_DECRYPTED);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(dec_msg->attachments, nullptr);
    ASSERT_EQ(dec_msg->attachments->next , nullptr);
    ASSERT_NE(dec_msg->attachments->filename, nullptr);
    ASSERT_STREQ(dec_msg->attachments->filename, "file://cheese.txt.gpg");
    ASSERT_NE(dec_msg->attachments->mime_type, nullptr);
    ASSERT_STREQ(dec_msg->attachments->mime_type, "application/octet-stream");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_encr_att_plus_key_OpenPGP) {
    string msg = slurp("test_mails/OpenPGP PGP test - already encr attach then key.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_DECRYPTED);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(dec_msg->attachments, nullptr);
    ASSERT_EQ(dec_msg->attachments->next , nullptr);
    ASSERT_NE(dec_msg->attachments->filename, nullptr);
    ASSERT_STREQ(dec_msg->attachments->filename, "file://cheese.txt.gpg");
    ASSERT_NE(dec_msg->attachments->mime_type, nullptr);
    ASSERT_STREQ(dec_msg->attachments->mime_type, "application/octet-stream");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}


TEST_F(KeyAttachmentTest, check_key_plus_unencr_att_OpenPGP) {
    string msg = slurp("test_mails/OpenPGP PGP test - key then not-yet encr attach.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(dec_msg->attachments, nullptr);
    ASSERT_EQ(dec_msg->attachments->next , nullptr);
    ASSERT_NE(dec_msg->attachments->filename, nullptr);
    ASSERT_STREQ(dec_msg->attachments->filename, "file://cheese.txt");
    ASSERT_NE(dec_msg->attachments->mime_type, nullptr);
    ASSERT_STREQ(dec_msg->attachments->mime_type, "text/plain");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_unencr_att_plus_key_OpenPGP) {
    string msg = slurp("test_mails/OpenPGP PGP test - not-yet encr attach then key.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_DECRYPTED);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(dec_msg->attachments, nullptr);
    ASSERT_EQ(dec_msg->attachments->next , nullptr);
    ASSERT_NE(dec_msg->attachments->filename, nullptr);
    ASSERT_STREQ(dec_msg->attachments->filename, "file://cheese.txt");
    ASSERT_NE(dec_msg->attachments->mime_type, nullptr);
    ASSERT_STREQ(dec_msg->attachments->mime_type, "text/plain");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_many_keys_OpenPGP) {
    string msg = slurp("test_mails/OpenPGP PGP test - many keys.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_DECRYPTED);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_EQ(dec_msg->attachments, nullptr);
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_many_keys_w_encr_file_OpenPGP) {
    string msg = slurp("test_mails/OpenPGP PGP test - many keys enc file in middle.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_DECRYPTED);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(dec_msg->attachments, nullptr);
    ASSERT_EQ(dec_msg->attachments->next , nullptr);
    ASSERT_NE(dec_msg->attachments->filename, nullptr);
    ASSERT_STREQ(dec_msg->attachments->filename, "file://cheese.txt.gpg");
    ASSERT_NE(dec_msg->attachments->mime_type, nullptr);
    ASSERT_STREQ(dec_msg->attachments->mime_type, "application/octet-stream");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_many_keys_w_unencr_file_OpenPGP) {
    string msg = slurp("test_mails/OpenPGP PGP test - not-yet encr attach then key.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_DECRYPTED);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(dec_msg->attachments, nullptr);
    ASSERT_EQ(dec_msg->attachments->next , nullptr);
    ASSERT_NE(dec_msg->attachments->filename, nullptr);
    ASSERT_STREQ(dec_msg->attachments->filename, "file://cheese.txt");
    ASSERT_NE(dec_msg->attachments->mime_type, nullptr);
    ASSERT_STREQ(dec_msg->attachments->mime_type, "text/plain");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

TEST_F(KeyAttachmentTest, check_many_keys_w_many_files_OpenPGP) {
    string msg = slurp("test_mails/OpenPGP test - many keys and many files.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg, nullptr);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg, nullptr);

    const char* not_pres = "Encrypted attachment not preserved.";
    const char* left_att = "Decryption left attachments it should have deleted.";
    const char* no_fname = "Attachment doesn't have a filename.";
    const char* no_mime = "Attachment doesn't have a MIME type.";

    // pair is filename, mime_type
    vector<pair<string,string>> v =
        {
            {"file://index.html","text/html"},
            {"file://barky.txt","text/plain"},
            {"file://cheese.txt.gpg","application/octet-stream"},
            {"file://this_is_not_a_key_or_encrypted.asc","text/plain"},
            {"file://this_is_not_a_key_or_encrypted.gpg","text/plain"},
            {"file://cheese.txt","text/plain"}
        };

    bloblist_t* curr_att = dec_msg->attachments;
    vector<pair<string,string>>::iterator it = v.begin();

    while (it != v.end()) {
        ASSERT_NE(curr_att, nullptr);
        ASSERT_NE(curr_att->filename, nullptr);
        ASSERT_NE(curr_att->mime_type, nullptr);
        ASSERT_STREQ(curr_att->filename, (*it).first.c_str());
        ASSERT_STREQ(curr_att->mime_type, (*it).second.c_str());
        it++;
        curr_att = curr_att->next;
    }

    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}
