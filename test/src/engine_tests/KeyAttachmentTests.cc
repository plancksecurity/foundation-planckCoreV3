// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <cassert>

#include "pEpEngine.h"
#include "mime.h"

#include <cpptest.h>
#include "test_util.h"
#include "EngineTestIndividualSuite.h"
#include "KeyAttachmentTests.h"

using namespace std;

KeyAttachmentTests::KeyAttachmentTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_key_attachment"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_key_attachment)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_key_attachment"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_key_attachment)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_key_attach_inline"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_key_attach_inline)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_key_plus_encr_att_inline"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_key_plus_encr_att_inline)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_encr_att_plus_key_inline"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_encr_att_plus_key_inline)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_key_plus_unencr_att_inline"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_key_plus_unencr_att_inline)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_unencr_att_plus_key_inline"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_unencr_att_plus_key_inline)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_many_keys_inline"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_many_keys_inline)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_many_keys_w_encr_file_inline"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_many_keys_w_encr_file_inline)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_many_keys_w_unencr_file_inline"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_many_keys_w_unencr_file_inline)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_key_attach_OpenPGP"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_key_attach_OpenPGP)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_key_plus_encr_att_OpenPGP"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_key_plus_encr_att_OpenPGP)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_encr_att_plus_key_OpenPGP"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_encr_att_plus_key_OpenPGP)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_key_plus_unencr_att_OpenPGP"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_key_plus_unencr_att_OpenPGP)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_unencr_att_plus_key_OpenPGP"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_unencr_att_plus_key_OpenPGP)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_many_keys_OpenPGP"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_many_keys_OpenPGP)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_many_keys_w_encr_file_OpenPGP"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_many_keys_w_encr_file_OpenPGP)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_many_keys_w_unencr_file_OpenPGP"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_many_keys_w_unencr_file_OpenPGP)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyAttachmentTests::check_many_keys_w_many_files_OpenPGP"),
                                                                      static_cast<Func>(&KeyAttachmentTests::check_many_keys_w_many_files_OpenPGP)));
}

void KeyAttachmentTests::setup() {
    EngineTestIndividualSuite::setup();
    assert(slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_renewed_pub.asc"));
    assert(slurp_and_import_key(session, "test_keys/priv/inquisitor-0xA4728718_renewed_priv.asc"));
    // accidentally encrypted the encrypted attachment to alice - this really doesn't matter here tbh
    assert(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    assert(slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc"));    
}

void KeyAttachmentTests::check_key_attachment() {
    TEST_ASSERT(true);
}

void KeyAttachmentTests::check_key_attach_inline() {
    string msg = slurp("test_mails/Inline PGP test.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(dec_msg->attachments == NULL, "Decryption left attachments it should have deleted.");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

void KeyAttachmentTests::check_key_plus_encr_att_inline() {
    string msg = slurp("test_mails/Inline PGP test - key then already encr attach.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(dec_msg->attachments, "Encrypted attachment not preserved.");
    TEST_ASSERT_MSG(dec_msg->attachments->next == NULL, "Decryption left attachments it should have deleted.");    
    TEST_ASSERT_MSG(dec_msg->attachments->filename, "Attachment doesn't have a filename");
    // TODO: is there a missing update to resource IDs in decrypt in parts?
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->filename, "cheese.txt.gpg") == 0, dec_msg->attachments->filename);    
    TEST_ASSERT_MSG(dec_msg->attachments->mime_type, "Attachment doesn't have a mime type");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->mime_type, "application/octet-stream") == 0, dec_msg->attachments->mime_type);    
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

void KeyAttachmentTests::check_encr_att_plus_key_inline() {
    TEST_ASSERT(true);
}

void KeyAttachmentTests::check_key_plus_unencr_att_inline() {
    string msg = slurp("test_mails/Inline PGP test - key then not-yet encr attach.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(dec_msg->attachments, "Encrypted attachment not preserved.");
    TEST_ASSERT_MSG(dec_msg->attachments->next == NULL, "Decryption left attachments it should have deleted.");    
    TEST_ASSERT_MSG(dec_msg->attachments->filename, "Attachment doesn't have a filename");
    // TODO: is there a missing update to resource IDs in decrypt in parts?
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->filename, "cheese.txt") == 0, dec_msg->attachments->filename);    
    TEST_ASSERT_MSG(dec_msg->attachments->mime_type, "Attachment doesn't have a mime type");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->mime_type, "application/octet-stream") == 0, dec_msg->attachments->mime_type);    
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

void KeyAttachmentTests::check_unencr_att_plus_key_inline() {
    TEST_ASSERT(true);
}

void KeyAttachmentTests::check_many_keys_inline() {
    string msg = slurp("test_mails/Inline PGP test - many keys.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(dec_msg->attachments == NULL, "Decryption left attachments it should have deleted.");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}
        
void KeyAttachmentTests::check_many_keys_w_encr_file_inline() {
    string msg = slurp("test_mails/Inline PGP test - many keys w_ encr file.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(dec_msg->attachments, "Encrypted attachment not preserved.");
    TEST_ASSERT_MSG(dec_msg->attachments->next == NULL, "Decryption left attachments it should have deleted.");    
    TEST_ASSERT_MSG(dec_msg->attachments->filename, "Attachment doesn't have a filename");
    // TODO: is there a missing update to resource IDs in decrypt in parts?
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->filename, "cheese.txt") == 0, dec_msg->attachments->filename);    
    TEST_ASSERT_MSG(dec_msg->attachments->mime_type, "Attachment doesn't have a mime type");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->mime_type, "application/octet-stream") == 0, dec_msg->attachments->mime_type);    
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}
        
void KeyAttachmentTests::check_many_keys_w_unencr_file_inline() {
    TEST_ASSERT(true);
}

void KeyAttachmentTests::check_key_attach_OpenPGP() {
    string msg = slurp("test_mails/OpenPGP test key attach.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(dec_msg->attachments == NULL, "Decryption left attachments it should have deleted.");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

void KeyAttachmentTests::check_key_plus_encr_att_OpenPGP() {
    string msg = slurp("test_mails/OpenPGP PGP test - key then already encr attach.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(dec_msg->attachments, "Encrypted attachment not preserved.");
    TEST_ASSERT_MSG(dec_msg->attachments->next == NULL, "Decryption left attachments it should have deleted.");    
    TEST_ASSERT_MSG(dec_msg->attachments->filename, "Attachment doesn't have a filename");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->filename, "file://cheese.txt.gpg") == 0, dec_msg->attachments->filename);    
    TEST_ASSERT_MSG(dec_msg->attachments->mime_type, "Attachment doesn't have a mime type");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->mime_type, "application/octet-stream") == 0, dec_msg->attachments->mime_type);    
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

void KeyAttachmentTests::check_encr_att_plus_key_OpenPGP() {
    string msg = slurp("test_mails/OpenPGP PGP test - already encr attach then key.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(dec_msg->attachments, "Encrypted attachment not preserved.");
    TEST_ASSERT_MSG(dec_msg->attachments->next == NULL, "Decryption left attachments it should have deleted.");    
    TEST_ASSERT_MSG(dec_msg->attachments->filename, "Attachment doesn't have a filename");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->filename, "file://cheese.txt.gpg") == 0, dec_msg->attachments->filename);    
    TEST_ASSERT_MSG(dec_msg->attachments->mime_type, "Attachment doesn't have a mime type");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->mime_type, "application/octet-stream") == 0, dec_msg->attachments->mime_type);    
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}


void KeyAttachmentTests::check_key_plus_unencr_att_OpenPGP() {
    string msg = slurp("test_mails/OpenPGP PGP test - key then not-yet encr attach.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(dec_msg->attachments, "Encrypted attachment not preserved.");
    TEST_ASSERT_MSG(dec_msg->attachments->next == NULL, "Decryption left attachments it should have deleted.");    
    TEST_ASSERT_MSG(dec_msg->attachments->filename, "Attachment doesn't have a filename");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->filename, "file://cheese.txt") == 0, dec_msg->attachments->filename);    
    TEST_ASSERT_MSG(dec_msg->attachments->mime_type, "Attachment doesn't have a mime type");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->mime_type, "text/plain") == 0, dec_msg->attachments->mime_type);    
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}
 
void KeyAttachmentTests::check_unencr_att_plus_key_OpenPGP() {
    string msg = slurp("test_mails/OpenPGP PGP test - not-yet encr attach then key.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(dec_msg->attachments, "Encrypted attachment not preserved.");
    TEST_ASSERT_MSG(dec_msg->attachments->next == NULL, "Decryption left attachments it should have deleted.");    
    TEST_ASSERT_MSG(dec_msg->attachments->filename, "Attachment doesn't have a filename");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->filename, "file://cheese.txt") == 0, dec_msg->attachments->filename);    
    TEST_ASSERT_MSG(dec_msg->attachments->mime_type, "Attachment doesn't have a mime type");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->mime_type, "text/plain") == 0, dec_msg->attachments->mime_type);    
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}
 
void KeyAttachmentTests::check_many_keys_OpenPGP() {
    string msg = slurp("test_mails/OpenPGP PGP test - many keys.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(!dec_msg->attachments, "Not all keys removed.");
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

void KeyAttachmentTests::check_many_keys_w_encr_file_OpenPGP() {
    string msg = slurp("test_mails/OpenPGP PGP test - many keys enc file in middle.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(dec_msg->attachments, "Encrypted attachment not preserved.");
    TEST_ASSERT_MSG(dec_msg->attachments->next == NULL, "Decryption left attachments it should have deleted.");    
    TEST_ASSERT_MSG(dec_msg->attachments->filename, "Attachment doesn't have a filename");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->filename, "file://cheese.txt.gpg") == 0, dec_msg->attachments->filename);    
    TEST_ASSERT_MSG(dec_msg->attachments->mime_type, "Attachment doesn't have a mime type");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->mime_type, "application/octet-stream") == 0, dec_msg->attachments->mime_type);    
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}

void KeyAttachmentTests::check_many_keys_w_unencr_file_OpenPGP() {
    string msg = slurp("test_mails/OpenPGP PGP test - not-yet encr attach then key.eml");
    message* enc_msg = NULL;
    message* dec_msg = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &enc_msg);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(enc_msg);
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));    
    TEST_ASSERT(dec_msg);
    TEST_ASSERT_MSG(dec_msg->attachments, "Encrypted attachment not preserved.");
    TEST_ASSERT_MSG(dec_msg->attachments->next == NULL, "Decryption left attachments it should have deleted.");    
    TEST_ASSERT_MSG(dec_msg->attachments->filename, "Attachment doesn't have a filename");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->filename, "file://cheese.txt") == 0, dec_msg->attachments->filename);    
    TEST_ASSERT_MSG(dec_msg->attachments->mime_type, "Attachment doesn't have a mime type");
    TEST_ASSERT_MSG(strcmp(dec_msg->attachments->mime_type, "text/plain") == 0, dec_msg->attachments->mime_type);    
    free_message(enc_msg);
    free_message(dec_msg);
    free_stringlist(keylist);
}
         
void KeyAttachmentTests::check_many_keys_w_many_files_OpenPGP() {
    TEST_ASSERT(true);
}
