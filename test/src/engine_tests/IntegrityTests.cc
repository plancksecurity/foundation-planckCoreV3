// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <assert.h>
#include <unistd.h>

#include "pEpEngine.h"
#include "message_api.h"

#include "test_util.h"

#include "EngineTestIndividualSuite.h"
#include "IntegrityTests.h"

using namespace std;

IntegrityTests::IntegrityTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    recip_fpr = "9D8047989841CF4207EA152A4ACAF735F390A40D";
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_unsigned_PGP_MIME"),
                                                                      static_cast<Func>(&IntegrityTests::check_unsigned_PGP_MIME)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_unsigned_PGP_MIME_attached_key"),
                                                                      static_cast<Func>(&IntegrityTests::check_unsigned_PGP_MIME_attached_key)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_unsigned_PGP_MIME_w_render_flag"),
                                                                      static_cast<Func>(&IntegrityTests::check_unsigned_PGP_MIME_w_render_flag)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_known_good_signed_PGP_MIME"),
                                                                      static_cast<Func>(&IntegrityTests::check_known_good_signed_PGP_MIME)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_known_good_signed_PGP_MIME_attached_key"),
                                                                      static_cast<Func>(&IntegrityTests::check_known_good_signed_PGP_MIME_attached_key)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_unknown_signed_PGP_MIME_no_key"),
                                                                      static_cast<Func>(&IntegrityTests::check_unknown_signed_PGP_MIME_no_key)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_unknown_signed_PGP_MIME_attached_key"),
                                                                      static_cast<Func>(&IntegrityTests::check_unknown_signed_PGP_MIME_attached_key)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_unsigned_PGP_MIME_corrupted"),
                                                                      static_cast<Func>(&IntegrityTests::check_unsigned_PGP_MIME_corrupted)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_signed_PGP_MIME_corrupted"),
                                                                      static_cast<Func>(&IntegrityTests::check_signed_PGP_MIME_corrupted)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_unsigned_2_0"),
                                                                      static_cast<Func>(&IntegrityTests::check_unsigned_2_0)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_unknown_signed_2_0_no_key"),
                                                                      static_cast<Func>(&IntegrityTests::check_unknown_signed_2_0_no_key)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_unknown_signed_2_0_no_key_known_signer"),
                                                                      static_cast<Func>(&IntegrityTests::check_unknown_signed_2_0_no_key_known_signer)));                                                                                                                                        
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_unknown_signed_2_0_key_attached"),
                                                                      static_cast<Func>(&IntegrityTests::check_unknown_signed_2_0_key_attached)));  
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IntegrityTests::check_integrity"),
                                                                      static_cast<Func>(&IntegrityTests::check_integrity)));
}

void IntegrityTests::setup() {
    EngineTestIndividualSuite::setup();
    string recip_key = slurp("test_keys/pub/integrity_test_recip_0-0xF390A40D_pub.asc");
    PEP_STATUS status = import_key(session, recip_key.c_str(), recip_key.size(), NULL);
    assert(status == PEP_STATUS_OK);
    recip_key = "";
    string priv_key = slurp("test_keys/priv/integrity_test_recip_0-0xF390A40D_priv.asc");
    cout << priv_key << endl;
    cout << "GNUPGHOME is " << getenv("GNUPGHOME") << endl;
    status = import_key(session, priv_key.c_str(), priv_key.size(), NULL);
    assert(status == PEP_STATUS_OK);
    stringlist_t* debug_keylist = NULL;
    status = find_private_keys(session, recip_fpr, &debug_keylist);
    assert(debug_keylist);
    
    pEp_identity* me = new_identity("integrity_test_recip@darthmama.org", recip_fpr, PEP_OWN_USERID, "Integrity Test Recipient");
    assert(me != NULL);
    status = set_own_key(session, me, recip_fpr);
    assert(status == PEP_STATUS_OK);

    message = "";
    decrypted_msg = NULL;
    decrypt_status = PEP_STATUS_OK;
    rating = PEP_rating_undefined;
    flags = 0;
    keylist = NULL;
    dummy_ignore = NULL;
}

void IntegrityTests::tear_down() {
    free_stringlist(keylist);
    free(decrypted_msg);
    EngineTestIndividualSuite::tear_down();
}

/*
Type            Error State             Render              Status Code
---------------------------------------------------------------------------------------------------------------
inline          ALL                     Yes, if present     Whatever GPG gives us
PGP/MIME        Unsigned                No                  DECRYPTED_BUT_UNSIGNED (grey)
                Signed, no key          Yes                 NO_KEY_FOR_SIGNER
                Bad sig                 No                  SIGNATURE_DOES_NOT_MATCH
Message 1.0     Unsigned                No                  MODIFICATION_DETECTED
                Signed, no key          No                  MODIFICATION_DETECTED
                Bad sig                 No                  SIGNATURE_DOES_NOT_MATCH
Message 2.0     Unsigned                No                  MODIFICATION_DETECTED (red)
                Signed, no key          No                  MODIFICATION_DETECTED  (red)
                Bad sig                 No                  SIGNATURE_DOES_NOT_MATCH

*/

void IntegrityTests::check_known_good_signed_PGP_MIME() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/Signed no attach PGP_MIME.eml", message,
                                             "test_keys/pub/integrity_test_signer_0-0xFF26631A_pub.asc"));

    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_STATUS_OK", tl_status_string(decrypt_status));
    TEST_ASSERT_MSG(decrypt_status == PEP_STATUS_OK, failed_msg_buf);
    TEST_ASSERT(decrypted_msg != NULL);
    TEST_ASSERT(rating == PEP_rating_reliable);
}

void IntegrityTests::check_known_good_signed_PGP_MIME_attached_key() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/Signed attached key PGP_MIME.eml", message,
                                             NULL));

    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_STATUS_OK", tl_status_string(decrypt_status));
    TEST_ASSERT_MSG(decrypt_status == PEP_STATUS_OK, failed_msg_buf);
    TEST_ASSERT(decrypted_msg != NULL);
    TEST_ASSERT(rating == PEP_rating_reliable);
}

void IntegrityTests::check_unsigned_PGP_MIME() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/Unsigned from PGP_MIME_noattach.eml", message,
                                             "test_keys/pub/integrity_test_signer_0-0xFF26631A_pub.asc"));

    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_DECRYPTED_BUT_UNSIGNED", tl_status_string(decrypt_status));
    TEST_ASSERT_MSG(decrypt_status == PEP_DECRYPTED_BUT_UNSIGNED, failed_msg_buf);
    TEST_ASSERT(decrypted_msg == NULL);
    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Rating == %s, should be PEP_rating_unreliable", tl_rating_string(rating));
    TEST_ASSERT_MSG(rating == PEP_rating_unreliable, failed_msg_buf);
}

void IntegrityTests::check_unsigned_PGP_MIME_attached_key() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/Unsigned from PGP_MIME_attach.eml", message,
                                             NULL));

    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_DECRYPTED_BUT_UNSIGNED", tl_status_string(decrypt_status));
    TEST_ASSERT_MSG(decrypt_status == PEP_DECRYPTED_BUT_UNSIGNED, failed_msg_buf);
    TEST_ASSERT(decrypted_msg == NULL);
    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Rating == %s, should be PEP_rating_unreliable", tl_rating_string(rating));
    TEST_ASSERT_MSG(rating == PEP_rating_unreliable, failed_msg_buf);
}

void IntegrityTests::check_unsigned_PGP_MIME_w_render_flag() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/Unsigned from PGP_MIME_noattach.eml", message,
                                             "test_keys/pub/integrity_test_signer_0-0xFF26631A_pub.asc"));
    flags |= PEP_decrypt_deliver_pgpmime_badsigned;
    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_DECRYPTED_BUT_UNSIGNED", tl_status_string(decrypt_status));
    TEST_ASSERT_MSG(decrypt_status == PEP_DECRYPTED_BUT_UNSIGNED, failed_msg_buf);
    TEST_ASSERT(decrypted_msg != NULL);
    TEST_ASSERT(rating == PEP_rating_unreliable);
}


void IntegrityTests::check_unknown_signed_PGP_MIME_no_key() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/Signed PGP_MIME by unknown signer no attach.eml", message,
                                             NULL));
    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_DECRYPT_NO_KEY_FOR_SIGNER", tl_status_string(decrypt_status));
    TEST_ASSERT_MSG(decrypt_status == PEP_DECRYPT_NO_KEY_FOR_SIGNER, failed_msg_buf);
    TEST_ASSERT(decrypted_msg != NULL);
    TEST_ASSERT(rating == PEP_rating_unreliable);
}

void IntegrityTests::check_unknown_signed_PGP_MIME_attached_key() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/Signed PGP_MIME by unknown signer attach.eml", message,
                                             NULL));

    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_STATUS_OK", tl_status_string(decrypt_status));
    TEST_ASSERT_MSG(decrypt_status == PEP_STATUS_OK, failed_msg_buf);
    TEST_ASSERT(decrypted_msg != NULL);
    TEST_ASSERT(rating == PEP_rating_reliable);
}

// FIXME: we need cleverer attacked mails
void IntegrityTests::check_unsigned_PGP_MIME_corrupted() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/Unsigned from PGP_MIME_attach_corrupted.eml", message,
                                             NULL));

    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

//    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_STATUS_OK", tl_status_string(decrypt_status));
//    TEST_ASSERT_MSG(decrypt_status == PEP_STATUS_OK, failed_msg_buf);
    TEST_ASSERT(decrypt_status != PEP_STATUS_OK && decrypt_status != PEP_DECRYPTED);
    TEST_ASSERT(decrypted_msg == NULL);
}

void IntegrityTests::check_signed_PGP_MIME_corrupted() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/Signed attached key PGP_MIME_corrupted.eml", message,
                                             NULL));

    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

//    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_STATUS_OK", tl_status_string(decrypt_status));
//    TEST_ASSERT_MSG(decrypt_status == PEP_STATUS_OK, failed_msg_buf);
    TEST_ASSERT(decrypt_status != PEP_STATUS_OK && decrypt_status != PEP_DECRYPTED);
    TEST_ASSERT(decrypted_msg == NULL);
}

void IntegrityTests::check_unsigned_2_0() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/fake_2.0_unsigned.eml", message,
                                             NULL));
    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_DECRYPT_MODIFICATION_DETECTED", tl_status_string(decrypt_status));
    TEST_ASSERT_MSG(decrypt_status == PEP_DECRYPT_MODIFICATION_DETECTED, failed_msg_buf);
    TEST_ASSERT(decrypted_msg == NULL);
    TEST_ASSERT(rating == PEP_rating_under_attack);
}

void IntegrityTests::check_unknown_signed_2_0_no_key() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/fake_2.0_signed_no_key_attached.eml", message,
                                             NULL));
    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_DECRYPT_MODIFICATION_DETECTED", tl_status_string(decrypt_status));
    TEST_ASSERT_MSG(decrypt_status == PEP_DECRYPT_MODIFICATION_DETECTED, failed_msg_buf);
    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypted msg should have been NULL, but starts with %s", decrypted_msg);
    TEST_ASSERT_MSG(decrypted_msg == NULL, failed_msg_buf);
    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Rating == %s, should be PEP_rating_under_attack", tl_rating_string(rating));
    TEST_ASSERT_MSG(rating == PEP_rating_under_attack, failed_msg_buf);
}

void IntegrityTests::check_unknown_signed_2_0_no_key_known_signer() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/fake_2.0_signed_no_key_attached.eml", message,
                                             "test_keys/pub/integrity_test_signer_0-0xFF26631A_pub.asc"));
    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_DECRYPT_MODIFICATION_DETECTED", tl_status_string(decrypt_status));
    TEST_ASSERT_MSG(decrypt_status == PEP_DECRYPT_MODIFICATION_DETECTED, failed_msg_buf);
    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypted msg should have been NULL, but starts with %s", decrypted_msg);
    TEST_ASSERT_MSG(decrypted_msg == NULL, failed_msg_buf);
    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Rating == %s, should be PEP_rating_under_attack", tl_rating_string(rating));
    TEST_ASSERT_MSG(rating == PEP_rating_under_attack, failed_msg_buf);
}


void IntegrityTests::check_unknown_signed_2_0_key_attached() {
    TEST_ASSERT(slurp_message_and_import_key(session, "test_mails/fake_2.0_good.eml", message,
                                             NULL));
    decrypt_status = MIME_decrypt_message(session, message.c_str(), message.size(), &decrypted_msg, &keylist,
                                          &rating, &flags, &dummy_ignore);

    snprintf(failed_msg_buf, TEST_FAILED_MESSAGE_BUFSIZE, "Decrypt status == %s, should be PEP_STATUS_OK", tl_status_string(decrypt_status));
    TEST_ASSERT_MSG(decrypt_status == PEP_STATUS_OK, failed_msg_buf);
    TEST_ASSERT(decrypted_msg != NULL);
    TEST_ASSERT(rating == PEP_rating_reliable);
}


void IntegrityTests::check_integrity() {
    TEST_ASSERT(true);
}
