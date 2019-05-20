// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <cpptest.h>
#include <fstream>

#include "pEpEngine.h"

#include "test_util.h"
#include "EngineTestIndividualSuite.h"
#include "VerifyTests.h"

using namespace std;

VerifyTests::VerifyTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("VerifyTests::check_revoked_tpk"),
                                                                      static_cast<Func>(&VerifyTests::check_revoked_tpk)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("VerifyTests::check_revoked_signing_key"),
                                                                      static_cast<Func>(&VerifyTests::check_revoked_signing_key)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("VerifyTests::check_expired_tpk"),
                                                                      static_cast<Func>(&VerifyTests::check_expired_tpk)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("VerifyTests::check_expired_signing_key"),
                                                                      static_cast<Func>(&VerifyTests::check_expired_signing_key)));
}

void VerifyTests::check_revoked_tpk() {
    slurp_and_import_key(session, "test_keys/priv/pep-test-mary-0x7F59F03CD04A226E_priv.asc");

    string ciphertext = slurp("test_files/pep-test-mary-signed-encrypted-to-self.asc");

    // Decrypt and verify it.
    char *plaintext = NULL;
    size_t plaintext_size = 0;
    stringlist_t *keylist = NULL;
    PEP_STATUS status = decrypt_and_verify(session,
                                           ciphertext.c_str(),
                                           ciphertext.size(),
                                           NULL, 0,
                                           &plaintext, &plaintext_size,
                                           &keylist, NULL);

    TEST_ASSERT_MSG(status == PEP_DECRYPTED_AND_VERIFIED, tl_status_string(status));
    TEST_ASSERT(keylist);
    // Signer is mary.
    TEST_ASSERT(keylist->value);
    cout << "fpr: " << mary_fpr << "; got: " << keylist->value << endl;
    TEST_ASSERT(strcmp(mary_fpr, keylist->value) == 0);
    // Recipient is mary.
    TEST_ASSERT(keylist->next);
    TEST_ASSERT(keylist->next->value);
    TEST_ASSERT(strcmp(mary_fpr, keylist->next->value) == 0);
    // Content is returned.
    TEST_ASSERT(strcmp(plaintext, "tu was!\n") == 0);

    // Import the revocation certificate.
    slurp_and_import_key(session, "test_keys/priv/pep-test-mary-0x7F59F03CD04A226E.rev");

    plaintext = NULL;
    plaintext_size = 0;
    keylist = NULL;
    status = decrypt_and_verify(session,
                                ciphertext.c_str(), ciphertext.size(),
                                NULL, 0,
                                &plaintext, &plaintext_size,
                                &keylist, NULL);

    // Now it should fail.
    TEST_ASSERT_MSG(status == PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH, tl_status_string(status));
    TEST_ASSERT(keylist);
    // No signer.
    TEST_ASSERT(strcmp(keylist->value, "") == 0);
    // Recipient is mary.
    TEST_ASSERT(keylist->next);
    TEST_ASSERT(keylist->next->value);
    TEST_ASSERT(strcmp(mary_fpr, keylist->next->value) == 0);
    // Content is returned.
    TEST_ASSERT(strcmp(plaintext, "tu was!\n") == 0);


    string text = slurp("test_files/pep-test-mary-signed.txt");
    string sig = slurp("test_files/pep-test-mary-signed.txt.sig");

    plaintext = NULL;
    plaintext_size = 0;
    keylist = NULL;
    status = verify_text(session,
                         text.c_str(), text.size(),
                         sig.c_str(), sig.size(),
                         &keylist);

    // Now it should fail.
    TEST_ASSERT_MSG(status == PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH, tl_status_string(status));
    TEST_ASSERT(keylist);
    // No signer.
    TEST_ASSERT(strcmp(keylist->value, "") == 0);
    TEST_ASSERT(! keylist->next);
}

void VerifyTests::check_revoked_signing_key() {
    slurp_and_import_key(session, "test_keys/priv/pep-test-mary-0x7F59F03CD04A226E_priv.asc");
    slurp_and_import_key(session, "test_keys/pub/pep-test-mary-0x7F59F03CD04A226E_revoked_sig_key.asc");

    string ciphertext = slurp("test_files/pep-test-mary-signed-encrypted-to-self.asc");

    // Decrypt and verify it.
    char *plaintext = NULL;
    size_t plaintext_size = 0;
    stringlist_t *keylist = NULL;
    PEP_STATUS status = decrypt_and_verify(session,
                                           ciphertext.c_str(),
                                           ciphertext.size(),
                                           NULL, 0,
                                           &plaintext, &plaintext_size,
                                           &keylist, NULL);

    // It should fail.
    TEST_ASSERT_MSG(status == PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH, tl_status_string(status));
    TEST_ASSERT(keylist);
    // No signer.
    TEST_ASSERT(strcmp(keylist->value, "") == 0);
    // Recipient is mary.
    TEST_ASSERT(keylist->next);
    TEST_ASSERT(keylist->next->value);
    TEST_ASSERT(strcmp(mary_fpr, keylist->next->value) == 0);
    // Content is returned.
    TEST_ASSERT(strcmp(plaintext, "tu was!\n") == 0);


    string text = slurp("test_files/pep-test-mary-signed.txt");
    string sig = slurp("test_files/pep-test-mary-signed.txt.sig");

    plaintext = NULL;
    plaintext_size = 0;
    keylist = NULL;
    status = verify_text(session,
                         text.c_str(), text.size(),
                         sig.c_str(), sig.size(),
                         &keylist);

    // Now it should fail.
    TEST_ASSERT_MSG(status == PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH, tl_status_string(status));
    TEST_ASSERT(keylist);
    // No signer.
    TEST_ASSERT(strcmp(keylist->value, "") == 0);
    TEST_ASSERT(! keylist->next);
}

void VerifyTests::check_expired_tpk() {
    slurp_and_import_key(session, "test_keys/priv/pep-test-mary-0x7F59F03CD04A226E_priv.asc");
    slurp_and_import_key(session, "test_keys/pub/pep-test-mary-0x7F59F03CD04A226E_expired_pub.asc");

    string ciphertext = slurp("test_files/pep-test-mary-signed-encrypted-to-self.asc");

    // Decrypt and verify it.
    char *plaintext = NULL;
    size_t plaintext_size = 0;
    stringlist_t *keylist = NULL;
    PEP_STATUS status = decrypt_and_verify(session,
                                           ciphertext.c_str(),
                                           ciphertext.size(),
                                           NULL, 0,
                                           &plaintext, &plaintext_size,
                                           &keylist, NULL);

    // It should fail.
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));
    TEST_ASSERT(keylist);
    // No signer.
    TEST_ASSERT(strcmp(keylist->value, "") == 0);
    // Recipient is mary.
    TEST_ASSERT(keylist->next);
    TEST_ASSERT(keylist->next->value);
    TEST_ASSERT(strcmp(mary_fpr, keylist->next->value) == 0);
    // Content is returned.
    TEST_ASSERT(strcmp(plaintext, "tu was!\n") == 0);


    string text = slurp("test_files/pep-test-mary-signed.txt");
    string sig = slurp("test_files/pep-test-mary-signed.txt.sig");

    plaintext = NULL;
    plaintext_size = 0;
    keylist = NULL;
    status = verify_text(session,
                         text.c_str(), text.size(),
                         sig.c_str(), sig.size(),
                         &keylist);

    // Now it should fail.
    TEST_ASSERT_MSG(status == PEP_UNENCRYPTED, tl_status_string(status));
    TEST_ASSERT(keylist);
    // No signer.
    TEST_ASSERT(strcmp(keylist->value, "") == 0);
    TEST_ASSERT(! keylist->next);
}

void VerifyTests::check_expired_signing_key() {
    slurp_and_import_key(session, "test_keys/priv/pep-test-mary-0x7F59F03CD04A226E_priv.asc");
    slurp_and_import_key(session, "test_keys/pub/pep-test-mary-0x7F59F03CD04A226E_expired_sig_key.asc");

    string ciphertext = slurp("test_files/pep-test-mary-signed-encrypted-to-self.asc");

    // Decrypt and verify it.
    char *plaintext = NULL;
    size_t plaintext_size = 0;
    stringlist_t *keylist = NULL;
    PEP_STATUS status = decrypt_and_verify(session,
                                           ciphertext.c_str(),
                                           ciphertext.size(),
                                           NULL, 0,
                                           &plaintext, &plaintext_size,
                                           &keylist, NULL);

    // It should fail.
    TEST_ASSERT_MSG(status == PEP_DECRYPTED, tl_status_string(status));
    TEST_ASSERT(keylist);
    // No signer.
    TEST_ASSERT(strcmp(keylist->value, "") == 0);
    // Recipient is mary.
    TEST_ASSERT(keylist->next);
    TEST_ASSERT(keylist->next->value);
    TEST_ASSERT(strcmp(mary_fpr, keylist->next->value) == 0);
    // Content is returned.
    TEST_ASSERT(strcmp(plaintext, "tu was!\n") == 0);


    string text = slurp("test_files/pep-test-mary-signed.txt");
    string sig = slurp("test_files/pep-test-mary-signed.txt.sig");

    plaintext = NULL;
    plaintext_size = 0;
    keylist = NULL;
    status = verify_text(session,
                         text.c_str(), text.size(),
                         sig.c_str(), sig.size(),
                         &keylist);

    // Now it should fail.
    TEST_ASSERT_MSG(status == PEP_UNENCRYPTED, tl_status_string(status));
    TEST_ASSERT(keylist);
    // No signer.
    TEST_ASSERT(strcmp(keylist->value, "") == 0);
    TEST_ASSERT(! keylist->next);
}
