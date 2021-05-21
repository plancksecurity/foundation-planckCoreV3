// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <fstream>

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "test_util.h"
#include "TestConstants.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for VerifyTest(keylist->next) != (nullptr)
    class VerifyTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;
            const char *mary_fpr = "599B3D67800DB37E2DCE05C07F59F03CD04A226E";
        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            VerifyTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~VerifyTest() override {
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
            // Objects declared here can be used by all tests in the VerifyTest suite.

    };

}  // namespace

// Neal: how are these supposed to behave under gnupg? Or is this again sequoia-specific?
#ifdef USE_SEQUOIA
TEST_F(VerifyTest, check_revoked_tpk) {
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

    ASSERT_EQ(status , PEP_DECRYPTED_AND_VERIFIED);
    ASSERT_NE(keylist, nullptr);
    // Signer is mary.
    ASSERT_NE(keylist->value, nullptr);
    output_stream << "fpr: " << mary_fpr << "; got: " << keylist->value << endl;
    ASSERT_STREQ(mary_fpr, keylist->value);
    // Recipient is mary.
    ASSERT_NE(keylist->next, nullptr);
    ASSERT_NE(keylist->next->value, nullptr);
    ASSERT_STREQ(mary_fpr, keylist->next->value);
    // Content is returned.
    ASSERT_STREQ(plaintext, "tu was!\n");

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
    ASSERT_EQ(status , PEP_VERIFY_SIGNER_KEY_REVOKED);
    ASSERT_NE(keylist, nullptr);
    // No signer.
    ASSERT_STREQ(keylist->value, "");
    // Recipient is mary.
    ASSERT_NE(keylist->next, nullptr);
    ASSERT_NE(keylist->next->value, nullptr);
    ASSERT_STREQ(mary_fpr, keylist->next->value);
    // Content is returned.
    ASSERT_STREQ(plaintext, "tu was!\n");


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
    ASSERT_EQ(status , PEP_VERIFY_SIGNER_KEY_REVOKED);
    ASSERT_NE(keylist, nullptr);
    // No signer.
    ASSERT_STREQ(keylist->value, "");
    ASSERT_EQ(keylist->next, nullptr);
}

TEST_F(VerifyTest, check_revoked_signing_key) {
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
    ASSERT_EQ(status , PEP_VERIFY_SIGNER_KEY_REVOKED);
    ASSERT_NE(keylist, nullptr);
    // No signer.
    ASSERT_STREQ(keylist->value, "");
    // Recipient is mary.
    ASSERT_NE(keylist->next, nullptr);
    ASSERT_NE(keylist->next->value, nullptr);
    ASSERT_STREQ(mary_fpr, keylist->next->value);
    // Content is returned.
    ASSERT_STREQ(plaintext, "tu was!\n");


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
    ASSERT_EQ(status , PEP_VERIFY_SIGNER_KEY_REVOKED);
    ASSERT_NE(keylist, nullptr);
    // No signer.
    ASSERT_STREQ(keylist->value, "");
    ASSERT_EQ(keylist->next, nullptr);
}

// Not REALLY sure what the difference here is btw this and the next one, but OK..
// I'm guessing the keys differ in what's expired? Neal?
TEST_F(VerifyTest, check_expired_tpk) {
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

    // It should not fail.
    ASSERT_EQ(status , PEP_DECRYPTED_AND_VERIFIED);
    ASSERT_NE(keylist, nullptr);
    // No signer.
    ASSERT_STREQ(keylist->value, "599B3D67800DB37E2DCE05C07F59F03CD04A226E");
    // Recipient is mary.
    ASSERT_NE(keylist->next, nullptr);
    ASSERT_NE(keylist->next->value, nullptr);
    ASSERT_STREQ(mary_fpr, keylist->next->value);
    // Content is returned.
    ASSERT_STREQ(plaintext, "tu was!\n");


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
    ASSERT_EQ(status , PEP_VERIFIED);
    ASSERT_NE(keylist, nullptr);
    // Signer.
    ASSERT_STREQ(keylist->value, "599B3D67800DB37E2DCE05C07F59F03CD04A226E");
    ASSERT_EQ(keylist->next, nullptr);

    free(plaintext);
    free_stringlist(keylist);
}

TEST_F(VerifyTest, check_expired_signing_key) {
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

    // It should not fail.
    ASSERT_EQ(status , PEP_DECRYPTED_AND_VERIFIED);
    ASSERT_NE(keylist, nullptr);
    // Yes, signer.
    ASSERT_STREQ(keylist->value, "599B3D67800DB37E2DCE05C07F59F03CD04A226E");
    // Recipient is mary.
    ASSERT_NE(keylist->next, nullptr);
    ASSERT_NE(keylist->next->value, nullptr);
    ASSERT_STREQ(mary_fpr, keylist->next->value);
    // Content is returned.
    ASSERT_STREQ(plaintext, "tu was!\n");
    
    // Let's try again though, this time doing the whole thing, because we should get 
    // an unreliable rating back.
    free(plaintext);
    plaintext = NULL;
    free_stringlist(keylist);
    keylist = NULL;
    PEP_decrypt_flags_t flags = 0;
    PEP_rating rating;
    char* mod_src = NULL;
    MIME_decrypt_message(session, ciphertext.c_str(), ciphertext.size(), 
                         &plaintext, &keylist, &rating, &flags, &mod_src);
    ASSERT_EQ(rating, PEP_rating_unreliable);

    string text = slurp("test_files/pep-test-mary-signed.txt");
    string sig = slurp("test_files/pep-test-mary-signed.txt.sig");

    plaintext = NULL;
    plaintext_size = 0;
    keylist = NULL;
    status = verify_text(session,
                         text.c_str(), text.size(),
                         sig.c_str(), sig.size(),
                         &keylist);

    // Shouldn't fail
    ASSERT_EQ(status , PEP_VERIFIED);
    ASSERT_NE(keylist, nullptr);
    // Signer exists.
    ASSERT_STREQ(keylist->value, "599B3D67800DB37E2DCE05C07F59F03CD04A226E");
    ASSERT_EQ(keylist->next, nullptr);
    
    free(plaintext);
    free_stringlist(keylist);
}
#endif
