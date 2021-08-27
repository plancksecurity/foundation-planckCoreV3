#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "TestUtilities.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>

#define DEFAULT_FROM_TEST_GEN 0

namespace {

	//The fixture for DefaultFromEmailTest
    class DefaultFromEmailTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            DefaultFromEmailTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~DefaultFromEmailTest() override {
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

            const char* john_fpr = "AA2E4BEB93E5FE33DEFD8BE1135CD6D170DCF575";
            const char* inq_fpr = "8E8D2381AE066ABE1FEE509821BA977CA4728718";
            string mail_prefix = "test_mails/default_keys_test_ver_";
            string mail_suffix = string(".eml");
            string OpenPGP_file = mail_prefix + "OpenPGP" + mail_suffix;
            string v1_0_file = mail_prefix + "1.0" + mail_suffix;
            string v2_0_file = mail_prefix + "2.0" + mail_suffix;
            string v2_1_file = mail_prefix + "2.1" + mail_suffix;
            string v2_2_file = mail_prefix + "2.2" + mail_suffix;
            string v10_111_file = mail_prefix + "10.111" + mail_suffix;

            void create_base_test_msg(message** msg, unsigned int to_major, unsigned int to_minor, bool is_pEp) {
                pEp_identity* from = NULL; 
                PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::JOHN, true, true, true, true, true, true, &from);
                ASSERT_OK;

                pEp_identity* to = NULL;
                status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::INQUISITOR, true, true,is_pEp, false, false, false, &to);
                ASSERT_OK;
                to->major_ver = to_major;
                to->minor_ver = to_minor;
                status = set_identity(session, to);
                ASSERT_OK;
                status = update_identity(session, to);
                ASSERT_EQ(to->major_ver, to_major);
                ASSERT_EQ(to->minor_ver, to_minor);

                message* retval = new_message(PEP_dir_outgoing);
                const char* shortmsg = "Exciting subject!";
                const char* longmsg = "¡Feliz Navidad!\n\n¡Feliz Navidad!\n\n¡Feliz Navidad, prospero año y felicidad!\n";
                retval->from = from;
                retval->to = new_identity_list(to);
                retval->shortmsg = strdup(shortmsg);
                retval->longmsg = strdup(longmsg);
                *msg = retval;
            }

            // Bob is a known identity, Sylvia is not. That is our explicit convention.
            // So we set Bob's identity, but not Sylvia's.
            void set_up_and_check_initial_identities(TestUtilsPreset::ident_preset sender,
                                                     const TestUtilsPreset::IdentityInfo& sender_info) {
                pEp_identity* alice = TestUtilsPreset::generateAndSetPrivateIdentity(session,
                                                                                     TestUtilsPreset::ALICE);
                pEp_identity* recip = NULL;
                PEP_STATUS status = PEP_STATUS_OK;

                switch (sender) {
                    case TestUtilsPreset::BOB: {
                        // We need recip to exist in DB without a known key.
                        recip = new_identity(sender_info.email,
                                             NULL,
                                             sender_info.user_id,
                                             sender_info.name);
                        PEP_STATUS status = set_identity(session, recip);
                        ASSERT_OK;
                        // Make sure identity exists
                        free_identity(recip);
                        recip = NULL;
                        status = get_identity(session, sender_info.email, sender_info.user_id, &recip);
                        ASSERT_OK;
                        break;
                    }
                    case TestUtilsPreset::SYLVIA: {
                        // Make sure identity doesn't exist
                        // Do NOT use update_identity, which will create it in the DB!
                        status = get_identity(session, sender_info.email, sender_info.user_id, &recip);
                        ASSERT_EQ(status, PEP_CANNOT_FIND_IDENTITY);
                        break;
                    }
                    default:
                        ASSERT_FALSE(true);
                }
                // Make sure also doesn't exist in TOFU form
                free_identity(recip);
                recip = NULL;
                string TOFU = string("TOFU_") + sender_info.email;
                status = get_identity(session, sender_info.email, TOFU.c_str(), &recip);
                ASSERT_EQ(status, PEP_CANNOT_FIND_IDENTITY);

                free_identity(recip);
            }

            // return type is void because the ASSERT macros will take care of the status issues
            void read_decrypt_check_incoming_mail(string filename,
                                                  PEP_rating expected_rating,
                                                  PEP_STATUS expected_decrypt_status) {
                message* infile = NULL;
                PEP_rating rating = PEP_rating_undefined;
                PEP_STATUS status = vanilla_read_file_and_decrypt_with_rating(session, &infile,
                                                                              filename.c_str(), &rating);
                ASSERT_EQ(status, expected_decrypt_status);
                ASSERT_EQ(rating, expected_rating);
                free_message(infile);
            }

            // return type is void because the ASSERT macros will take care of the status issues
            void check_sender_default_key_status(const TestUtilsPreset::IdentityInfo& sender_info,
                                                 PEP_comm_type expected_ct) {
                pEp_identity* sender = new_identity(sender_info.email, NULL,
                                                    sender_info.user_id, sender_info.name);
                ASSERT_NOTNULL(sender);
                PEP_STATUS status = update_identity(session, sender);
                ASSERT_OK;
                if (expected_ct != PEP_ct_key_not_found) {
                    ASSERT_NOTNULL(sender->fpr);
                    ASSERT_STREQ(sender->fpr, sender_info.fpr);
                }
                else
                    ASSERT_NULL(sender->fpr);

                ASSERT_EQ(sender->comm_type, expected_ct);
                free_identity(sender);
            }

            void force_sender_default_to_be_set(TestUtilsPreset::ident_preset sender_key, bool trust) {
                const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[sender_key];
                pEp_identity* sender = new_identity(sender_info.email, sender_info.fpr, sender_info.user_id, sender_info.name);
                PEP_STATUS status = set_comm_partner_key(session, sender, sender_info.fpr);
                ASSERT_OK;
                status = TestUtilsPreset::import_preset_key(session, sender_key, false);
                ASSERT_OK;
                status = update_identity(session, sender);
                ASSERT_OK;
                ASSERT_NOTNULL(sender->fpr);
                ASSERT_STREQ(sender->fpr, sender_info.fpr);
                if (trust) {
                    status = trust_personal_key(session, sender);
                    ASSERT_OK;
                }
                free_identity(sender);
            }
        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the DefaultFromEmailTest suite.
    };

}  // namespace

///////////////////////////////////////////////////////////////
// New start with canonical emails added for fdik's tests
///////////////////////////////////////////////////////////////


// Case 1: Partner didn't have our key

// A. Test successful cases

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_bob_no_pEp) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAliceUnencrypted_OpenPGP.eml",
                                     PEP_rating_unencrypted, PEP_UNENCRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_OpenPGP_unconfirmed);
}

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_sylvia_no_pEp) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAliceUnencrypted_OpenPGP.eml",
                                     PEP_rating_unencrypted, PEP_UNENCRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_OpenPGP_unconfirmed);
}

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_sylvia) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAliceUnencrypted.eml",
                                     PEP_rating_unencrypted, PEP_UNENCRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);
}

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_bob) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAliceUnencrypted.eml",
                                     PEP_rating_unencrypted, PEP_UNENCRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);

}

// B. Test failures

// Failure case 1) No key attached
TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_sylvia_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAliceUnencrypted_NoKey.eml",
                                     PEP_rating_unencrypted, PEP_UNENCRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_bob_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAliceUnencrypted_NoKey.eml",
                                     PEP_rating_unencrypted, PEP_UNENCRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_reliable_bob_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB, false);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAliceUnencrypted_NoKey.eml",
                                     PEP_rating_unencrypted, PEP_UNENCRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);

}

// Case 2: Partner had our key; we did not have theirs

// A. Test successful cases

// Bob is a known OpenPGP partner - we use the "wrong filename" version because OpenPGP doesn't use our conventions
TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_no_pep) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_1_0_wrong_key_filename_no_pEp.eml",
                                     PEP_rating_reliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_OpenPGP_unconfirmed);
}

// Sylvia is an unknown OpenPGP partner
TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_no_pep) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_1_0_wrong_key_filename_no_pEp.eml",
                                     PEP_rating_reliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_OpenPGP_unconfirmed);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_2) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_2.eml",
                                     PEP_rating_reliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_2) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_2.eml",
                                     PEP_rating_reliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_1) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_1.eml",
                                     PEP_rating_reliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_1) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_1.eml",
                                     PEP_rating_reliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);

}

// We no longer accept keys from 2.0 messages, so this should fail
TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_0) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_0.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

// We no longer accept keys from 2.0 messages, so this should fail
TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_0) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_0.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

// We use the "wrong" filename version on purpose to ensure we aren't relying on 2.2 changes
TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_1_0) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_1_0_wrong_key_filename_Modified_Version.eml",
                                     PEP_rating_reliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);

}

// We use the "wrong" filename version on purpose to ensure we aren't relying on 2.2 changes
TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_1_0) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_1_0_wrong_key_filename_ModifiedVersion.eml",
                                     PEP_rating_reliable, PEP_STATUS_OK);
    
    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);

}
// B. Test failures

// Failure case 1) No key attached

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_no_pep_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_1_0_NoKey_no_pEp.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_no_pep_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_1_0_NoKey_no_pEp.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_2_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_2_NoKey.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_2_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_2_NoKey.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_1_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_1_NoKey.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_1_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_1_NoKey.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_0_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_0_NoKey.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_0_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_0_NoKey.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_1_0_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_1_0_NoKey.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_1_0_no_key) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_1_0_NoKey.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

// Failure case 2) Wrong key attached - Note: 1.0 only looks at the number of keys attached, so there's no concept of "wrong sender key"

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_no_pep_wrong_sender_key_attached) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_1_0_wrong_sender_key_attached_no_pEp.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_no_pep_wrong_sender_key_attached) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_1_0_wrong_sender_key_attached_no_pEp.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_2_wrong_sender_key_attached) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_2_wrong_sender_key_attached.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_2_wrong_sender_key_attached) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_2_wrong_sender_key_attached.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_1_wrong_sender_key_attached) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_1_wrong_sender_key_attached.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_1_wrong_sender_key_attached) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_1_wrong_sender_key_attached.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_0_wrong_sender_key_attached) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_0_wrong_sender_key_attached.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_0_wrong_sender_key_attached) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_0_wrong_sender_key_attached.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

// Note: 1.0 only looks at the number of keys attached, so there's no concept of "wrong filename"

// Failure case 3) Wrong sender key filename
TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_2_wrong_keyfilename) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_2_wrong_key_filename.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_2_wrong_keyfilename) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_2_wrong_key_filename.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_1_wrong_keyfilename) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_1_wrong_key_filename.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_1_wrong_keyfilename) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_1_wrong_key_filename.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_0_wrong_keyfilename) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_0_wrong_key_filename.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_0_wrong_keyfilename) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_0_wrong_key_filename.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}


// C. Cases which may fail or succeed based on source
// Two keys attached

// This should fail because we expect exactly one key when not pEp
TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_two_keys_no_pEp) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_1_0_TwoKeys_no_pEp.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

// This should fail because we expect exactly one key when not pEp
TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_two_keys_no_pEp) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_1_0_TwoKeys_no_pEp.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_2_two_keys) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_2_TwoKeys.eml",
                                     PEP_rating_reliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_2_two_keys) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_2_TwoKeys.eml",
                                     PEP_rating_reliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_1_two_keys) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_1_TwoKeys.eml",
                                     PEP_rating_reliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_1_two_keys) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_1_TwoKeys.eml",
                                     PEP_rating_reliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_0_two_keys) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_0_TwoKeys.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_0_two_keys) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_0_TwoKeys.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_1_0_two_keys) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_1_0_TwoKeys.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_1_0_two_keys) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_1_0_TwoKeys.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

// Identity Key:
// Bob: known partner
// Sylvia: unknown partner
//

// Case 0: We already have a default key. Make sure we don't step on it.

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_reliable_channel_bob_noclobber_no_pEp) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, false);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAliceUnencrypted_OpenPGP.eml",
                                     PEP_rating_unencrypted, PEP_UNENCRYPTED);

    // Make sure import didn't overwrite default
    check_sender_default_key_status(sender_info2, PEP_ct_OpenPGP_unconfirmed);
}

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_reliable_channel_bob_noclobber_2_2) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, false);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAliceUnencrypted.eml",
                                     PEP_rating_unencrypted, PEP_UNENCRYPTED);

    // Make sure import didn't overwrite default
    check_sender_default_key_status(sender_info2, PEP_ct_pEp_unconfirmed);
}

// FOR THE ENCRYPTED NO_CLOBBER TESTS:
// We expect this to be unreliable now as of ENGINE-847, because the imported key on decryption is NOT associated with Bob;
// he already has a default, and this ain't it, and we have no sense of "key claim" with OpenPGP.
// Also note that the ONLY place the key attached to this message will be present at ALL is in the keys.db - we don't
// even put it into the pgp_keypair list. So as far as pEp itself is concerned, that key doesn't exist until the
// user tells us it does.


TEST_F(DefaultFromEmailTest, check_encrypted_key_import_reliable_channel_bob_noclobber_no_pep) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, false);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_1_0_wrong_key_filename_no_pEp.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info2, PEP_ct_OpenPGP_unconfirmed);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_reliable_channel_bob_noclobber_2_2) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, false);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_2.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info2, PEP_ct_pEp_unconfirmed);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_reliable_channel_bob_noclobber_2_1) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, false);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_1.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info2, PEP_ct_pEp_unconfirmed);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_reliable_channel_bob_noclobber_2_0) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, false);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_0.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info2, PEP_ct_pEp_unconfirmed);

}

// We use the "wrong" filename version on purpose to ensure we aren't relying on 2.2 changes
TEST_F(DefaultFromEmailTest, check_encrypted_key_import_reliable_channel_bob_noclobber_1_0) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, false);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_1_0_wrong_key_filename_ModifiedVersion.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);
    
    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info2, PEP_ct_pEp_unconfirmed);

}

////////////////////////////

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_trusted_channel_bob_noclobber_no_pEp) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, true);


    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAliceUnencrypted_OpenPGP.eml",
                                     PEP_rating_unencrypted, PEP_UNENCRYPTED);

    // Make sure import didn't overwrite default
    check_sender_default_key_status(sender_info2, PEP_ct_OpenPGP);
}

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_trusted_channel_bob_noclobber_2_2) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, true);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAliceUnencrypted.eml",
                                     PEP_rating_unencrypted, PEP_UNENCRYPTED);

    // Make sure import didn't overwrite default
    check_sender_default_key_status(sender_info2, PEP_ct_pEp);
}
//////////////////////////

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_trusted_channel_bob_noclobber_no_pep) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, true);

    // Ok, we now the desired state. Run the import mail fun.
    // N.B.: We expect this to be unreliable now as of ENGINE-847, because the imported key on decryption is NOT associated with Bob;
    //       he already has a default, and this ain't it, and we have no sense of "key claim" with OpenPGP.
    //       Also note that the ONLY place the key attached to this message will be present at ALL is in the keys.db - we don't
    //       even put it into the pgp_keypair list. So as far as pEp itself is concerned, that key doesn't exist until the
    //       user tells us it does.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_1_0_wrong_key_filename_no_pEp.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info2, PEP_ct_OpenPGP);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_trusted_channel_bob_noclobber_2_2) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, true);

    // Ok, we now the desired state. Run the import mail fun.
    // NOTE: This behaves differently from the "no_pep" cases for one very important reason - in setting
    // the user as a pEp user during the setup above, we actually set the initial imported key as a default before
    // changing it in the previous line.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_2.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info2, PEP_ct_pEp);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_trusted_channel_bob_noclobber_2_1) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, true);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_1.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info2, PEP_ct_pEp);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_trusted_channel_bob_noclobber_2_0) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, true);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_0.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info2, PEP_ct_pEp);

}

// We use the "wrong" filename version on purpose to ensure we aren't relying on 2.2 changes
TEST_F(DefaultFromEmailTest, check_encrypted_key_import_trusted_channel_bob_noclobber_1_0) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    const TestUtilsPreset::IdentityInfo& sender_info2 = TestUtilsPreset::presets[TestUtilsPreset::BOB2];

    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB2, true);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_1_0_wrong_key_filename_ModifiedVersion.eml",
                                     PEP_rating_unreliable, PEP_STATUS_OK);
    
    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info2, PEP_ct_pEp);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_2_bad_sender_claim) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom3.1BobToAlice_2_2_claim_doesnt_match_signer.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_reliable_bob_2_2_bad_sender_claim) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB, false);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom3.1BobToAlice_2_2_claim_doesnt_match_signer.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp_unconfirmed);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_trusted_bob_2_2_bad_sender_claim) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    force_sender_default_to_be_set(TestUtilsPreset::BOB, true);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom3.1BobToAlice_2_2_claim_doesnt_match_signer.eml",
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_pEp);

}
