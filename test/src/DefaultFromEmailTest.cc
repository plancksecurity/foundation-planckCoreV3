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

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the DefaultFromEmailTest suite.
    };

}  // namespace

// Should be rerun to generate additional test mails every time the message version changes IMHO
// Add in more version strings I guess. So inelegant, but... sigh. Who has time? Not me.
// You can step through this and force some other paths to generate other paths and create emails 
// which will be otherwise difficult to get, but that shouldn't be necessary beyond the first time 
// this is written in 2.2, I suspect, so others should ignore this blathery part.
//

TEST_F(DefaultFromEmailTest, check_encrypt_to_OpenPGP_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 0, 0, false);

    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(enc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out(OpenPGP_file.c_str(), enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}

TEST_F(DefaultFromEmailTest, check_encrypt_to_pEp_1_0_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 1, 0, true);

    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(enc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out(v1_0_file.c_str(), enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}

TEST_F(DefaultFromEmailTest, check_encrypt_to_pEp_2_0_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 2, 0, true);

    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(enc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out(v2_0_file.c_str(), enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}

TEST_F(DefaultFromEmailTest, check_encrypt_to_pEp_2_1_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 2, 1, true);

    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(enc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out(v2_1_file.c_str(), enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}

TEST_F(DefaultFromEmailTest, check_encrypt_to_pEp_2_2_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 2, 2, true);

    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(enc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out(v2_2_file.c_str(), enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}

TEST_F(DefaultFromEmailTest, check_encrypt_to_pEp_10_111_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 10, 111, true);

    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(enc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out(v10_111_file.c_str(), enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}

TEST_F(DefaultFromEmailTest, check_unencrypted_from_pEp_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 1, 0, true);

    // We actually want this to be to someone we don't have the key for, so we remove
    // the set up "to"
    free_identity_list(unenc_msg->to);
    pEp_identity* ramoth = new_identity("ramoth_cat@darthmama.org", NULL, "RAMOTH", "Ramoth T. Cat, Spy Queen of Orlais");
    unenc_msg->to = new_identity_list(ramoth);
    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    ASSERT_EQ(enc_msg, nullptr);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(unenc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out("test_mails/unencrypted_from_pEp.eml", enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}
TEST_F(DefaultFromEmailTest, check_unencrypted_OpenPGP_from_TB_import_bare_default) {
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* ramoth = new_identity("ramoth_cat@darthmama.org", NULL, PEP_OWN_USERID, "Ramoth T. Cat, Spy Queen of Orlais");
    status = myself(session, ramoth);
    ASSERT_OK;

    // Import the message which contains a single key. Be sure we get this key back.
    string email = slurp("test_mails/unencrypted_OpenPGP_with_key_attached.eml");

    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    const char* sender_key_fpr = "89047BFE779999F77CFBEDB284593ADAC6406F81";
    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    ASSERT_NULL(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, enc_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* bcc = idents->ident;
    ASSERT_NOTNULL(bcc);
    ASSERT_NOTNULL(bcc->fpr);
    ASSERT_STREQ(sender_key_fpr, bcc->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, bcc);
    ASSERT_NOTNULL(bcc->fpr);
    ASSERT_STREQ(sender_key_fpr, bcc->fpr);

    // FIXME: free stuff
}

TEST_F(DefaultFromEmailTest, check_unencrypted_OpenPGP_import_default_alternate_available) {
    // PEP_STATUS status = PEP_STATUS_OK;
    // const char* sender_key_fpr = "62D4932086185C15917B72D30571AFBCA5493553";
    // pEp_identity* ramoth = new_identity("ramoth_cat@darthmama.org", NULL, PEP_OWN_USERID, "Ramoth T. Cat, Spy Queen of Orlais");
    // status = myself(session, ramoth);
    // ASSERT_OK;

    // // FIXME: change this message to an non-expiring key, btw.
    // // Import the message which contains a single key. Be sure we get this key back.
    // string email = slurp("test_mails/unencrypted_OpenPGP_with_key_attached.eml");

    // ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/big_clumsy_cat_0xC6406F81_pub.asc"));
    // pEp_identity* bcc = NULL;

    // // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // // otherwise, we're also testing the parser driver.
    // message* enc_msg = NULL;
    // status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    // ASSERT_OK;
    // ASSERT_NOTNULL(enc_msg);

    // message* dec_msg = NULL;
    // stringlist_t* keylist = NULL;
    // PEP_rating rating;
    // PEP_decrypt_flags_t flags = 0;
    // status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    // ASSERT_EQ(status, PEP_UNENCRYPTED);
    // ASSERT_NULL(dec_msg);

    // identity_list* idents = NULL;
    // status = get_identities_by_address(session, enc_msg->from->address, &idents);
    // ASSERT_OK;
    // ASSERT_NOTNULL(idents);
    // ASSERT_NULL(idents->next);

    // bcc = idents->ident;
    // ASSERT_NOTNULL(bcc);
    // ASSERT_NOTNULL(bcc->fpr);
    // ASSERT_STREQ(sender_key_fpr, bcc->fpr);

    // // Now make sure update identity returns the same
    // status = update_identity(session, bcc);
    // ASSERT_NOTNULL(bcc->fpr);
    // ASSERT_STREQ(sender_key_fpr, bcc->fpr);

    // // FIXME: free stuff
}
TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_OpenPGP_import_bare_default) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v1_import_bare_default) {
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* ramoth = new_identity("ramoth_cat@darthmama.org", NULL, PEP_OWN_USERID, "Ramoth T. Cat, Spy Queen of Orlais");
    status = myself(session, ramoth);
    ASSERT_OK;

    // FIXME: change this message to an non-expiring key, btw.
    // Import the message which contains a single key. Be sure we get this key back.
    string email = slurp("test_mails/unencrypted_from_pEp_1.0.eml");

    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    ASSERT_NULL(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, enc_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* bcc = idents->ident;
    ASSERT_NOTNULL(bcc);
    ASSERT_NOTNULL(bcc->fpr);
    ASSERT_STREQ(john_fpr, bcc->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, bcc);
    ASSERT_NOTNULL(bcc->fpr);
    ASSERT_STREQ(john_fpr, bcc->fpr);

    // FIXME: free stuff    
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v1_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_0_import_bare_default) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_0_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_1_import_bare_default) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_1_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_2_import_bare_default) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_2_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_to_to_OpenPGP_import_bare_default) {
    string email = slurp(OpenPGP_file);
    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    PEP_STATUS status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    pEp_identity* me = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::INQUISITOR, true, true, true, true, true, true, &me);
    ASSERT_OK;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg);

    print_mail(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, dec_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* john = idents->ident;
    ASSERT_NOTNULL(john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // FIXME: free stuff    

}

TEST_F(DefaultFromEmailTest, check_OpenPGP_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_to_pEp_v1_import_bare_default) {
    string email = slurp(v1_0_file);
    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    PEP_STATUS status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    pEp_identity* me = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::INQUISITOR, true, true, true, true, true, true, &me);
    ASSERT_OK;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg);

    print_mail(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, dec_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* john = idents->ident;
    ASSERT_NOTNULL(john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // FIXME: free stuff    
}

TEST_F(DefaultFromEmailTest, check_pEp_v1_import_default_alternate_available) {
}

// We don't accept default keys from 2.0 messages anymore
TEST_F(DefaultFromEmailTest, check_to_pEp_v2_0_import_bare_default) {
    string email = slurp(v2_0_file);
    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    PEP_STATUS status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    pEp_identity* me = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::INQUISITOR, true, true, true, true, true, true, &me);
    ASSERT_OK;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg);

    print_mail(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, dec_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* john = idents->ident;
    ASSERT_NOTNULL(john);
    ASSERT_NULL(john->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, john);
    ASSERT_NULL(john->fpr);

    // FIXME: free stuff    
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_0_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_to_pEp_v2_1_import_bare_default) {
    string email = slurp(v2_1_file);
    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    PEP_STATUS status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    pEp_identity* me = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::INQUISITOR, true, true, true, true, true, true, &me);
    ASSERT_OK;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg);

    print_mail(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, dec_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* john = idents->ident;
    ASSERT_NOTNULL(john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // FIXME: free stuff        
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_1_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_to_pEp_v2_2_import_bare_default) {
    string email = slurp(v2_2_file);
    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    PEP_STATUS status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    pEp_identity* me = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::INQUISITOR, true, true, true, true, true, true, &me);
    ASSERT_OK;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg);

    print_mail(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, dec_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* john = idents->ident;
    ASSERT_NOTNULL(john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // FIXME: free stuff        
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_2_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_to_pEp_v10_111_import_bare_default) {
    string email = slurp(v10_111_file);
    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    PEP_STATUS status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    pEp_identity* me = NULL;
    status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::INQUISITOR, true, true, true, true, true, true, &me);
    ASSERT_OK;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg);

    print_mail(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, dec_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* john = idents->ident;
    ASSERT_NOTNULL(john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // FIXME: free stuff        
}
/////////////////////////////////////////////////////
// The following require key election removal to function correctly
/////////////////////////////////////////////////////

TEST_F(DefaultFromEmailTest, check_unencrypted_OpenPGP_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v1_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_1_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_2_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_OpenPGP_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v1_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_1_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_2_import_two_alternate_available) {
}

///////////////////////////////////////////////////////////////
// New start with canonical emails added for fdik's tests
///////////////////////////////////////////////////////////////

// Identity Key:
// Bob: known pEp partner
// Carol: known OpenPGP partner
// Sylvia: unknown pEp partner
// John: unknown OpenPGP partner

// Case 1: Partner didn't have our key

// A. Test successful cases

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_carol) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_john) {
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
TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_bob_no_pep_no_key) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_key_import_sylvia_no_pep_no_key) {
}

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
                                     PEP_rating_reliable, PEP_STATUS_OK);

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
                                     PEP_rating_reliable, PEP_STATUS_OK);

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

// Failure case 2) Wrong key attached
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
TEST_F(DefaultFromEmailTest, check_encrypted_key_import_carol_wrong_keyfilename) {
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_john_wrong_keyfilename) {
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_2_wrong_keyfilename) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_2_wrong_sender_key_attached.eml", 
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_2_wrong_keyfilename) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_2_wrong_sender_key_attached.eml", 
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_1_wrong_keyfilename) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_1_wrong_sender_key_attached.eml", 
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_1_wrong_keyfilename) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_1_wrong_sender_key_attached.eml", 
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_2_0_wrong_keyfilename) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_2_0_wrong_sender_key_attached.eml", 
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_0_wrong_keyfilename) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_0_wrong_sender_key_attached.eml", 
                                     PEP_rating_unreliable, PEP_DECRYPTED);

    // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);

}

// Note: 1.0 only looks at the number of keys attached, so there's no concept of "wrong sender key"

// C. Cases which may fail or succeed based on source
// Two keys attached

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_carol_two_keys) {
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_john_two_keys) {
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
                                     PEP_rating_reliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_2_0_two_keys) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_2_0_TwoKeys.eml", 
                                     PEP_rating_reliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_sylvia_1_0_two_keys) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::SYLVIA];
    set_up_and_check_initial_identities(TestUtilsPreset::SYLVIA, sender_info);

    // Ok, we now have a blank slate. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2SylviaToAlice_1_0_TwoKeys.eml", 
                                     PEP_rating_reliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}

TEST_F(DefaultFromEmailTest, check_encrypted_key_import_bob_1_0_two_keys) {
    const TestUtilsPreset::IdentityInfo& sender_info = TestUtilsPreset::presets[TestUtilsPreset::BOB];
    set_up_and_check_initial_identities(TestUtilsPreset::BOB, sender_info);

    // Ok, we now the desired state. Run the import mail fun.
    read_decrypt_check_incoming_mail("test_mails/CanonicalFrom2.2BobToAlice_1_0_TwoKeys.eml", 
                                     PEP_rating_reliable, PEP_STATUS_OK);

     // Check that the default key matches the canonical default key for this sender,
    // if expected to be present.
    check_sender_default_key_status(sender_info, PEP_ct_key_not_found);
}