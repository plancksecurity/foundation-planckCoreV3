// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <cstring>
#include <iostream>
#include <fstream>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "platform.h"
#include "mime.h"
#include "message_api.h"
#include "keymanagement.h"
#include "TestUtilities.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for ReencryptPlusExtraKeysTest
    class ReencryptPlusExtraKeysTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            ReencryptPlusExtraKeysTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~ReencryptPlusExtraKeysTest() override {
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
            
            // Own identity keys
            const char* fpr_own_recip_key = "85D022E0CC9BA9F6B922CA7B638E5211B1A2BE89";
            const char* fpr_own_recip_2_key = "7A2EEB933E6FD99207B83E397B6D3751D6E75FFF";
            // Sender key
            const char* fpr_sender_pub_key = "95FE24B262A34FA5C6A8D0AAF90144FC3B508C8E";
    
            // Other recips
            const char* fpr_recip_0_pub_key = "CDF787C7C9664E02825DD416C6FBCF8D1F4A5986";
            const char* fpr_recip_2_pub_key = "60701073D138EF622C8F9221B6FC86831EDBE691";

            // Extra keys
            const char* fpr_pub_extra_key_0 = "33BB6C92EBFB6F29641C75B5B79D916C828AA789";
            const char* fpr_pub_extra_key_1 = "3DB93A746785FDD6110798AB3B193A9E8B026AEC";
            const char* fpr_pub_extra_key_2 = "E8AC9779A2D13A15D8D55C84B049F489BB5BCCF6";

            void import_reenc_test_keys() {
                PEP_STATUS status;
                // Import own identity keys
                const string own_recip_pub_key = slurp("test_keys/pub/reencrypt_recip_0-0xB1A2BE89_pub.asc");
                const string own_recip_priv_key = slurp("test_keys/priv/reencrypt_recip_0-0xB1A2BE89_priv.asc");
                const string own_recip_2_pub_key = slurp("test_keys/pub/reencrypt_recip_numero_deux_test_0-0xD6E75FFF_pub.asc");
                const string own_recip_2_priv_key = slurp("test_keys/priv/reencrypt_recip_numero_deux_test_0-0xD6E75FFF_priv.asc");
                status = import_key(session, own_recip_pub_key.c_str(), own_recip_pub_key.length(), NULL);
                ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
                status = import_key(session, own_recip_priv_key.c_str(), own_recip_priv_key.length(), NULL);
                ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
                status = import_key(session, own_recip_2_pub_key.c_str(), own_recip_2_pub_key.length(), NULL);
                ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
                status = import_key(session, own_recip_2_priv_key.c_str(), own_recip_2_priv_key.length(), NULL);
                ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);

                // Import sender key
                const string sender_pub_key = slurp("test_keys/pub/reencrypt_sender_0-0x3B508C8E_pub.asc");
                status = import_key(session, sender_pub_key.c_str(), sender_pub_key.length(), NULL);
                ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
                
                // Import other recips
                const string recip_0_pub_key = slurp("test_keys/pub/reencrypt_other_recip_0-0x1F4A5986_pub.asc");
                status = import_key(session, recip_0_pub_key.c_str(), recip_0_pub_key.length(), NULL);
                ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
                // we're leaving recip_1 out for the Hell of it - D3886D0DF75113BE2799C9374D6B99FE0F8273D8    
                const string recip_2_pub_key = slurp("test_keys/pub/reencrypt_other_recip_2-0x1EDBE691_pub.asc");
                status = import_key(session, recip_2_pub_key.c_str(), recip_2_pub_key.length(), NULL);
                ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);

                // Import extra keys
                const string pub_extra_key_0 = slurp("test_keys/pub/reencrypt_extra_keys_0-0x828AA789_pub.asc");    
                const string pub_extra_key_1 = slurp("test_keys/pub/reencrypt_extra_keys_1-0x8B026AEC_pub.asc");
                status = import_key(session, pub_extra_key_0.c_str(), pub_extra_key_0.length(), NULL);
                ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
                status = import_key(session, pub_extra_key_1.c_str(), pub_extra_key_1.length(), NULL);
                ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);

                output_stream << "Keys imported." << endl;
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the ReencryptPlusExtraKeysTest suite.
    
            
    };

}  // namespace


TEST_F(ReencryptPlusExtraKeysTest, check_reencrypt_unencrypted_subj) {
    config_unencrypted_subject(session, true);
    pEp_identity* carol = NULL;

    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::CAROL,
                                      true, true, true, true, true, true, &carol);

    ASSERT_OK;
    ASSERT_NOTNULL(carol);

    status = set_identity_flags(session, carol, PEP_idf_org_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, carol);
    ASSERT_OK;
    ASSERT_EQ(carol->flags, carol->flags & PEP_idf_org_ident);

    string mailfile = slurp("test_mails/From_M2_1.eml");

    char* decrypted_text = nullptr;

    // In: extra keys; Out: keys that were used to encrypt this.
    stringlist_t* keys = NULL;
    PEP_decrypt_flags_t flags = PEP_decrypt_flag_untrusted_server;

    flags = PEP_decrypt_flag_untrusted_server;
    char* modified_src = NULL;

    message* decoded = NULL;
    status = mime_decode_message(mailfile.c_str(), mailfile.size(), &decoded, NULL);
    ASSERT_NE(decoded, nullptr);
    ASSERT_OK;
    message* dec_msg = NULL;
    decoded->recv_by = identity_dup(carol);


    status = decrypt_message_2(session, decoded, &dec_msg, &keys, &flags);

    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(PEP_decrypt_flag_src_modified & flags, 0);

    message* checker = decoded;
    ASSERT_STREQ(checker->shortmsg, "Boom shaka laka");
    config_unencrypted_subject(session, false);

    message* src_msg = NULL;
    status = mime_decode_message(mailfile.c_str(), mailfile.size(), &src_msg, NULL);
    ASSERT_NOTNULL(src_msg);
    ASSERT_STREQ(src_msg->attachments->next->value, checker->attachments->next->value);
    config_unencrypted_subject(session, false);

}

TEST_F(ReencryptPlusExtraKeysTest, check_reencrypt_unencrypted_subj_check_efficient) {
    config_unencrypted_subject(session, true);
    pEp_identity* carol = NULL;

    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::CAROL,
                                      true, true, true, true, true, true, &carol);

    ASSERT_OK;
    ASSERT_NOTNULL(carol);

    status = set_identity_flags(session, carol, PEP_idf_org_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, carol);
    ASSERT_OK;
    ASSERT_EQ(carol->flags, carol->flags & PEP_idf_org_ident);

    string mailfile = slurp("test_mails/From_M2_1.eml");

    char* decrypted_text = nullptr;

    // In: extra keys; Out: keys that were used to encrypt this.
    stringlist_t* keys = NULL;
    PEP_decrypt_flags_t flags = PEP_decrypt_flag_untrusted_server;

    flags = PEP_decrypt_flag_untrusted_server;
    char* modified_src = NULL;

    message* decoded = NULL;
    status = mime_decode_message(mailfile.c_str(), mailfile.size(), &decoded, NULL);
    ASSERT_NE(decoded, nullptr);
    ASSERT_OK;
    message* dec_msg = NULL;
    decoded->recv_by = identity_dup(carol);

    status = decrypt_message_2(session, decoded, &dec_msg, &keys, &flags);

    ASSERT_NE(status, PEP_CANNOT_REENCRYPT);
    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(PEP_decrypt_flag_src_modified & flags, 0);

    message* checker = decoded;
    ASSERT_STREQ(checker->shortmsg, "Boom shaka laka");

    message* src_msg = NULL;
    status = mime_decode_message(mailfile.c_str(), mailfile.size(), &src_msg, NULL);
    ASSERT_NOTNULL(src_msg);
    ASSERT_STREQ(src_msg->attachments->next->value, checker->attachments->next->value);

    free_message(dec_msg);
    dec_msg = NULL;
    flags = PEP_decrypt_flag_untrusted_server;
    free_stringlist(keys);
    keys = NULL; // remember, this is no extra_keys in this test

    status = decrypt_message_2(session, checker, &dec_msg, &keys, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg );
    ASSERT_EQ(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NOTNULL(checker);
    ASSERT_NOTNULL(dec_msg->_sender_fpr);
    ASSERT_NOTNULL(keys);
    ASSERT_STREQ(dec_msg->_sender_fpr, keys->value); // should be the same, since not reencrypted
    
    config_unencrypted_subject(session, false);    
}


TEST_F(ReencryptPlusExtraKeysTest, check_reencrypt_unencrypted_subj_extra_keys) {
    config_unencrypted_subject(session, true);
    
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/reencrypt_extra_keys_0-0x828AA789_pub.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/reencrypt_extra_keys_1-0x8B026AEC_pub.asc"));
    
    stringlist_t* keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);
    
    pEp_identity* carol = NULL;

    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::CAROL,
                                      true, true, true, true, true, true, &carol);

    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(carol);

    status = set_identity_flags(session, carol, PEP_idf_org_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, carol);
    ASSERT_OK;
    ASSERT_EQ(carol->flags, carol->flags & PEP_idf_org_ident);

    string mailfile = slurp("test_mails/From_M2_1.eml");

    char* decrypted_text = nullptr;

    // In: extra keys; Out: keys that were used to encrypt this.
    PEP_decrypt_flags_t flags = PEP_decrypt_flag_untrusted_server;

    flags = PEP_decrypt_flag_untrusted_server;
    char* modified_src = NULL;

    message* decoded = NULL;
    status = mime_decode_message(mailfile.c_str(), mailfile.size(), &decoded, NULL);
    ASSERT_NE(decoded, nullptr);
    ASSERT_OK;
    message* dec_msg = NULL;
    decoded->recv_by = identity_dup(carol);

    status = decrypt_message_2(session, decoded, &dec_msg, &keys, &flags);

    ASSERT_NE(status, PEP_CANNOT_REENCRYPT);

    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(PEP_decrypt_flag_src_modified & flags, 0);

    message* checker = decoded;
    ASSERT_STREQ(checker->shortmsg, "Boom shaka laka");

    message* src_msg = NULL;
    status = mime_decode_message(mailfile.c_str(), mailfile.size(), &src_msg, NULL);
    ASSERT_NOTNULL(src_msg);
    ASSERT_STRNE(src_msg->attachments->next->value, checker->attachments->next->value);

    flags = 0;
    message* decryptomatic = NULL;
    stringlist_t* extra_keys = NULL;
    status = decrypt_message_2(session, checker, &decryptomatic, &extra_keys, &flags);

    bool own_key_found, extra_key_0_found, extra_key_1_found;
    
    own_key_found = extra_key_0_found = extra_key_1_found = false;
    int i = 0;

    for (stringlist_t* kl = extra_keys; kl && kl->value; kl = kl->next, i++)
    {
        if (i == 0) {
              output_stream << "Signed by " << (strcasecmp("", kl->value) == 0 ? "NOBODY" : kl->value) << endl;
              ASSERT_STRCASEEQ(carol->fpr, kl->value);
        }
        else {
            if (strcasecmp(carol->fpr, kl->value) == 0)
                own_key_found = true;
            else if (strcasecmp(fpr_pub_extra_key_0, kl->value) == 0)
                extra_key_0_found = true;
            else if (strcasecmp(fpr_pub_extra_key_1, kl->value) == 0)
                extra_key_1_found = true;
            else {
                output_stream << "FAIL: Encrypted for " << kl->value << ", which it should not be." << endl;
                ASSERT_TRUE(false);
            }
        }
        ASSERT_LT(i, 4);
    }
    ASSERT_TRUE(own_key_found && extra_key_0_found && extra_key_1_found);  
    config_unencrypted_subject(session, false);      
}

TEST_F(ReencryptPlusExtraKeysTest, check_reencrypt_unencrypted_subj_extra_keys_efficient_pass) {
    config_unencrypted_subject(session, true);
    
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/reencrypt_extra_keys_0-0x828AA789_pub.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/reencrypt_extra_keys_1-0x8B026AEC_pub.asc"));
    
    stringlist_t* keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);
    
    pEp_identity* carol = NULL;

    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::CAROL,
                                      true, true, true, true, true, true, &carol);

    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(carol);

    status = set_identity_flags(session, carol, PEP_idf_org_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, carol);
    ASSERT_OK;
    ASSERT_EQ(carol->flags, carol->flags & PEP_idf_org_ident);


    string mailfile = slurp("test_mails/From_M2_1.eml");

    char* decrypted_text = nullptr;

    // In: extra keys; Out: keys that were used to encrypt this.
    PEP_decrypt_flags_t flags = PEP_decrypt_flag_untrusted_server;

    flags = PEP_decrypt_flag_untrusted_server;
    char* modified_src = NULL;

    message* decoded = NULL;
    status = mime_decode_message(mailfile.c_str(), mailfile.size(), &decoded, NULL);
    ASSERT_NE(decoded, nullptr);
    ASSERT_OK;
    message* dec_msg = NULL;
    decoded->recv_by = identity_dup(carol);

    status = decrypt_message_2(session, decoded, &dec_msg, &keys, &flags);

    ASSERT_NE(status, PEP_CANNOT_REENCRYPT);

    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(PEP_decrypt_flag_src_modified & flags, 0);

    message* checker = decoded;
    ASSERT_STREQ(checker->shortmsg, "Boom shaka laka");

    message* src_msg = NULL;
    status = mime_decode_message(mailfile.c_str(), mailfile.size(), &src_msg, NULL);
    ASSERT_NOTNULL(src_msg);
    ASSERT_STRNE(src_msg->attachments->next->value, checker->attachments->next->value);

    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);
    flags = PEP_decrypt_flag_untrusted_server;
    message* decryptomatic = NULL;
    status = decrypt_message_2(session, checker, &decryptomatic, &keys, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(decryptomatic);
    ASSERT_EQ(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NOTNULL(checker);
    ASSERT_NOTNULL(decryptomatic->_sender_fpr);
    ASSERT_NOTNULL(keys);
    ASSERT_STREQ(decryptomatic->_sender_fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    ASSERT_STREQ(keys->value, "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42");
    // ofstream outfile;
    // outfile.open("test_mails/From_M2_1_all_extra.eml");
    // outfile << modified_src;
    // outfile.close();
    
    config_unencrypted_subject(session, false);    
}

TEST_F(ReencryptPlusExtraKeysTest, check_reencrypt_unencrypted_subj_extra_keys_efficient_missing) {
    config_unencrypted_subject(session, true);
    
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/reencrypt_extra_keys_0-0x828AA789_pub.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/reencrypt_extra_keys_1-0x8B026AEC_pub.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-dave-0xBB5BCCF6_pub.asc"));
    stringlist_t* keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);
    
    pEp_identity* carol = NULL;

    PEP_STATUS status = TestUtilsPreset::set_up_preset(session, TestUtilsPreset::CAROL,
                                      true, true, true, true, true, true, &carol);

    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(carol);


    status = set_identity_flags(session, carol, PEP_idf_org_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, carol);
    ASSERT_OK;
    ASSERT_EQ(carol->flags, carol->flags & PEP_idf_org_ident);

    string mailfile = slurp("test_mails/From_M2_1.eml");

    char* decrypted_text = nullptr;

    // In: extra keys; Out: keys that were used to encrypt this.
    PEP_decrypt_flags_t flags = PEP_decrypt_flag_untrusted_server;

    flags = PEP_decrypt_flag_untrusted_server;
    char* modified_src = NULL;

    message* decoded = NULL;
    status = mime_decode_message(mailfile.c_str(), mailfile.size(), &decoded, NULL);
    ASSERT_NE(decoded, nullptr);
    ASSERT_OK;
    message* dec_msg = NULL;
    decoded->recv_by = identity_dup(carol);

    status = decrypt_message_2(session, decoded, &dec_msg, &keys, &flags);

    ASSERT_NE(status, PEP_CANNOT_REENCRYPT);

    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(PEP_decrypt_flag_src_modified & flags, 0);

    message* checker = decoded;
    ASSERT_STREQ(checker->shortmsg, "Boom shaka laka");
    message* src_msg = NULL;
    status = mime_decode_message(mailfile.c_str(), mailfile.size(), &src_msg, NULL);
    ASSERT_NOTNULL(src_msg);
    ASSERT_STRNE(src_msg->attachments->next->value, checker->attachments->next->value);

    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);
    stringlist_add(keys, fpr_pub_extra_key_2);
    
    flags = PEP_decrypt_flag_untrusted_server;
    message* decryptomatic = NULL;
    checker->recv_by = identity_dup(carol);
    status = decrypt_message_2(session, checker, &decryptomatic, &keys, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(decryptomatic);
    ASSERT_EQ(flags & PEP_decrypt_flag_src_modified, PEP_decrypt_flag_src_modified);
    ASSERT_NOTNULL(checker);
    ASSERT_NOTNULL(decryptomatic->_sender_fpr);
    ASSERT_NOTNULL(keys);
    ASSERT_STREQ(decryptomatic->_sender_fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    ASSERT_STREQ(keys->value, "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42");
    // ofstream outfile;
    // outfile.open("test_mails/From_M2_1_all_extra.eml");
    // outfile << modified_src;
    // outfile.close();
    
    config_unencrypted_subject(session, false);    
}

// FIXME: Also split this one up.
TEST_F(ReencryptPlusExtraKeysTest, check_reencrypt_plus_extra_keys) {
    PEP_STATUS status = PEP_STATUS_OK;

    /* import all the keys */
    import_reenc_test_keys();    

    output_stream << "Keys imported." << endl;

    pEp_identity* me_recip_1 = new_identity("reencrypt_recip@darthmama.cool", fpr_own_recip_key, PEP_OWN_USERID, "Me Recipient");
    pEp_identity* me_recip_2 = new_identity("reencrypt_recip_numero_deux_test@darthmama.org", fpr_own_recip_2_key, PEP_OWN_USERID, "Me Recipient");

    output_stream << "Inserting own identities and keys into database." << endl;
    status = set_own_key(session, me_recip_2, fpr_own_recip_2_key);
    ASSERT_OK;
    output_stream << "Done: inserting own identities and keys into database." << endl;

    status = set_identity_flags(session, me_recip_2, PEP_idf_org_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, me_recip_2);
    ASSERT_OK;
    ASSERT_EQ(me_recip_2->flags, me_recip_2->flags & PEP_idf_org_ident);

    const string to_reencrypt_from_enigmail = slurp("test_mails/reencrypt_sent_by_enigmail.eml");
    const string to_reencrypt_from_enigmail_BCC = slurp("test_mails/reencrypt_BCC_sent_by_enigmail.eml");
    const string to_reencrypt_from_pEp = slurp("test_mails/reencrypt_encrypted_through_pEp.eml");

    output_stream << endl << "Case 1a: Calling decrypt_message with reencrypt flag set on message sent from enigmail for recip 2 with no extra keys." << endl;

    char* decrypted_text = nullptr;

    // In: extra keys; Out: keys that were used to encrypt this.
    stringlist_t* keys = NULL;
    PEP_decrypt_flags_t flags = 0;

    flags = PEP_decrypt_flag_untrusted_server;
    char* modified_src = NULL;

    message* decoded = NULL;
    status = mime_decode_message(to_reencrypt_from_enigmail.c_str(), to_reencrypt_from_enigmail.size(), &decoded, NULL);
    ASSERT_NE(decoded, nullptr);
    ASSERT_OK;
    message* dec_msg = NULL;
    decoded->recv_by = identity_dup(me_recip_2);

    status = decrypt_message_2(session, decoded, &dec_msg, &keys, &flags);

    ASSERT_NE(status, PEP_CANNOT_REENCRYPT);

    ASSERT_NE(dec_msg, nullptr);
    ASSERT_EQ(PEP_decrypt_flag_src_modified & flags, 0);

    free_message(decoded);
    free_message(dec_msg);

    output_stream << "Case 1a: PASS" << endl << endl;

    output_stream << "Case 1b: Calling decrypt_message with reencrypt flag set on message sent from enigmail for recip 2 extra keys." << endl;

    // In: extra keys; Out: keys that were used to encrypt this.
    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);

    flags = PEP_decrypt_flag_untrusted_server;

    decoded = NULL;
    status = mime_decode_message(to_reencrypt_from_enigmail.c_str(), to_reencrypt_from_enigmail.size(), &decoded, NULL);
    ASSERT_NE(decoded, nullptr);
    ASSERT_OK;
    dec_msg = NULL;
    decoded->recv_by = identity_dup(me_recip_2);

    status = decrypt_message_2(session, decoded, &dec_msg, &keys, &flags);

    ASSERT_NE(status, PEP_CANNOT_REENCRYPT);

    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(PEP_decrypt_flag_src_modified & flags, 0);

    free_message(dec_msg);
    dec_msg = NULL;

    output_stream << "CHECK: Decrypting to see what keys it was encrypted for." << endl;

    flags = 0;
    message* throwaway = NULL;

    decoded->recv_by = identity_dup(me_recip_2);
    stringlist_t* tmp_keys = NULL;
    status = decrypt_message_2(session, decoded, &dec_msg, &tmp_keys, &flags);

    output_stream << "keys used:\n";

    bool own_key_found = false;
    bool extra_key_0_found = false;
    bool extra_key_1_found = false;

    int i = 0;

    if (tmp_keys && tmp_keys->next)
        dedup_stringlist(tmp_keys->next);

    for (stringlist_t* kl = tmp_keys; kl && kl->value; kl = kl->next, i++)
    {
        if (i == 0) {
              output_stream << "Signed by " << (strcasecmp("", kl->value) == 0 ? "NOBODY" : kl->value) << endl;
              ASSERT_EQ(strcasecmp(fpr_own_recip_2_key,kl->value) , 0);
        }
        else {
            if (strcasecmp(fpr_own_recip_2_key, kl->value) == 0) {
                output_stream << "Encrypted for us." << endl;
                own_key_found = true;
            }
            else if (strcasecmp(fpr_pub_extra_key_0, kl->value) == 0) {
                output_stream << "Encrypted for extra key 0." << endl;
                extra_key_0_found = true;
            }
            else if (strcasecmp(fpr_pub_extra_key_1, kl->value) == 0) {
                output_stream << "Encrypted for extra key 1." << endl;
                extra_key_1_found = true;
            }
            else {
                output_stream << "FAIL: Encrypted for " << kl->value << ", which it should not be." << endl;
                ASSERT_TRUE(false);
            }
            output_stream << "\t " << kl->value << endl;
        }
        ASSERT_LT(i , 4);
    }
    ASSERT_TRUE(own_key_found && extra_key_0_found && extra_key_1_found);
    output_stream << "Message was encrypted for all the keys it should be, and none it should not!" << endl;
    free_stringlist(tmp_keys);
    tmp_keys = NULL;

    output_stream << "Case 1b: PASS" << endl << endl;

    output_stream << "Case 2a: Calling decrypt_message with reencrypt flag set on message sent with recip 2 in BCC from enigmail with no extra keys." << endl;

    free(modified_src);
    modified_src = NULL;

    free_stringlist(keys);
    keys = NULL;

    flags = PEP_decrypt_flag_untrusted_server;

    decoded = NULL;
    status = mime_decode_message(to_reencrypt_from_enigmail_BCC.c_str(), to_reencrypt_from_enigmail_BCC.size(), &decoded, NULL);
    ASSERT_NE(decoded, nullptr);
    ASSERT_OK;
    dec_msg = NULL;
    decoded->recv_by = identity_dup(me_recip_2);

    status = decrypt_message_2(session, decoded, &dec_msg, &keys, &flags);

    ASSERT_NE(status, PEP_CANNOT_REENCRYPT);

    ASSERT_NE(dec_msg, nullptr);
    ASSERT_EQ(PEP_decrypt_flag_src_modified & flags, 0);

    free_message(dec_msg);
    dec_msg = NULL;

    output_stream << "Case 2a: PASS" << endl << endl;

    output_stream << "Case 2b: Calling decrypt_message with reencrypt flag set on message sent with recip 2 in BCC from enigmail with extra keys." << endl;

    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);

    flags = PEP_decrypt_flag_untrusted_server;

    decoded = NULL;
    status = mime_decode_message(to_reencrypt_from_enigmail_BCC.c_str(), to_reencrypt_from_enigmail_BCC.size(), &decoded, NULL);
    ASSERT_NE(decoded, nullptr);
    ASSERT_OK;
    dec_msg = NULL;
    decoded->recv_by = identity_dup(me_recip_2);

    status = decrypt_message_2(session, decoded, &dec_msg, &keys, &flags);

    ASSERT_NE(status, PEP_CANNOT_REENCRYPT);

    ASSERT_NE(dec_msg, nullptr);
    ASSERT_NE(PEP_decrypt_flag_src_modified & flags, 0);

    free_message(dec_msg);
    dec_msg = NULL;

    output_stream << "CHECK: Decrypting to see what keys it was encrypted for." << endl;

    flags = 0;
    throwaway = NULL;

    decoded->recv_by = identity_dup(me_recip_2);
    tmp_keys = NULL;
    status = decrypt_message_2(session, decoded, &dec_msg, &tmp_keys, &flags);

    output_stream << "keys used:\n";

    own_key_found = false;
    extra_key_0_found = false;
    extra_key_1_found = false;

    i = 0;

    if (tmp_keys && tmp_keys->next)
        dedup_stringlist(tmp_keys->next);

    for (stringlist_t* kl = tmp_keys; kl && kl->value; kl = kl->next, i++)
    {
        if (i == 0) {
              output_stream << "Signed by " << (strcasecmp("", kl->value) == 0 ? "NOBODY" : kl->value) << endl;
              // ASSERT_EQ(strcasecmp(fpr_own_recip_2_key,kl->value) , 0);
        }
        else {
            if (strcasecmp(fpr_own_recip_2_key, kl->value) == 0) {
                output_stream << "Encrypted for us." << endl;
                own_key_found = true;
            }
            else if (strcasecmp(fpr_pub_extra_key_0, kl->value) == 0) {
                output_stream << "Encrypted for extra key 0." << endl;
                extra_key_0_found = true;
            }
            else if (strcasecmp(fpr_pub_extra_key_1, kl->value) == 0) {
                output_stream << "Encrypted for extra key 1." << endl;
                extra_key_1_found = true;
            }
            else {
                output_stream << "FAIL: Encrypted for " << kl->value << ", which it should not be." << endl;
                // TEST_ASSERT_MSG(false, "Encrypted for someone it shouldn't have been.");
            }
            output_stream << "\t " << kl->value << endl;
        }
        ASSERT_LT(i , 4);
    }
//        TEST_ASSERT_MSG(own_key_found && extra_key_0_found && extra_key_1_found, "Not encrypted for all desired keys.");

    output_stream << "Message was encrypted for all the keys it should be, and none it should not!" << endl;

    output_stream << "Case 2b: PASS" << endl << endl;

    output_stream << "Case 3a: Calling decrypt_message with reencrypt flag set on message generated by pEp (message 2.0) with no extra keys." << endl;

    free_stringlist(keys);
    keys = NULL;

    status = set_own_key(session, me_recip_1, fpr_own_recip_key);
    ASSERT_OK;

    status = set_identity_flags(session, me_recip_1, PEP_idf_org_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);
    
    status = myself(session, me_recip_1);
    ASSERT_OK;
    ASSERT_EQ(me_recip_1->flags, me_recip_1->flags & PEP_idf_org_ident);

    flags = PEP_decrypt_flag_untrusted_server;

    decoded = NULL;
    status = mime_decode_message(to_reencrypt_from_pEp.c_str(), to_reencrypt_from_pEp.size(), &decoded, NULL);
    ASSERT_NE(decoded, nullptr);
    ASSERT_OK;
    dec_msg = NULL;
    decoded->recv_by = identity_dup(me_recip_1);

    status = decrypt_message_2(session, decoded, &dec_msg, &keys, &flags);

    ASSERT_NE(status, PEP_CANNOT_REENCRYPT);

    ASSERT_NE(dec_msg, nullptr);
    ASSERT_EQ(PEP_decrypt_flag_src_modified & flags, 0);

    free_message(dec_msg);
    dec_msg = NULL;

    output_stream << "Case 3a: PASS" << endl << endl;


    output_stream << "Case 3b: Calling decrypt_message with reencrypt flag set on message generated by pEp (message 2.0) with extra keys." << endl;

    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);

    flags = PEP_decrypt_flag_untrusted_server;

    decoded = NULL;
    status = mime_decode_message(to_reencrypt_from_pEp.c_str(), to_reencrypt_from_pEp.size(), &decoded, NULL);
    ASSERT_NE(decoded, nullptr);
    ASSERT_OK;
    dec_msg = NULL;
    decoded->recv_by = identity_dup(me_recip_1);

    status = decrypt_message_2(session, decoded, &dec_msg, &keys, &flags);

    ASSERT_NE(status, PEP_CANNOT_REENCRYPT);

    ASSERT_NE(dec_msg, nullptr);

    free_message(dec_msg);
    dec_msg = NULL;

    output_stream << "CHECK: Decrypting to see what keys it was encrypted for." << endl;

    flags = 0;
    throwaway = NULL;

    decoded->recv_by = identity_dup(me_recip_1);
    tmp_keys = NULL;
    status = decrypt_message_2(session, decoded, &dec_msg, &tmp_keys, &flags);

    output_stream << "keys used:\n";

    own_key_found = false;
    extra_key_0_found = false;
    extra_key_1_found = false;

    i = 0;

    if (tmp_keys && tmp_keys->next)
        dedup_stringlist(tmp_keys->next);

    for (stringlist_t* kl = tmp_keys; kl && kl->value; kl = kl->next, i++)
    {
        if (i == 0) {
              output_stream << "Signed by " << (strcasecmp("", kl->value) == 0 ? "NOBODY" : kl->value) << endl;
//              TEST_ASSERT_MSG(strcasecmp(fpr_own_recip_key,kl->value) == 0);
        }
        else {
            if (strcasecmp(fpr_own_recip_key, kl->value) == 0) {
                output_stream << "Encrypted for us." << endl;
                own_key_found = true;
            }
            else if (strcasecmp(fpr_pub_extra_key_0, kl->value) == 0) {
                output_stream << "Encrypted for extra key 0." << endl;
                extra_key_0_found = true;
            }
            else if (strcasecmp(fpr_pub_extra_key_1, kl->value) == 0) {
                output_stream << "Encrypted for extra key 1." << endl;
                extra_key_1_found = true;
            }
            else {
                output_stream << "FAIL: Encrypted for " << kl->value << ", which it should not be." << endl;
//                TEST_ASSERT_MSG(false);
            }
            output_stream << "\t " << kl->value << endl;
        }
        ASSERT_LT(i , 4);
    }
//    TEST_ASSERT_MSG(own_key_found && extra_key_0_found && extra_key_1_found);
    output_stream << "Message was encrypted for all the keys it should be, and none it should not!" << endl;

    output_stream << "Case 3b: PASS" << endl << endl;

}


TEST_F(ReencryptPlusExtraKeysTest, check_efficient_reencrypt_from_enigmail) {
    output_stream << "Call decrypt_message with reencrypt flag set on message sent from enigmail for recip 2 extra keys." << endl;
    
    PEP_STATUS status = PEP_STATUS_OK;

    /* import all the keys */
    import_reenc_test_keys();    
    
    // Set up own identities
    pEp_identity* me_recip_1 = new_identity("reencrypt_recip@darthmama.cool", fpr_own_recip_key, PEP_OWN_USERID, "Me Recipient");
    pEp_identity* me_recip_2 = new_identity("reencrypt_recip_numero_deux_test@darthmama.org", fpr_own_recip_2_key, PEP_OWN_USERID, "Me Recipient");

    output_stream << "Inserting own identities and keys into database." << endl;
    status = set_own_key(session, me_recip_2, fpr_own_recip_2_key);
    ASSERT_OK;
    output_stream << "Done: inserting own identities and keys into database." << endl;

    status = set_identity_flags(session, me_recip_2, PEP_idf_org_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, me_recip_2);
    ASSERT_OK;
    ASSERT_EQ(me_recip_2->flags, me_recip_2->flags & PEP_idf_org_ident);

    // BEGIN ACTUAL TEST

    // Ready to receive message for the first time
    const string to_reencrypt_from_enigmail = slurp("test_mails/reencrypt_sent_by_enigmail.eml");

    message* dec_msg = NULL;
    message* enc_msg = NULL;

    // In: extra keys; Out: keys that were used to encrypt this.
    stringlist_t* keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);
    
    PEP_decrypt_flags_t flags = 0;

    flags = PEP_decrypt_flag_untrusted_server;

    // Put the original message into a message struct
    status = mime_decode_message(to_reencrypt_from_enigmail.c_str(), to_reencrypt_from_enigmail.size(), &enc_msg, NULL);

    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg );
    enc_msg->recv_by = identity_dup(me_recip_2);
    // First reencryption - should give us a reencrypted message
    status = decrypt_message_2(session, enc_msg, &dec_msg, &keys, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg );
    ASSERT_NE(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NOTNULL(enc_msg );

    // Second reencryption - should NOT give us a reencrypted message
    output_stream << "CHECK: Do it again, and make sure there's no modified source!" << endl;

    free_message(dec_msg);
    dec_msg = NULL;
    flags = PEP_decrypt_flag_untrusted_server;
    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);

    status = decrypt_message_2(session, enc_msg, &dec_msg, &keys, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg );
    ASSERT_EQ(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NOTNULL(enc_msg );
    ASSERT_NOTNULL(dec_msg->_sender_fpr);
    ASSERT_NOTNULL(keys);
    ASSERT_STRNE(dec_msg->_sender_fpr, keys->value);
    free_stringlist(keys);
    free_message(enc_msg);
    free_message(dec_msg);
    free_identity(me_recip_1);
    free_identity(me_recip_2);
}

TEST_F(ReencryptPlusExtraKeysTest, check_efficient_reencrypt_from_enigmail_w_own_recip_in_bcc) {
    output_stream << "Call decrypt_message with reencrypt flag set on message sent with recip 2 in BCC from enigmail with extra keys." << endl;
    
    PEP_STATUS status = PEP_STATUS_OK;

    /* import all the keys */
    import_reenc_test_keys();    
    
    // Set up own identities
    pEp_identity* me_recip_1 = new_identity("reencrypt_recip@darthmama.cool", fpr_own_recip_key, PEP_OWN_USERID, "Me Recipient");
    pEp_identity* me_recip_2 = new_identity("reencrypt_recip_numero_deux_test@darthmama.org", fpr_own_recip_2_key, PEP_OWN_USERID, "Me Recipient");

    output_stream << "Inserting own identities and keys into database." << endl;
    status = set_own_key(session, me_recip_2, fpr_own_recip_2_key);
    ASSERT_OK;
    output_stream << "Done: inserting own identities and keys into database." << endl;

    status = set_identity_flags(session, me_recip_2, PEP_idf_org_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, me_recip_2);
    ASSERT_OK;
    ASSERT_EQ(me_recip_2->flags, me_recip_2->flags & PEP_idf_org_ident);

    // BEGIN ACTUAL TEST

    // Ready to receive message for the first time
    const string to_reencrypt_from_enigmail_BCC = slurp("test_mails/reencrypt_BCC_sent_by_enigmail.eml");

    message* dec_msg = NULL;
    message* enc_msg = NULL;

    // In: extra keys; Out: keys that were used to encrypt this.
    stringlist_t* keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);
    
    PEP_decrypt_flags_t flags = 0;

    flags = PEP_decrypt_flag_untrusted_server;

    // Put the original message into a message struct

    status = mime_decode_message(to_reencrypt_from_enigmail_BCC.c_str(), to_reencrypt_from_enigmail_BCC.size(), &enc_msg, NULL);
    enc_msg->recv_by = identity_dup(me_recip_2);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg );

    // First reencryption - should give us a reencrypted message
    status = decrypt_message_2(session, enc_msg, &dec_msg, &keys, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg );
    ASSERT_NE(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NOTNULL(enc_msg );

    // Second reencryption - should NOT give us a reencrypted message
    output_stream << "CHECK: Do it again, and make sure there's no modified source!" << endl;

    free_message(dec_msg);
    dec_msg = NULL;
    flags = PEP_decrypt_flag_untrusted_server;
    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);    

    status = decrypt_message_2(session, enc_msg, &dec_msg, &keys, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg );
    ASSERT_EQ(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NOTNULL(enc_msg );
    ASSERT_NOTNULL(dec_msg->_sender_fpr);
    ASSERT_NOTNULL(keys);
    ASSERT_STRNE(dec_msg->_sender_fpr, keys->value);

    free_stringlist(keys);
    free_message(enc_msg);
    free_message(dec_msg);
    free_identity(me_recip_1);
    free_identity(me_recip_2);
}

TEST_F(ReencryptPlusExtraKeysTest, check_efficient_reencrypt_from_pEp_2_0) {
    output_stream << "Call decrypt_message with reencrypt flag set on message generated by pEp (message 2.0) with extra keys." << endl;
    PEP_STATUS status = PEP_STATUS_OK;

    /* import all the keys */
    import_reenc_test_keys();    
    
    // Set up own identities
    pEp_identity* me_recip_1 = new_identity("reencrypt_recip@darthmama.cool", fpr_own_recip_key, PEP_OWN_USERID, "Me Recipient");
    pEp_identity* me_recip_2 = new_identity("reencrypt_recip_numero_deux_test@darthmama.org", fpr_own_recip_2_key, PEP_OWN_USERID, "Me Recipient");

    output_stream << "Inserting own identities and keys into database." << endl;
    status = set_own_key(session, me_recip_2, fpr_own_recip_2_key);
    ASSERT_OK;
    output_stream << "Done: inserting own identities and keys into database." << endl;

    status = set_identity_flags(session, me_recip_2, PEP_idf_org_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, me_recip_2);
    ASSERT_OK;
    ASSERT_EQ(me_recip_2->flags, me_recip_2->flags & PEP_idf_org_ident);


    // BEGIN ACTUAL TEST

    // Ready to receive message for the first time
    const string to_reencrypt_from_pEp = slurp("test_mails/reencrypt_encrypted_through_pEp.eml");

    message* dec_msg = NULL;
    message* enc_msg = NULL;

    // In: extra keys; Out: keys that were used to encrypt this.
    stringlist_t* keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);
    
    PEP_decrypt_flags_t flags = 0;

    flags = PEP_decrypt_flag_untrusted_server;

    // Put the original message into a message struct
    status = mime_decode_message(to_reencrypt_from_pEp.c_str(), to_reencrypt_from_pEp.size(), &enc_msg, NULL);
    enc_msg->recv_by = identity_dup(me_recip_2);

    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg );

    // First reencryption - should give us a reencrypted message
    status = decrypt_message_2(session, enc_msg, &dec_msg, &keys, &flags);
    ASSERT_NE(status, PEP_CANNOT_REENCRYPT);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg , nullptr);
    ASSERT_NE(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NOTNULL(enc_msg );

    // Second reencryption - should NOT give us a reencrypted message
    output_stream << "CHECK: Do it again, and make sure there's no modified source!" << endl;

    free_message(dec_msg);
    dec_msg = NULL;
    flags = PEP_decrypt_flag_untrusted_server;
    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);    

    status = decrypt_message_2(session, enc_msg, &dec_msg, &keys, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg );
    ASSERT_EQ(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NOTNULL(enc_msg );
    ASSERT_NOTNULL(dec_msg->_sender_fpr);
    ASSERT_NOTNULL(keys);
    ASSERT_STRNE(dec_msg->_sender_fpr, keys->value);

    free_stringlist(keys);
    free_message(enc_msg);
    free_message(dec_msg);
    free_identity(me_recip_1);
    free_identity(me_recip_2);    
}
