// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>
#include <iostream>
#include <fstream>

#include "TestUtilities.h"
#include "TestConstants.h"

#include "pEpEngine.h"
#include "pEp_internal.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for URIAddressTest
    class URIAddressTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            URIAddressTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~URIAddressTest() override {
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

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the URIAddressTest suite.

    };

}  // namespace

#if 0
TEST_F(URIAddressTest, check_uri_address_not_a_test) {
    const char* uri_addr = "payto://BIC/SYSTEM";

    pEp_identity* me = new_identity(uri_addr, NULL, "System", NULL);

    PEP_STATUS status = myself(session, me);

    ASSERT_OK;
    ASSERT_TRUE(me->fpr && me->fpr[0] != '\0');

    char* keydata = NULL;
    size_t keysize = 0;
    status = export_key(session, me->fpr,
                        &keydata, &keysize);

    ASSERT_GT(keydata && keysize, 0);
    
    ofstream outfile_pub, outfile_priv;
    outfile_pub.open("test_keys/pub/URI_address_test_key_pub.asc");
    outfile_pub << keydata;    
    outfile_pub.close();
    
    free(keydata);
    keydata = NULL;
    keysize = 0;

    status = export_secret_key(session, me->fpr,
                              &keydata, &keysize);

    ASSERT_GT(keydata && keysize, 0);
    
    outfile_priv.open("test_keys/priv/URI_address_test_key_priv.asc");  
    outfile_priv << keydata;
    outfile_priv.close();
}
#endif

// FIXME: URL, URN
TEST_F(URIAddressTest, check_uri_address_genkey) {
    const char* uri_addr = "shark://grrrr/39874293847092837443987492834";
    const char* uname = "GRRRR, the angry shark";

    pEp_identity* me = new_identity(uri_addr, NULL, PEP_OWN_USERID, uname);

    PEP_STATUS status = myself(session, me);

    ASSERT_OK;
    ASSERT_TRUE(me->fpr && me->fpr[0] != '\0');

    char* keydata = NULL;
    size_t keysize = 0;
    status = export_key(session, me->fpr,
                        &keydata, &keysize);

    ASSERT_GT(keydata && keysize, 0);
    // no guarantee of NUL-termination atm.
//    output_stream << keydata << endl;

    free(keydata);
    free_identity(me);
}

TEST_F(URIAddressTest, check_uri_address_genkey_empty_uname) {
    const char* uri_addr = "payto://BIC/SYSTEMB";
    const char* uname = "Jonas's Broken Identity";

    pEp_identity* me = new_identity(uri_addr, NULL, "SystemB", NULL);

    PEP_STATUS status = myself(session, me);

    ASSERT_OK;
    ASSERT_TRUE(me->fpr && me->fpr[0] != '\0');

    char* keydata = NULL;
    size_t keysize = 0;
    status = export_key(session, me->fpr,
                        &keydata, &keysize);

    ASSERT_GT(keydata && keysize, 0);
    // no guarantee of NUL-termination atm.
//    output_stream << keydata << endl;

    pEp_identity* me_copy = new_identity(uri_addr, NULL, "SystemB", NULL);
    status = myself(session, me_copy);

    ASSERT_OK;
    ASSERT_TRUE(me_copy->fpr && me_copy->fpr[0] != '\0');
    ASSERT_TRUE(me_copy->username && me_copy->username[0] != '\0');
        
    free(keydata);
    free_identity(me);
}

TEST_F(URIAddressTest, check_uri_address_encrypt_2_keys_no_uname) {
    const char* uri_addr_a = "payto://BIC/SYSTEMA";    
    const char* uri_addr_b = "payto://BIC/SYSTEMB";
    const char* uid_a = "SystemA";
    const char* uid_b = "SystemB";
    const char* fpr_a = "B425BAC5ED6014AAE8E34381429FA046E70B09F9";
    const char* fpr_b = "80C8BE340FBF59BCB54FAD1B53703426DCC3681E";
    slurp_and_import_key(session, "test_keys/pub/URI_address_test_key0_pub.asc");
    slurp_and_import_key(session, "test_keys/pub/URI_address_test_key1_pub.asc");
    slurp_and_import_key(session, "test_keys/priv/URI_address_test_key0_priv.asc");
    
    pEp_identity* me_setup = new_identity(uri_addr_a, fpr_a, uid_a, uri_addr_a);
    PEP_STATUS status = set_own_key(session, me_setup, fpr_a);    
    ASSERT_EQ(status, PEP_STATUS_OK);

    pEp_identity* me = new_identity(uri_addr_a, NULL, uid_a, NULL);
    status = myself(session, me);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(me->fpr);
    ASSERT_NOTNULL(me->username);    
    ASSERT_STREQ(me->fpr, fpr_a);
    ASSERT_STREQ(me->username, uri_addr_a);
    
    // Try without a userid
    pEp_identity* you = new_identity(uri_addr_b, NULL, NULL, NULL);
    status = update_identity(session, you);
    ASSERT_EQ(status, PEP_STATUS_OK);
    // Post-key-election: has to be set
    ASSERT_NULL(you->fpr);
    you->fpr = strdup(fpr_b);
    status = set_default_fpr_for_test(session,  you, false);
    ASSERT_OK;
    free_identity(you);
    you = new_identity(uri_addr_b, NULL, NULL, NULL);
    status = update_identity(session, you);
    ASSERT_EQ(status, PEP_STATUS_OK);

    ASSERT_NOTNULL(you->fpr);
    ASSERT_NOTNULL(you->username);    
    ASSERT_STREQ(you->fpr, fpr_b);
    ASSERT_STREQ(you->username, uri_addr_b);
    ASSERT_NOTNULL(you->user_id);
    
    // Ok, all good. Let's go with fresh, ugly identities.
    message* msg = new_message(PEP_dir_outgoing);
    pEp_identity* me_from = new_identity(uri_addr_a, NULL, uid_a, NULL);
    // Give this one a UID, we'll check the TOFU while we're at it.
    pEp_identity* you_to = new_identity(uri_addr_b, NULL, uid_b, NULL);        
    msg->from = me_from;
    msg->to = new_identity_list(you_to);
    msg->shortmsg = strdup("Some swift stuff!");            
    msg->longmsg = strdup("Some more swift stuff!");
    
    message* outmsg = NULL;
    status = encrypt_message(session, msg, NULL, &outmsg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(outmsg);
    free_message(msg);
    free_message(outmsg);
    free_identity(me_setup);
    free_identity(me);
    free_identity(you);                
}

// FIXME: URL, URN
TEST_F(URIAddressTest, check_uri_address_encrypt) {
    const char* uri_addr = "shark://grrrr/39874293847092837443987492834";
    const char* uname = "GRRRR, the angry shark";

    pEp_identity* me = new_identity(uri_addr, NULL, PEP_OWN_USERID, uname);

    PEP_STATUS status = myself(session, me);

    ASSERT_OK;
    ASSERT_TRUE(me->fpr && me->fpr[0] != '\0');


    const char* you_uri_addr = "shark://bait/8uyoi3lu4hl2..dfoif983j4b@%";
    const char* youname = "Nemo, the delicious fish";
    pEp_identity* you = new_identity(you_uri_addr, NULL, "Food for Shark", youname);
    status = generate_keypair(session, you);
    ASSERT_OK;

    stringlist_t* keylist = NULL;
    status = find_keys(session, you_uri_addr, &keylist);
    ASSERT_OK;
    ASSERT_TRUE(keylist && keylist->value);

    // Ah, but now there is no key election, so we have to set it explicitly.
    you->fpr = strdup(keylist->value);
    set_default_fpr_for_test(session,  you, false);
    free(you->fpr);
    you->fpr = NULL;

    status = update_identity(session, you);
    ASSERT_OK;
    ASSERT_FALSE(EMPTYSTR(you->fpr));

    message* msg = new_message(PEP_dir_outgoing);

    msg->from = me;
    msg->to = new_identity_list(you);
    msg->shortmsg = strdup("Invitation");
    msg->longmsg = strdup("Yo Neems, wanna come over for dinner?");

    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    
    // We don't check for anything here??? FIXME! WTF!
}

// FIXME:
// KB: I'm not really sure what we're now testing here, since key election is now gone.
//
TEST_F(URIAddressTest, check_uri_address_tofu_1) {
    const char* sys_a_addr = "payto://BIC/SYSTEMA";
    const char* sys_b_addr = "payto://BIC/SYSTEMB";
    const char* sys_a_fpr = "4334D6DB751A8CA2B4944075462AFDB6DA3FB4B9";
    const char* sys_b_fpr = "F5199E0B0AC4059572DAD8EA76B63B2954139F26";
    
    slurp_and_import_key(session, "test_keys/priv/BIC_SYSTEMA_0xDA3FB4B9_priv.asc");
    slurp_and_import_key(session, "test_keys/pub/BIC_SYSTEMA_0xDA3FB4B9_pub.asc");
    slurp_and_import_key(session, "test_keys/pub/BIC_SYSTEMB_0x54139F26_pub.asc");

    pEp_identity* me = new_identity(sys_a_addr, NULL, PEP_OWN_USERID, sys_a_addr);
    PEP_STATUS status = set_own_key(session, me, sys_a_fpr);
    ASSERT_OK;

    status = myself(session, me);
    ASSERT_OK;
    ASSERT_TRUE(me->fpr && me->fpr[0] != '\0');

    // No more key election.
    pEp_identity* you = new_identity(sys_b_addr, NULL, "SYSTEM_B", NULL);
    status = update_identity(session, you);
    you->fpr = strdup(sys_b_fpr);
    status = set_identity(session, you);
    ASSERT_OK;


/*
    stringlist_t* keylist = NULL;
    status = update_identity(session, you);
    ASSERT_OK;
    ASSERT_TRUE(you->fpr && you->fpr[0] != '\0');
*/
    message* msg = new_message(PEP_dir_outgoing);

    msg->from = me;
    msg->to = new_identity_list(you);
    msg->shortmsg = strdup("Smurfs");
    msg->longmsg = strdup("Are delicious?");

    message* enc_msg = NULL;
    
    // We were doing key election here on purpose. Too bad now...
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);

    char* outmsg = NULL;
    mime_encode_message(enc_msg, false, &outmsg, false);
    output_stream << outmsg << endl;
    
    if (false) {
        ofstream outfile;
        outfile.open("test_mails/system_a_to_b_755_part_1.eml");
        outfile << outmsg;    
        outfile.close();    
    }
    free(outmsg);
    free_message(msg);
    free_message(enc_msg);
}

TEST_F(URIAddressTest, check_uri_address_tofu_2) {
    const char* sys_a_addr = "payto://BIC/SYSTEMA";
    const char* sys_b_addr = "payto://BIC/SYSTEMB";
    const char* sys_a_fpr = "4334D6DB751A8CA2B4944075462AFDB6DA3FB4B9";
    const char* sys_b_fpr = "F5199E0B0AC4059572DAD8EA76B63B2954139F26";
    
    slurp_and_import_key(session, "test_keys/pub/BIC_SYSTEMB_0x54139F26_pub.asc");
    slurp_and_import_key(session, "test_keys/priv/BIC_SYSTEMB_0x54139F26_priv.asc");
    slurp_and_import_key(session, "test_keys/pub/BIC_SYSTEMA_0xDA3FB4B9_pub.asc");

    pEp_identity* me = new_identity(sys_b_addr, NULL, PEP_OWN_USERID, sys_b_addr);
    PEP_STATUS status = set_own_key(session, me, sys_b_fpr);
    ASSERT_OK;

    status = myself(session, me);
    ASSERT_OK;
    ASSERT_TRUE(me->fpr && me->fpr[0] != '\0');  
    
    pEp_identity* you = new_identity(sys_b_addr, NULL, "SYSTEM_B", NULL);
    status = update_identity(session, you);
    // No more key election.
    you->fpr = strdup(sys_b_fpr);
    status = set_identity(session, you);
    ASSERT_OK;
        
    string msg_txt = slurp("test_mails/system_a_to_b_755_part_1.eml");
    message* msg = NULL;
    
    mime_decode_message(msg_txt.c_str(), msg_txt.size(), &msg, NULL);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message_2(session, msg, &dec_msg, &keylist, &flags); 

    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(dec_msg);
    ASSERT_NOTNULL(dec_msg->from);
    ASSERT_NOTNULL(dec_msg->to);
    ASSERT_NOTNULL(dec_msg->to->ident);
    ASSERT_STREQ(dec_msg->from->address, "payto://BIC/SYSTEMA");
    ASSERT_STREQ(dec_msg->to->ident->address, "payto://BIC/SYSTEMB");    
}
