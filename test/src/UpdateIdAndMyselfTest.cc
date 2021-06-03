// This file is under GNU General Public License 3.0
// see LICENSE.txt

// N.B. This is a poorly split-up big monolithic test. We should, someday, refactor and do it right.

#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring> // for strcmp()
#include "TestConstants.h"

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "pEp_internal.h"
#include "message_api.h"
#include "keymanagement.h"
#include "TestUtilities.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

    //The fixture for UpdateIdAndMyselfTest
    class UpdateIdAndMyselfTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            UpdateIdAndMyselfTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~UpdateIdAndMyselfTest() override {
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
                start_username = strdup("Unser Testkandidat");
                myself_name = strdup("stupid_random_address@darthmama.cool");
            
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

            const char* testy_filename = "test_keys/testy_expired.pgp"; // pub/private keypair 
            const char* testy_fpr = "D1AEA592B78BEF2BE8D93C78DD835B271075DA7E";

            char* start_username = NULL;
            char* myself_name = NULL;
            const char* own_user_id = "Own_Beavis";
            char* generated_fpr = NULL;
            char* default_own_id = NULL;
            const char* alias_id = "Huss Es El Mejor Presidente Del Mundo!";
            char* new_fpr = NULL;
            const char* alex_address = "pep.test.alexander@peptest.ch";
            const char* alex_fpr = "3AD9F60FAEB22675DB873A1362D6981326B54E4E";
            const char* alex_userid = "Alex";
            const char* alex_username = "SuperDuperAlex";


        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the UpdateIdAndMyselfTest suite.

    };

}  // namespace

TEST_F(UpdateIdAndMyselfTest, check_myself_no_record_no_input_fpr) {

    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity * new_me = new_identity(myself_name, NULL, own_user_id, start_username);

    status = myself(session, new_me);
    ASSERT_OK;
    ASSERT_NOTNULL(new_me->fpr);
    ASSERT_EQ(new_me->comm_type, PEP_ct_pEp);

    free_identity(new_me);
}

TEST_F(UpdateIdAndMyselfTest, check_myself_no_input_fpr_w_record) {

    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity * new_me = new_identity(myself_name, NULL, own_user_id, start_username);

    status = myself(session, new_me);
    ASSERT_OK;
    ASSERT_NOTNULL(new_me->fpr);

    generated_fpr = strdup(new_me->fpr);
    free_identity(new_me);

    new_me = new_identity(myself_name, NULL, own_user_id, NULL);
    status = myself(session, new_me);
    ASSERT_OK;

    ASSERT_NOTNULL(new_me->fpr);
    ASSERT_STREQ(new_me->fpr, generated_fpr);
    ASSERT_NOTNULL(new_me->username);
    ASSERT_STREQ(new_me->username, start_username);
    ASSERT_NOTNULL(new_me->user_id);
    ASSERT_EQ(new_me->comm_type, PEP_ct_pEp);

    default_own_id = NULL;
    status = get_userid_alias_default(session, own_user_id, &default_own_id);
    if (status == PEP_CANNOT_FIND_ALIAS) {
        default_own_id = strdup(own_user_id);
    }

    ASSERT_STREQ(new_me->user_id, default_own_id);
    free_identity(new_me);
}

TEST_F(UpdateIdAndMyselfTest, check_myself_no_input_fpr_diff_user_id_w_record) {
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity * new_me = new_identity(myself_name, NULL, own_user_id, start_username);

    status = myself(session, new_me);
    ASSERT_OK;
    ASSERT_NOTNULL(new_me->fpr);
    generated_fpr = strdup(new_me->fpr);
    free_identity(new_me);
    new_me = NULL;

    status = PEP_STATUS_OK;
    new_me = new_identity(myself_name, NULL, alias_id, NULL);
    status = myself(session, new_me);
    ASSERT_OK;

    ASSERT_NOTNULL(new_me->fpr);
    ASSERT_STREQ(new_me->fpr, generated_fpr);
    ASSERT_NOTNULL(new_me->username);
    ASSERT_STREQ(new_me->username, start_username);
    ASSERT_NOTNULL(new_me->user_id);
    ASSERT_STREQ(new_me->user_id, own_user_id);
    ASSERT_EQ(new_me->comm_type, PEP_ct_pEp);

    char* tmp_def = NULL;

    status = get_userid_alias_default(session, alias_id, &tmp_def);
    ASSERT_OK;
    ASSERT_STREQ(tmp_def, own_user_id);

    free(tmp_def);
    tmp_def = NULL;
    free_identity(new_me);
}

TEST_F(UpdateIdAndMyselfTest, check_myself_replace_fpr) {
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity * new_me = new_identity(myself_name, NULL, own_user_id, start_username);

    status = myself(session, new_me);
    ASSERT_OK;
    ASSERT_NOTNULL(new_me->fpr);
    generated_fpr = strdup(new_me->fpr);
    free_identity(new_me);
    new_me = NULL;

    status = PEP_STATUS_OK;
    new_me = new_identity(myself_name, NULL, alias_id, start_username);
    status = generate_keypair(session, new_me);
    ASSERT_NOTNULL(new_me->fpr);

    output_stream << "Generated fingerprint ";
    output_stream << new_me->fpr << "\n";

    new_fpr = strdup(new_me->fpr);

    status = set_own_key(session, new_me, new_fpr);
    ASSERT_OK;
    ASSERT_NOTNULL(new_me->fpr);
    ASSERT_STRNE(new_me->fpr, generated_fpr);
    ASSERT_STREQ(new_me->fpr, new_fpr);
    ASSERT_NOTNULL(new_me->username);
    ASSERT_STREQ(new_me->username, start_username);
    ASSERT_NOTNULL(new_me->user_id);
    ASSERT_STREQ(new_me->user_id, own_user_id);
    ASSERT_TRUE(new_me->me);
    ASSERT_EQ(new_me->comm_type, PEP_ct_pEp);

    free_identity(new_me);
}

TEST_F(UpdateIdAndMyselfTest, check_myself_replace_fpr_revoke_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity * new_me = new_identity(myself_name, NULL, own_user_id, start_username);

    status = myself(session, new_me);
    ASSERT_OK;
    ASSERT_NOTNULL(new_me->fpr);
    generated_fpr = strdup(new_me->fpr);
    free_identity(new_me);
    new_me = NULL;

    status = PEP_STATUS_OK;
    new_me = new_identity(myself_name, NULL, alias_id, start_username);
    status = generate_keypair(session, new_me);
    ASSERT_NOTNULL(new_me->fpr);

    output_stream << "Generated fingerprint ";
    output_stream << new_me->fpr << "\n";

    new_fpr = strdup(new_me->fpr);
    
    status = PEP_STATUS_OK;
    status = revoke_key(session, generated_fpr, "Because it's fun");
    ASSERT_OK;

    new_me = new_identity(myself_name, NULL, alias_id, start_username);

    status = set_own_key(session, new_me, new_fpr);
    ASSERT_OK;
    ASSERT_NOTNULL(new_me->fpr);
    ASSERT_STRNE(new_me->fpr, generated_fpr);
    ASSERT_NOTNULL(new_me->username);
    ASSERT_STREQ(new_me->username, start_username);
    ASSERT_NOTNULL(new_me->user_id);
    ASSERT_STREQ(new_me->user_id, own_user_id);
    ASSERT_TRUE(new_me->me);
    ASSERT_EQ(new_me->comm_type, PEP_ct_pEp);

    status = myself(session, new_me);
    ASSERT_OK;
    ASSERT_NOTNULL(new_me->fpr);
    ASSERT_STRNE(new_me->fpr, generated_fpr);
    ASSERT_NOTNULL(new_me->username);
    ASSERT_STREQ(new_me->username, start_username);
    ASSERT_NOTNULL(new_me->user_id);
    ASSERT_STREQ(new_me->user_id, own_user_id);
    ASSERT_TRUE(new_me->me);
    ASSERT_EQ(new_me->comm_type, PEP_ct_pEp);

    free_identity(new_me);
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_w_matching_address_user_id_username) {
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_w_matching_address_user_id_new_username) {
}


TEST_F(UpdateIdAndMyselfTest, check_update_identity_w_matching_address_user_id_empty_username) {
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_w_matching_address_user_id_address_is_username) {
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_use_address_username_only) {
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_use_address_only) {
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_use_address_only_name_mismatch) {
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_use_address_only_on_own_ident) {
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_non_existent_user_id_address) {
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_address_username_userid_no_record) {
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_address_username_no_record) {
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_address_only_multiple_records) {
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_expired_key) {
    PEP_STATUS status = PEP_STATUS_OK;   

    // 1. create identity
    const char* bernd_address = "bernd.das.brot@darthmama.org";
    const char* bernd_fpr = "F8CE0F7E24EB190A2FCBFD38D4B088A7CAFAA422";
    const char* bernd_userid = "BERND_ID"; // simulate temp ID
    const char* bernd_username = "Bernd das Brot der Ultimative Testkandidat";
    const string bernd_pub_key = slurp("test_keys/pub/bernd.das.brot-0xCAFAA422_pub.asc");

    PEP_STATUS statuspub = import_key(session, bernd_pub_key.c_str(), bernd_pub_key.length(), NULL);
    ASSERT_EQ(statuspub, PEP_TEST_KEY_IMPORT_SUCCESS);

    pEp_identity* bernd = new_identity(bernd_address, bernd_fpr, bernd_userid, bernd_username);

    // 2. set identity
    status = set_identity(session, bernd);
    ASSERT_OK;
    free_identity(bernd);

    bernd = new_identity(bernd_address, NULL, bernd_userid, bernd_username);
    status = update_identity(session, bernd);
    ASSERT_OK;
    ASSERT_TRUE(bernd->fpr == nullptr || bernd->fpr[0] == '\0');
    ASSERT_NOTNULL(bernd->username);
    ASSERT_STREQ(bernd->username, bernd_username);
    ASSERT_NOTNULL(bernd->user_id);
    ASSERT_STREQ(bernd->user_id, bernd_userid); // ???
    ASSERT_TRUE(!bernd->me);
    ASSERT_EQ(bernd->comm_type, PEP_ct_key_not_found);
    ASSERT_STREQ(bernd->address, bernd_address);

    output_stream << "PASS: update_identity() correctly rejected expired key with PEP_ct_key_not_found" << endl << endl;
    free_identity(bernd);
}

// FIXME: rewrite for update_identity
TEST_F(UpdateIdAndMyselfTest, check_key_update_identity_only_revoked_mistrusted) {
    PEP_STATUS status = PEP_STATUS_OK;       
    ASSERT_OK;
//     // 17. key_elect_only_revoked_mistrusted() {
//     // Create id with no key
//     output_stream << "Creating new id with no key for : ";
//     char *myself_name_10000 = strdup("AAAAtestfool@testdomain.org");
//     for(int i=0; i < 4;i++)
//         myself_name_10000[i] += random() & 0xf;

//     output_stream << myself_name_10000 << "\n";

//     char* revoke_uuid = get_new_uuid();

//     pEp_identity * revokemaster_3000 = new_identity(myself_name_10000, NULL, revoke_uuid, start_username);

//     output_stream << "Generate three keys for "  << myself_name_10000 << " who has user_id " << revoke_uuid << endl;

//     char* revoke_fpr_arr[3];

//     status = generate_keypair(session, revokemaster_3000);
//     ASSERT_OK;
//     ASSERT_NOTNULL(revokemaster_3000->fpr);
//     revoke_fpr_arr[0] = strdup(revokemaster_3000->fpr);
//     free(revokemaster_3000->fpr);
//     revokemaster_3000->fpr = NULL;
//     output_stream << "revoke_fpr_arr[0] is " << revoke_fpr_arr[0] << endl;

//     status = generate_keypair(session, revokemaster_3000);
//     ASSERT_OK;
//     ASSERT_NOTNULL(revokemaster_3000->fpr);
//     revoke_fpr_arr[1] = strdup(revokemaster_3000->fpr);
//     free(revokemaster_3000->fpr);
//     revokemaster_3000->fpr = NULL;
//     output_stream << "revoke_fpr_arr[1] is " << revoke_fpr_arr[1] << endl;

//     status = generate_keypair(session, revokemaster_3000);
//     ASSERT_OK;
//     ASSERT_NOTNULL(revokemaster_3000->fpr);
//     revoke_fpr_arr[2] = strdup(revokemaster_3000->fpr);
//     free(revokemaster_3000->fpr);
//     revokemaster_3000->fpr = NULL;
//     output_stream << "revoke_fpr_arr[2] is " << revoke_fpr_arr[2] << endl;

//     output_stream << "Trust "  << revoke_fpr_arr[2] << " (default for identity) and " << revoke_fpr_arr[0] << endl;

//     free(revokemaster_3000->fpr);
//     revokemaster_3000->fpr = strdup(revoke_fpr_arr[2]);
//     status = trust_personal_key(session, revokemaster_3000);
//     ASSERT_OK;
//     status = get_trust(session, revokemaster_3000);
//     ASSERT_OK;
//     ASSERT_GT(revokemaster_3000->comm_type & PEP_ct_confirmed, 0);

//     free(revokemaster_3000->fpr);
//     revokemaster_3000->fpr = strdup(revoke_fpr_arr[0]);
//     status = trust_personal_key(session, revokemaster_3000);
//     ASSERT_OK;
//     status = get_trust(session, revokemaster_3000);
//     ASSERT_OK;
//     ASSERT_GT(revokemaster_3000->comm_type & PEP_ct_confirmed, 0);

//     status = update_identity(session, revokemaster_3000);
//     ASSERT_OK;
//     ASSERT_NOTNULL(revokemaster_3000->fpr);
//     ASSERT_STREQ(revokemaster_3000->fpr, revoke_fpr_arr[2]);
//     ASSERT_GT(revokemaster_3000->comm_type & PEP_ct_confirmed, 0);

//     output_stream << "update_identity returns the correct identity default." << endl;

//     output_stream << "Ok, now... we revoke the default..." << endl;

//     output_stream << "Revoking " << revoke_fpr_arr[2] << endl;

//     status = revoke_key(session, revoke_fpr_arr[2], "This little pubkey went to market");
//     ASSERT_OK;

//     bool is_revoked;
//     status = key_revoked(session, revokemaster_3000->fpr, &is_revoked);
//     ASSERT_OK;
//     ASSERT_TRUE(is_revoked);

//     output_stream << "Success revoking " << revoke_fpr_arr[2] << "!!! get_trust for this fpr gives us " << revokemaster_3000->comm_type << endl;

// //  KB: Is this still an issue, or did we delete some problematic code here, or...? 30.08.2019
// //  BAD ASSUMPTION - this only works if we query the trust DB in elect_pubkey, and we don't.
// //    output_stream << "Now see if update_identity gives us " << revoke_fpr_arr[0] << ", the only trusted key left." << endl;
//     status = update_identity(session, revokemaster_3000);
//     ASSERT_OK;
//     ASSERT_NOTNULL(revokemaster_3000->fpr);
//     bool was_key_0 = (strcmp(revokemaster_3000->fpr, revoke_fpr_arr[0]) == 0);
//     bool was_key_1 = (strcmp(revokemaster_3000->fpr, revoke_fpr_arr[1]) == 0);
//     ASSERT_TRUE(was_key_0 || was_key_1);
//     if (was_key_0)
//         ASSERT_GT(revokemaster_3000->comm_type & PEP_ct_confirmed, 0);
//     else
//         ASSERT_GT(revokemaster_3000->comm_type & PEP_ct_OpenPGP_unconfirmed, 0);

//     output_stream << "Success! So let's mistrust " << revoke_fpr_arr[0] << ", because seriously, that key was so uncool." << endl;

//     free(revokemaster_3000->fpr);
//     revokemaster_3000->fpr = strdup(revoke_fpr_arr[0]);
//     status = key_mistrusted(session, revokemaster_3000);
//     ASSERT_OK;

//     status = get_trust(session, revokemaster_3000);
//     ASSERT_OK;
//     ASSERT_EQ(revokemaster_3000->comm_type, PEP_ct_mistrusted);

//     output_stream << "Success! get_trust for this fpr gives us " << revokemaster_3000->comm_type << endl;

//     output_stream << "The only fpr left is an untrusted one - let's make sure this is what we get from update_identity." << endl;

//     status = update_identity(session, revokemaster_3000);
//     ASSERT_OK;
//     ASSERT_NOTNULL(revokemaster_3000->fpr);
//     ASSERT_STREQ(revokemaster_3000->fpr, revoke_fpr_arr[1]);
//     ASSERT_EQ(revokemaster_3000->comm_type & PEP_ct_confirmed, 0);

//     output_stream << "Success! We got " << revoke_fpr_arr[1] << "as the fpr with comm_type " << revokemaster_3000->comm_type << endl;

//     output_stream << "But, you know... let's revoke that one too and see what update_identity gives us." << endl;

//     status = revoke_key(session, revoke_fpr_arr[1], "Because it's more fun to revoke ALL of someone's keys");
//     ASSERT_OK;

//     status = key_revoked(session, revokemaster_3000->fpr, &is_revoked);
//     ASSERT_OK;
//     ASSERT_TRUE(is_revoked);

//     output_stream << "Success! get_trust for this fpr gives us " << revokemaster_3000->comm_type << endl;

//     output_stream << "Call update_identity - we expect nothing, plus an error comm type." << endl;

//     status = update_identity(session, revokemaster_3000);
//     ASSERT_NE(status, PEP_STATUS_OK);
//     ASSERT_NULL(revokemaster_3000->fpr);
//     ASSERT_NOTNULL(revokemaster_3000->username);
//     ASSERT_STREQ(revokemaster_3000->user_id, revoke_uuid);
//     ASSERT_EQ(revokemaster_3000->comm_type, PEP_ct_key_not_found);
//     output_stream << "Success! No key found. The comm_status error was " << revokemaster_3000->comm_type << "and the return status was " << tl_status_string(status) << endl;

//     free_identity(revokemaster_3000);
//     free(myself_name);
//     free(start_username);
//     free(generated_fpr);
//     free(default_own_id);
//     free(new_fpr);    
}

TEST_F(UpdateIdAndMyselfTest, check_myself_gen_password) {
    PEP_STATUS status;
    config_passphrase_for_new_keys(session, true, "test");
    pEp_identity* testy = new_identity("testy@darthmama.org", NULL, PEP_OWN_USERID, "Testy McKeys");
    testy->me = true;
    testy->comm_type = PEP_ct_pEp;
    status = set_identity(session, testy);
    ASSERT_OK;    

    status = myself(session, testy);    
    ASSERT_OK;
    ASSERT_NOTNULL(testy->fpr);
    ASSERT_NE(testy->fpr[0], '\0');
        
    status = probe_encrypt(session, testy->fpr);
    ASSERT_EQ(status, PEP_PASSPHRASE_REQUIRED);
    config_passphrase(session, "test");
    status = probe_encrypt(session, testy->fpr);
    ASSERT_OK;
}

TEST_F(UpdateIdAndMyselfTest, check_myself_gen_password_required) {
    PEP_STATUS status;
    
    session->new_key_pass_enable = true;
    
    pEp_identity* testy = new_identity("testy@darthmama.org", NULL, PEP_OWN_USERID, "Testy McKeys");
    testy->me = true;
    testy->comm_type = PEP_ct_pEp;
    status = set_identity(session, testy);
    ASSERT_OK;    

    status = myself(session, testy);    
    ASSERT_EQ(status, PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED);
}

TEST_F(UpdateIdAndMyselfTest, check_myself_gen_password_disable) {
    PEP_STATUS status;    
    config_passphrase_for_new_keys(session, true, "test");
    session->new_key_pass_enable = false;
    pEp_identity* testy = new_identity("testy@darthmama.org", NULL, PEP_OWN_USERID, "Testy McKeys");
    testy->me = true;
    testy->comm_type = PEP_ct_pEp;
    status = set_identity(session, testy);
    ASSERT_OK;    

    status = myself(session, testy);    
    ASSERT_OK;
    ASSERT_NOTNULL(testy->fpr);
    ASSERT_NE(testy->fpr[0], '\0');
        
    status = probe_encrypt(session, testy->fpr);
    ASSERT_OK;
}

TEST_F(UpdateIdAndMyselfTest, check_myself_renewal_password) {
    ASSERT_TRUE(slurp_and_import_key(session, testy_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, testy_fpr, &found_key);
    ASSERT_OK;
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
        
    pEp_identity* testy = new_identity("testy@darthmama.org", testy_fpr, PEP_OWN_USERID, "Testy McKeys");
    testy->me = true;
    testy->comm_type = PEP_ct_pEp;
    status = set_identity(session, testy);
    ASSERT_OK;    

    config_passphrase(session, "test");

    status = myself(session, testy);    
    ASSERT_OK;
    
    bool expired = false;
    status = key_expired(session, testy_fpr, time(NULL), &expired);
    ASSERT_OK;
    ASSERT_FALSE(expired);
    
    ASSERT_STREQ(testy_fpr, testy->fpr);
}    

TEST_F(UpdateIdAndMyselfTest, check_myself_renewal_wrong_password) {
    ASSERT_TRUE(slurp_and_import_key(session, testy_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, testy_fpr, &found_key);
    ASSERT_OK;
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
        
    pEp_identity* testy = new_identity("testy@darthmama.org", testy_fpr, PEP_OWN_USERID, "Testy McKeys");
    testy->me = true;
    testy->comm_type = PEP_ct_pEp;
    status = set_identity(session, testy);
    ASSERT_OK;    

    config_passphrase(session, "bob");

    status = myself(session, testy);    
    ASSERT_EQ(status, PEP_WRONG_PASSPHRASE);
}

TEST_F(UpdateIdAndMyselfTest, check_myself_renewal_requires_password) {
    ASSERT_TRUE(slurp_and_import_key(session, testy_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, testy_fpr, &found_key);
    ASSERT_OK;
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
        
    pEp_identity* testy = new_identity("testy@darthmama.org", testy_fpr, PEP_OWN_USERID, "Testy McKeys");
    testy->me = true;
    testy->comm_type = PEP_ct_pEp;
    status = set_identity(session, testy);
    ASSERT_OK;    

    status = myself(session, testy);    
    ASSERT_EQ(status, PEP_PASSPHRASE_REQUIRED);    
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_own_renewal_password) {
    ASSERT_TRUE(slurp_and_import_key(session, testy_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, testy_fpr, &found_key);
    ASSERT_OK;
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    // Force own identity to exist in DB, but not the onee we're working on
    pEp_identity* fake_id = new_identity("fake@fake.fake", NULL, PEP_OWN_USERID, "This identity is fake");
    fake_id->me = true;
    status = set_identity(session, fake_id);
    ASSERT_OK;            
        
    pEp_identity* testy = new_identity("testy@darthmama.org", testy_fpr, PEP_OWN_USERID, "Testy McKeys");
    status = set_identity(session, testy);
    ASSERT_OK;    

    config_passphrase(session, "test");

    free(testy->user_id);    
    testy->user_id = NULL;    
    status = update_identity(session, testy);    
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(testy->comm_type, PEP_ct_key_not_found);
    
    bool expired = false;
    status = key_expired(session, testy_fpr, time(NULL), &expired);
    ASSERT_OK;
    ASSERT_TRUE(expired);
}


TEST_F(UpdateIdAndMyselfTest, check_update_identity_own_renewal_wrong_password) {
    ASSERT_TRUE(slurp_and_import_key(session, testy_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, testy_fpr, &found_key);
    ASSERT_OK;
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);
    
    // Force own identity to exist in DB, but not the onee we're working on
    pEp_identity* fake_id = new_identity("fake@fake.fake", NULL, PEP_OWN_USERID, "This identity is fake");
    fake_id->me = true;
    status = set_identity(session, fake_id);
    ASSERT_OK;            
        
    pEp_identity* testy = new_identity("testy@darthmama.org", testy_fpr, PEP_OWN_USERID, "Testy McKeys");
    status = set_identity(session, testy);
    ASSERT_OK;    

    config_passphrase(session, "bob");

    free(testy->user_id);    
    testy->user_id = NULL;    
    status = update_identity(session, testy);    
    ASSERT_OK;
    ASSERT_EQ(testy->comm_type, PEP_ct_key_not_found);

    
    bool expired = false;
    status = key_expired(session, testy_fpr, time(NULL), &expired);
    ASSERT_OK;
    ASSERT_TRUE(expired);
}

TEST_F(UpdateIdAndMyselfTest, check_update_identity_own_renewal_requires_password) {
    ASSERT_TRUE(slurp_and_import_key(session, testy_filename));
    stringlist_t* found_key = NULL;
    PEP_STATUS status = find_keys(session, testy_fpr, &found_key);
    ASSERT_OK;
    ASSERT_NOTNULL(found_key);
    ASSERT_NOTNULL(found_key->value);

    // Force own identity to exist in DB, but not the onee we're working on
    pEp_identity* fake_id = new_identity("fake@fake.fake", NULL, PEP_OWN_USERID, "This identity is fake");
    fake_id->me = true;
    status = set_identity(session, fake_id);
    ASSERT_OK;            
        
    pEp_identity* testy = new_identity("testy@darthmama.org", testy_fpr, PEP_OWN_USERID, "Testy McKeys");
    status = set_identity(session, testy);
    ASSERT_OK;    

    free(testy->user_id);    
    testy->user_id = NULL;    
    status = update_identity(session, testy);    
    ASSERT_OK;
    ASSERT_EQ(testy->comm_type, PEP_ct_key_not_found);
    
    bool expired = false;
    status = key_expired(session, testy_fpr, time(NULL), &expired);
    ASSERT_OK;
    ASSERT_TRUE(expired);
}
