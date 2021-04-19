// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "test_util.h"


#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for UserIdCollisionTest
    class UserIdCollisionTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

            // own user
            pEp_identity* user_alice;
            // real ID, only minimal info w/ username
            pEp_identity* real_alex;
            // tofu ID, only minimal info w/ username        
            pEp_identity* tofu_alex;
            // real ID, only minimal info w/o username
            pEp_identity* real_alex_0;
            // tofu ID, only minimal info w/o username
            pEp_identity* tofu_alex_0;
            // real ID, only minimal info w/o username
            pEp_identity* real_alex_1;
            // tofu ID, only minimal info w/o username
            pEp_identity* tofu_alex_1;
            // real ID, various kinds of info
            pEp_identity* real_alex_2;
            // tofu ID, various kinds of info
            pEp_identity* tofu_alex_2;
            // real ID, various kinds of info
            pEp_identity* real_alex_3;
            // tofu ID, various kinds of info        
            pEp_identity* tofu_alex_3;
            // tofu ID, various kinds of info        
            pEp_identity* tofu_alex_4;
            // real ID, various kinds of info
            pEp_identity* real_alex_4;
            // tofu ID, various kinds of info        
            pEp_identity* tofu_alex_5;
            // real ID, various kinds of info
            pEp_identity* real_alex_5;
            // tofu ID, various kinds of info        
            pEp_identity* tofu_alex_6a;
            // real ID, various kinds of info
            pEp_identity* real_alex_6a;
            // tofu ID, various kinds of info        
            pEp_identity* tofu_alex_6b;
            // real ID, various kinds of info
            pEp_identity* real_alex_6b;
            // tofu ID, various kinds of info        
            pEp_identity* tofu_alex_6c;
            // real ID, various kinds of info
            pEp_identity* real_alex_6c;
            // tofu ID, various kinds of info        
            pEp_identity* tofu_alex_6d;
            // real ID, various kinds of info
            pEp_identity* real_alex_6d;
            
            const char* const alice_keyfile = "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc";
            const char* const alice_keyid = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
            const char* const alice_email = "pep.test.alice@pep-project.org";
            const char* const alex_keyfile = "test_keys/pub/pep.test.alexander-0x26B54E4E_pub.asc";
            const char* const alex_keyid = "3AD9F60FAEB22675DB873A1362D6981326B54E4E";        
            const char* const alex_email = "pep.test.alexander@peptest.ch";        
            const char* const alex0_keyfile = "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc";
            const char* const alex0_keyid = "F4598A17D4690EB3B5B0F6A344F04E963B7302DB";
            const char* const alex0_email = "pep.test.alexander0@darthmama.org";                
            const char* const alex1_keyfile = "test_keys/pub/pep.test.alexander1-0x541260F6_pub.asc";
            const char* const alex1_keyid = "59AF4C51492283522F6904531C09730A541260F6";        
            const char* const alex1_email = "pep.test.alexander1@darthmama.org";                                
            const char* const alex2_keyfile = "test_keys/pub/pep.test.alexander2-0xA6512F30_pub.asc";
            const char* const alex2_keyid = "46A994F19077C05610870273C4B8AB0BA6512F30";
            const char* const alex2_email = "pep.test.alexander2@darthmama.org";                                
            const char* const alex3_keyfile = "test_keys/pub/pep.test.alexander3-0x724B3975_pub.asc";
            const char* const alex3_keyid = "5F7076BBD92E14EA49F0DF7C2CE49419724B3975";        
            const char* const alex3_email = "pep.test.alexander3@darthmama.org";                
            const char* const alex4_keyfile = "test_keys/pub/pep.test.alexander4-0x844B9DCF_pub.asc";
            const char* const alex4_keyid = "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF";        
            const char* const alex4_email = "pep.test.alexander4@darthmama.org";                
            const char* const alex5_keyfile = "test_keys/pub/pep.test.alexander5-0x0773CD29_pub.asc";
            const char* const alex5_keyid = "58BCC2BF2AE1E3C4FBEAB89AD7838ACA0773CD29";        
            const char* const alex5_email = "pep.test.alexander5@darthmama.org";                
            const char* const alex6a_keyfile = "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc";
            const char* const alex6a_keyid = "B4CE2F6947B6947C500F0687AEFDE530BDA17020";        
            const char* const alex6_email = "pep.test.alexander6@darthmama.org";                
            const char* const alex6b_keyfile = "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc";
            const char* const alex6b_keyid = "2E21325D202A44BFD9C607FCF095B202503B14D8";        
            const char* const alex6c_keyfile = "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc";
            const char* const alex6c_keyid = "3C1E713D8519D7F907E3142D179EAA24A216E95A";        
            const char* const alex6d_keyfile = "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc";
            const char* const alex6d_keyid = "74D79B4496E289BD8A71B70BA8E2C4530019697D";        

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            UserIdCollisionTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~UserIdCollisionTest() override {
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
                user_alice = new_identity(alice_email, alice_keyid, PEP_OWN_USERID, "Alice from Mel's Diner");
                slurp_and_import_key(session, alice_keyfile);

                real_alex = new_identity(alex_email, alex_keyid, "AlexID", "Alexander the Mediocre");

                tofu_alex = new_identity(alex_email, alex_keyid, NULL, NULL);

                real_alex_0 = new_identity(alex_email, alex_keyid, "Alex0", "Alexander the Mediocre");

                tofu_alex_0 = new_identity(alex_email, alex_keyid, NULL, NULL);

                real_alex_1 = new_identity(alex1_email, alex_keyid, "Alex1", NULL);

                tofu_alex_1 = new_identity(alex1_email, alex1_keyid, NULL, NULL);

                real_alex_2 = new_identity(alex2_email, alex1_keyid, "Alex2", NULL);

                tofu_alex_2 = new_identity(alex2_email, alex2_keyid, NULL, NULL);

                real_alex_3 = new_identity(alex3_email, alex2_keyid, "Alex3", NULL);

                tofu_alex_3 = new_identity(alex3_email, alex3_keyid, NULL, NULL);

                real_alex_4 = new_identity(alex4_email, alex3_keyid, "Alex4", NULL);

                tofu_alex_4 = new_identity(alex4_email, alex4_keyid, NULL, NULL);

                real_alex_5 = new_identity(alex5_email, alex4_keyid, "Alex5", NULL);

                tofu_alex_5 = new_identity(alex5_email, alex5_keyid, NULL, NULL);

                real_alex_6a = new_identity(alex6_email, alex5_keyid, "Alex6", NULL);

                tofu_alex_6a = new_identity(alex6_email, alex6a_keyid, NULL, NULL);

                real_alex_6b = new_identity(alex6_email, alex6a_keyid, "Alex6", NULL);

                tofu_alex_6b = new_identity(alex6_email, alex6b_keyid, NULL, NULL);

                real_alex_6c = new_identity(alex6_email, alex6b_keyid, "Alex6", NULL);

                tofu_alex_6c = new_identity(alex6_email, alex6c_keyid, NULL, NULL);

                real_alex_6d = new_identity(alex6_email, alex6c_keyid, "Alex6", NULL);

                tofu_alex_6d = new_identity(alex6_email, alex6d_keyid, NULL, NULL);
                
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                free_identity(real_alex);
                free_identity(real_alex_0);
                free_identity(real_alex_1);
                free_identity(real_alex_2);
                free_identity(real_alex_3);
                free_identity(real_alex_4);
                free_identity(real_alex_5);
                free_identity(real_alex_6a);
                free_identity(real_alex_6b);
                free_identity(real_alex_6c);
                free_identity(real_alex_6d);
                free_identity(tofu_alex);
                free_identity(tofu_alex_0);
                free_identity(tofu_alex_1);
                free_identity(tofu_alex_2);
                free_identity(tofu_alex_3);
                free_identity(tofu_alex_4);
                free_identity(tofu_alex_5);
                free_identity(tofu_alex_6a);
                free_identity(tofu_alex_6b);
                free_identity(tofu_alex_6c);
                free_identity(tofu_alex_6d);

                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the UserIdCollisionTest suite.

    };

}  // namespace

//
// Create TOFU identity, set its FPR in the DB, test real id collision
// 
TEST_F(UserIdCollisionTest, simple_tofu_collision) {
    slurp_and_import_key(session,alex_keyfile);
    tofu_alex->username = strdup("Alexander the Mediocre");
    PEP_STATUS status = update_identity(session, tofu_alex);
    ASSERT_OK;
    string tofu_id = string("TOFU_") + alex_email;
    ASSERT_STREQ(tofu_alex->user_id, tofu_id.c_str());
    ASSERT_NULL(tofu_alex->fpr);
    status = set_fpr_preserve_ident(session, tofu_alex, alex_keyid, false);
    ASSERT_OK;
    status = update_identity(session, tofu_alex);
    ASSERT_OK;
    ASSERT_STREQ(tofu_alex->fpr, alex_keyid);

    status = update_identity(session, real_alex);
    ASSERT_OK;
    ASSERT_STREQ(real_alex->fpr, alex_keyid);
    bool tofu_still_exists = false;
    status = exists_person(session, tofu_alex, &tofu_still_exists);
    ASSERT_OK;
    ASSERT_FALSE(tofu_still_exists);
}

//
// Create TOFU identity, set its FPR in the DB, test real id collision
// with different usernames. Real ID shouldn't pick up the TOFU information
// OR its key, since key election has been removed.
// 
TEST_F(UserIdCollisionTest, simple_tofu_collision_different_usernames) {
    slurp_and_import_key(session,alex_keyfile);
    tofu_alex->username = strdup("Alexander Hamilton");
    PEP_STATUS status = update_identity(session, tofu_alex);
    ASSERT_OK;
    string tofu_id = string("TOFU_") + alex_email;
    ASSERT_STREQ(tofu_alex->user_id, tofu_id.c_str());
    ASSERT_NULL(tofu_alex->fpr);
    status = set_fpr_preserve_ident(session, tofu_alex, alex_keyid, false);
    ASSERT_OK;
    status = update_identity(session, tofu_alex);
    ASSERT_OK;
    ASSERT_STREQ(tofu_alex->fpr, alex_keyid);

    // Ok, so we had a TOFU id with a real username. It's different from THIS
    // username. As such, we shouldn't find a key here, because things won't 
    // be merged. // FIXME: This should change, probably. Discuss with Volker.
    status = update_identity(session, real_alex);
    ASSERT_OK;
    ASSERT_NULL(real_alex->fpr);

    bool tofu_still_exists = false;
    status = exists_person(session, tofu_alex, &tofu_still_exists);
    ASSERT_OK;

    // SHOULD still exist, because we don't replace when usernames differ
    ASSERT_TRUE(tofu_still_exists);
}

//
// Create TOFU identity, set its FPR in the DB, test second same tofu id collision
// with same usernames. Mostly, this test appears to check if things don't blow up
// when you don't update the TOFU id?
// 
TEST_F(UserIdCollisionTest, tofu_two_tofus_no_collision) {
    slurp_and_import_key(session,alex6a_keyfile);

    tofu_alex_6a->username = strdup("Alexander Hamilton");
    tofu_alex_6b->username = strdup("Alexander Hamilton");

    tofu_alex_6a->lang[0] = 'j';
    tofu_alex_6a->lang[1] = 'p';

    PEP_STATUS status = update_identity(session, tofu_alex_6a);
    ASSERT_OK;
    string tofu_id = string("TOFU_") + alex6_email;
    ASSERT_STREQ(tofu_alex_6a->user_id, tofu_id.c_str());
    ASSERT_NULL(tofu_alex_6a->fpr);
    status = set_fpr_preserve_ident(session, tofu_alex_6a, alex6a_keyid, false);
    ASSERT_OK;
    status = update_identity(session, tofu_alex_6a);
    ASSERT_OK;
    ASSERT_STREQ(tofu_alex_6a->fpr, alex6a_keyid);

    // Ok, we call with the same explicit TOFU id (?)
    tofu_alex_6b->user_id = strdup(tofu_id.c_str());
    status = update_identity(session, tofu_alex_6b);
    ASSERT_OK;
    ASSERT_STREQ(tofu_alex_6b->fpr, alex6a_keyid);
    bool tofu_still_exists = false;
    status = exists_person(session, tofu_alex_6a, &tofu_still_exists);
    ASSERT_OK;

    ASSERT_TRUE(tofu_still_exists);
    ASSERT_EQ(tofu_alex_6b->lang[0] , 'j');
    ASSERT_EQ(tofu_alex_6b->lang[1] , 'p');
}

TEST_F(UserIdCollisionTest, tofu_collision_same_tofus_diff_usernames) {
    slurp_and_import_key(session,alex6a_keyfile);

    tofu_alex_6a->username = strdup("Alexander Hamilton");
    tofu_alex_6b->username = strdup("Alexander the Not-Cool-At-All");

    tofu_alex_6a->lang[0] = 'j';
    tofu_alex_6a->lang[1] = 'p';

    PEP_STATUS status = update_identity(session, tofu_alex_6a);
    ASSERT_OK;
    string tofu_id = string("TOFU_") + alex6_email;
    ASSERT_STREQ(tofu_alex_6a->user_id, tofu_id.c_str());
    ASSERT_NULL(tofu_alex_6a->fpr);
    status = set_fpr_preserve_ident(session, tofu_alex_6a, alex6a_keyid, false);
    ASSERT_OK;
    status = update_identity(session, tofu_alex_6a);
    ASSERT_OK;
    ASSERT_STREQ(tofu_alex_6a->fpr, alex6a_keyid);

    // FIXME: This is such a weird thing... check this
    //
    // Ok, NOW we put in an explicit TOFU
    tofu_alex_6b->user_id = strdup(tofu_id.c_str());
    status = update_identity(session, tofu_alex_6b);
    ASSERT_OK;
    ASSERT_STREQ(tofu_alex_6b->fpr, alex6a_keyid);
    bool tofu_still_exists = false;
    status = exists_person(session, tofu_alex_6a, &tofu_still_exists);
    ASSERT_OK;
    // SHOULD still exist, because we don't replace when usernames differ
    ASSERT_TRUE(tofu_still_exists);
    ASSERT_EQ(tofu_alex_6b->lang[0] , 'j');
    ASSERT_EQ(tofu_alex_6b->lang[1] , 'p');
    ASSERT_STREQ(tofu_alex_6b->username, "Alexander the Not-Cool-At-All");
}

TEST_F(UserIdCollisionTest, real_followed_by_explicit_tofu) {
    slurp_and_import_key(session,alex_keyfile);
    real_alex->username = strdup("Alexander the Mediocre");
 
    PEP_STATUS status = update_identity(session, real_alex);
    ASSERT_OK;
    ASSERT_NULL(real_alex->fpr);
    status = set_fpr_preserve_ident(session, real_alex, alex_keyid, false);
    ASSERT_OK;
    status = update_identity(session, real_alex);
    ASSERT_OK;
    ASSERT_STREQ(real_alex->fpr, alex_keyid);

    string tofu_id = string("TOFU_") + alex_email;
    tofu_alex->username = strdup(real_alex->username);
    tofu_alex->user_id = strdup(tofu_id.c_str());
    status = update_identity(session, tofu_alex);
    ASSERT_OK;
    ASSERT_STREQ(tofu_alex->user_id, "AlexID");
    bool tofu_still_exists = false;
    free(tofu_alex->user_id);
    tofu_alex->user_id = strdup(tofu_id.c_str());
    status = exists_person(session, tofu_alex, &tofu_still_exists);
    ASSERT_OK;
    ASSERT_FALSE(tofu_still_exists);
}

TEST_F(UserIdCollisionTest, merge_records_normal) {
    // Tofu 6a has lots of stuff.
    slurp_and_import_key(session,alex6a_keyfile);
    tofu_alex_6a->username = strdup("Alexander Hamilton");
    tofu_alex_6a->lang[0] = 'e';
    tofu_alex_6a->lang[1] = 's';
    PEP_STATUS status = update_identity(session, tofu_alex_6a);
    slurp_and_import_key(session,alex6c_keyfile);
    free(tofu_alex_6a->fpr);
    tofu_alex_6a->fpr = strdup(alex6c_keyid);
    tofu_alex_6a->comm_type = PEP_ct_OpenPGP;
    status = set_identity(session, tofu_alex_6a);
    slurp_and_import_key(session,alex6d_keyfile);
    free(tofu_alex_6a->fpr);
    tofu_alex_6a->fpr = strdup(alex6d_keyid);
    tofu_alex_6a->comm_type = PEP_ct_pEp_unconfirmed; // ???
    status = set_identity(session, tofu_alex_6a);
    real_alex_6a->username = strdup(tofu_alex_6a->username);
    status = update_identity(session, real_alex_6a);
    ASSERT_OK;
    ASSERT_EQ(real_alex_6a->lang[0] , 'e');
    ASSERT_EQ(real_alex_6a->comm_type , PEP_ct_pEp_unconfirmed);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6c_keyid);
    status = get_trust(session, real_alex_6a);
    ASSERT_OK;
    ASSERT_EQ(real_alex_6a->comm_type , PEP_ct_OpenPGP);
}

TEST_F(UserIdCollisionTest, merge_records_set) {
    // Tofu 6a has lots of stuff.
    slurp_and_import_key(session,alex6a_keyfile);
    tofu_alex_6a->username = strdup("Alexander Hamilton");
    tofu_alex_6a->lang[0] = 'e';
    tofu_alex_6a->lang[1] = 's';
    PEP_STATUS status = update_identity(session, tofu_alex_6a);
    slurp_and_import_key(session,alex6b_keyfile);
    slurp_and_import_key(session,alex6c_keyfile);
    free(tofu_alex_6a->fpr);
    tofu_alex_6a->fpr = strdup(alex6c_keyid);
    tofu_alex_6a->comm_type = PEP_ct_pEp_unconfirmed;
    status = set_identity(session, tofu_alex_6a);
    status = set_as_pEp_user(session, tofu_alex_6a);
    slurp_and_import_key(session,alex6d_keyfile);
    free(tofu_alex_6a->fpr);
    tofu_alex_6a->fpr = strdup(alex6d_keyid);
    tofu_alex_6a->comm_type = PEP_ct_OpenPGP;
    status = set_identity(session, tofu_alex_6a);
    real_alex_6a->username = strdup(tofu_alex_6a->username);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6d_keyid);
    status = set_person(session, real_alex_6a, true); // NOT identit
    ASSERT_OK;
    status = update_identity(session, real_alex_6a);
    ASSERT_OK;
    ASSERT_EQ(real_alex_6a->lang[0] , 'e');
    ASSERT_EQ(real_alex_6a->comm_type , PEP_ct_pEp);
    bool pEp_peep = false;
    status = is_pEp_user(session, real_alex_6a, &pEp_peep);
    ASSERT_TRUE(pEp_peep);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6c_keyid);
    status = get_trust(session, real_alex_6a);
    ASSERT_EQ(real_alex_6a->comm_type , PEP_ct_pEp_unconfirmed);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6d_keyid);
    status = get_trust(session, real_alex_6a);
    ASSERT_EQ(real_alex_6a->comm_type , PEP_ct_pEp);
}

TEST_F(UserIdCollisionTest, merge_records_set_2) {
    // Tofu 6a has lots of stuff.
    slurp_and_import_key(session,alex6a_keyfile);
    tofu_alex_6a->username = strdup("Alexander Hamilton");
    tofu_alex_6a->lang[0] = 'e';
    tofu_alex_6a->lang[1] = 's';
    PEP_STATUS status = update_identity(session, tofu_alex_6a);
    slurp_and_import_key(session,alex6b_keyfile);
    slurp_and_import_key(session,alex6c_keyfile);
    free(tofu_alex_6a->fpr);
    tofu_alex_6a->fpr = strdup(alex6c_keyid);
    tofu_alex_6a->comm_type = PEP_ct_OpenPGP_unconfirmed;
    status = set_identity(session, tofu_alex_6a);
    slurp_and_import_key(session,alex6d_keyfile);
    free(tofu_alex_6a->fpr);
    tofu_alex_6a->fpr = strdup(alex6d_keyid);
    tofu_alex_6a->comm_type = PEP_ct_OpenPGP;
    status = set_identity(session, tofu_alex_6a);
    real_alex_6a->username = strdup(tofu_alex_6a->username);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6d_keyid);
    status = set_person(session, real_alex_6a, true); // NOT identity
    ASSERT_OK;
    status = set_as_pEp_user(session, real_alex_6a);
    ASSERT_OK;
    status = update_identity(session, real_alex_6a);
    ASSERT_OK;
    ASSERT_EQ(real_alex_6a->lang[0] , 'e');
    ASSERT_EQ(real_alex_6a->comm_type , PEP_ct_pEp);
    bool pEp_peep = false;
    status = is_pEp_user(session, real_alex_6a, &pEp_peep);
    ASSERT_TRUE(pEp_peep);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6c_keyid);
    status = get_trust(session, real_alex_6a);
    ASSERT_EQ(real_alex_6a->comm_type , PEP_ct_pEp_unconfirmed);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6d_keyid);
    status = get_trust(session, real_alex_6a);
    ASSERT_EQ(real_alex_6a->comm_type , PEP_ct_pEp);
}
