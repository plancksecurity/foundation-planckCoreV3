// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include "test_util.h"
#include "TestConstants.h"

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for OwnKeysRetrieveTest
    class OwnKeysRetrieveTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            OwnKeysRetrieveTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~OwnKeysRetrieveTest() override {
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
            // Objects declared here can be used by all tests in the OwnKeysRetrieveTest suite.

    };

}  // namespace


TEST_F(OwnKeysRetrieveTest, check_own_keys_retrieve_single_private) {
    // Setup own identity
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                PEP_OWN_USERID, "Alice in Wonderland", NULL, true
            );
    ASSERT_OK;

    // Ok, see if we get it back.
    stringlist_t* keylist = NULL;

    status = _own_keys_retrieve(session, &keylist, 0, true);
    ASSERT_OK;
    ASSERT_NOTNULL(keylist);
    ASSERT_NOTNULL(keylist->value);
    ASSERT_NULL(keylist->next);

    ASSERT_STREQ(keylist->value, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
}

TEST_F(OwnKeysRetrieveTest, check_own_keys_retrieve_single_private_single_pub) {
    // Set up an own idea that only has a public key
    PEP_STATUS status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                "pep.test.bob@pep-project.org", "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", PEP_OWN_USERID, "Bob's Burgers",
                NULL, false
            );
    ASSERT_OK;

    // Make it an own identity in the DB
    pEp_identity* me_bob = new_identity("pep.test.bob@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    status = update_identity(session, me_bob);
    ASSERT_OK;
    ASSERT_STREQ(me_bob->fpr, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39");
    status = trust_personal_key(session, me_bob);
    ASSERT_OK;

    me_bob->me = true;
    status = set_identity(session, me_bob);
    free_identity(me_bob);
    me_bob = NULL;
    ASSERT_OK;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                PEP_OWN_USERID, "Alice in Wonderland", NULL, true
            );
    ASSERT_OK;

    // Ok, see if we get it back.
    stringlist_t* keylist = NULL;

    status = _own_keys_retrieve(session, &keylist, 0, true);
    ASSERT_OK;
    ASSERT_NOTNULL(keylist);
    ASSERT_NOTNULL(keylist->value);
    ASSERT_NULL(keylist->next);

    ASSERT_STREQ(keylist->value, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
}

TEST_F(OwnKeysRetrieveTest, check_own_keys_retrieve_multiple_private) {
    // Setup own identity
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander0-0x3B7302DB_priv.asc",
                "pep.test.xander@pep-project.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB",
                PEP_OWN_USERID, "Xander in Wonderland", NULL, true
            );
    ASSERT_OK;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander1-0x541260F6_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander1-0x541260F6_priv.asc",
                "pep.test.xander@pep-project.org", "59AF4C51492283522F6904531C09730A541260F6",
                PEP_OWN_USERID, "Xander2", NULL, true
            );
    ASSERT_OK;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander2-0xA6512F30_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander2-0xA6512F30_priv.asc",
                "pep.test.xander.work@pep-project.org", "46A994F19077C05610870273C4B8AB0BA6512F30",
                PEP_OWN_USERID, "Xander3", NULL, true
            );
    ASSERT_OK;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander3-0x724B3975_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander3-0x724B3975_priv.asc",
                "pep.test.xander@pep-project.org", "5F7076BBD92E14EA49F0DF7C2CE49419724B3975",
                PEP_OWN_USERID, "Xander4", NULL, true
            );
    ASSERT_OK;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander4-0x844B9DCF_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander4-0x844B9DCF_priv.asc",
                "pep.test.xander.home@pep-project.org", "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF",
                PEP_OWN_USERID, "Xander in Wonderland Again", NULL, true
            );
    ASSERT_OK;

    // Ok, see if we get it back.
    stringlist_t* keylist = NULL;

    status = _own_keys_retrieve(session, &keylist, 0, true);
    ASSERT_OK;
    ASSERT_NOTNULL(keylist);

    int fpr_count = 0;

    const char* fpr_list[5];

    bool* found_list = (bool*)calloc(5, sizeof(bool));
    fpr_list[0] = "F4598A17D4690EB3B5B0F6A344F04E963B7302DB";
    fpr_list[1] = "59AF4C51492283522F6904531C09730A541260F6";
    fpr_list[2] = "46A994F19077C05610870273C4B8AB0BA6512F30";
    fpr_list[3] = "5F7076BBD92E14EA49F0DF7C2CE49419724B3975";
    fpr_list[4] = "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF";

    for (stringlist_t* _kl = keylist; _kl; _kl = _kl->next) {
        ASSERT_NOTNULL(_kl->value);
        fpr_count++;

        for (int j = 0; j < 5; j++) {
            if (strcmp(_kl->value, fpr_list[j]) == 0) {
                found_list[j] = true;
                break;
            }
        }
    }
    ASSERT_EQ(fpr_count , 5);
    for (int j = 0; j < 5; j++) {
        ASSERT_TRUE(found_list[j]);
    }
    free(found_list);
    free_stringlist(keylist);
}

TEST_F(OwnKeysRetrieveTest, check_own_keys_retrieve_multiple_private_and_pub) {
    // Setup own identity
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander0-0x3B7302DB_priv.asc",
                "pep.test.xander@pep-project.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB",
                PEP_OWN_USERID, "Xander in Wonderland", NULL, true
            );
    ASSERT_OK;

    // Own pub key
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander5-0x0773CD29_pub.asc"));

    // Make it an own identity in the DB
    pEp_identity* me_pub = new_identity("pep.test.xander@pep-project.org", "58BCC2BF2AE1E3C4FBEAB89AD7838ACA0773CD29", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    ASSERT_OK;
    free_identity(me_pub);
    me_pub = NULL;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander1-0x541260F6_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander1-0x541260F6_priv.asc",
                "pep.test.xander@pep-project.org", "59AF4C51492283522F6904531C09730A541260F6",
                PEP_OWN_USERID, "Xander2", NULL, true
            );
    ASSERT_OK;

    // Own pub key
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc"));

    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.xander@pep-project.org", "74D79B4496E289BD8A71B70BA8E2C4530019697D", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    ASSERT_OK;
    free_identity(me_pub);
    me_pub = NULL;


    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander2-0xA6512F30_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander2-0xA6512F30_priv.asc",
                "pep.test.xander.work@pep-project.org", "46A994F19077C05610870273C4B8AB0BA6512F30",
                PEP_OWN_USERID, "Xander3", NULL, true
            );
    ASSERT_OK;

    // Own pub key
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc"));

    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.xander@pep-project.org", "2E21325D202A44BFD9C607FCF095B202503B14D8", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    ASSERT_OK;
    free_identity(me_pub);
    me_pub = NULL;


    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander3-0x724B3975_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander3-0x724B3975_priv.asc",
                "pep.test.xander@pep-project.org", "5F7076BBD92E14EA49F0DF7C2CE49419724B3975",
                PEP_OWN_USERID, "Xander4", NULL, true
            );
    ASSERT_OK;

    // Own pub key
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc"));

    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.xander@pep-project.org", "3C1E713D8519D7F907E3142D179EAA24A216E95A", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    ASSERT_OK;
    free_identity(me_pub);
    me_pub = NULL;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander4-0x844B9DCF_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander4-0x844B9DCF_priv.asc",
                "pep.test.xander.home@pep-project.org", "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF",
                PEP_OWN_USERID, "Xander in Wonderland Again", NULL, true
            );
    ASSERT_OK;

    // Ok, see if we get it back.
    stringlist_t* keylist = NULL;

    status = _own_keys_retrieve(session, &keylist, 0, true);
    ASSERT_OK;
    ASSERT_NOTNULL(keylist);

    int fpr_count = 0;

    const char* fpr_list[5];

    bool* found_list = (bool*)calloc(5, sizeof(bool));
    fpr_list[0] = "F4598A17D4690EB3B5B0F6A344F04E963B7302DB";
    fpr_list[1] = "59AF4C51492283522F6904531C09730A541260F6";
    fpr_list[2] = "46A994F19077C05610870273C4B8AB0BA6512F30";
    fpr_list[3] = "5F7076BBD92E14EA49F0DF7C2CE49419724B3975";
    fpr_list[4] = "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF";

    for (stringlist_t* _kl = keylist; _kl; _kl = _kl->next) {
        ASSERT_NOTNULL(_kl->value);
        fpr_count++;

        for (int j = 0; j < 5; j++) {
            if (strcmp(_kl->value, fpr_list[j]) == 0) {
                found_list[j] = true;
                break;
            }
        }
    }
    ASSERT_EQ(fpr_count , 5);
    for (int j = 0; j < 5; j++) {
        ASSERT_TRUE(found_list[j]);
    }
    free(found_list);
    free_stringlist(keylist);
}

TEST_F(OwnKeysRetrieveTest, check_own_keys_retrieve_multi_pub_only) {

    PEP_STATUS status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc",
                "pep.test.alexander0@darthmama.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB",
                PEP_OWN_USERID, "Xander in Wonderland", NULL, false
            );
    ASSERT_OK;
    // Make it an own identity in the DB
    pEp_identity* me_pub = new_identity("pep.test.alexander0@darthmama.org", NULL, PEP_OWN_USERID, NULL);
    status = update_identity(session, me_pub);
    ASSERT_OK;
    ASSERT_STREQ(me_pub->fpr, "F4598A17D4690EB3B5B0F6A344F04E963B7302DB");
    status = trust_personal_key(session, me_pub);
    ASSERT_OK;

    me_pub->me = true;
    status = set_identity(session, me_pub);
    free_identity(me_pub);
    me_pub = NULL;
    ASSERT_OK;


    // Own pub key
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander5-0x0773CD29_pub.asc"));

    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.alexander0@darthmama.org", "58BCC2BF2AE1E3C4FBEAB89AD7838ACA0773CD29", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    ASSERT_OK;
    free_identity(me_pub);
    me_pub = NULL;

    // Own pub key
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc"));

    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.alexander0@darthmama.org", "74D79B4496E289BD8A71B70BA8E2C4530019697D", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    ASSERT_OK;
    free_identity(me_pub);
    me_pub = NULL;

    // Own pub key
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc"));

    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.alexander0@darthmama.org", "2E21325D202A44BFD9C607FCF095B202503B14D8", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    ASSERT_OK;
    free_identity(me_pub);
    me_pub = NULL;

    // Own pub key
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc"));

    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.alexander0@darthmama.org", "3C1E713D8519D7F907E3142D179EAA24A216E95A", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    ASSERT_OK;
    free_identity(me_pub);
    me_pub = NULL;

    // Ok, see if we get anything back.
    stringlist_t* keylist = NULL;

    status = _own_keys_retrieve(session, &keylist, 0, true);
    ASSERT_OK;
    ASSERT_NULL(keylist);

    free_stringlist(keylist);
}

TEST_F(OwnKeysRetrieveTest, check_own_keys_retrieve_no_own) {
    PEP_STATUS status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc",
                "pep.test.alexander0@darthmama.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB",
                "NotMe", "Xander in Wonderland", NULL, false
            );
    ASSERT_OK;

    pEp_identity* a_pub = new_identity("pep.test.alexander0@darthmama.org", NULL, "NotMe", NULL);
    status = update_identity(session, a_pub);
    ASSERT_OK;
    ASSERT_STREQ(a_pub->fpr, "F4598A17D4690EB3B5B0F6A344F04E963B7302DB");
    status = trust_personal_key(session, a_pub);
    ASSERT_OK;
    free_identity(a_pub);
    a_pub = NULL;

    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander5-0x0773CD29_pub.asc"));

    a_pub = new_identity("pep.test.alexander0@darthmama.org", "58BCC2BF2AE1E3C4FBEAB89AD7838ACA0773CD29", "NotMe", NULL);
    a_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, a_pub);
    ASSERT_OK;
    free_identity(a_pub);
    a_pub = NULL;

    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc"));

    a_pub = new_identity("pep.test.alexander0@darthmama.org", "74D79B4496E289BD8A71B70BA8E2C4530019697D", "NotMe", NULL);
    a_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, a_pub);
    ASSERT_OK;
    free_identity(a_pub);
    a_pub = NULL;

    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc"));

    a_pub = new_identity("pep.test.alexander0@darthmama.org", "2E21325D202A44BFD9C607FCF095B202503B14D8", "NotMe", NULL);
    a_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, a_pub);
    ASSERT_OK;
    free_identity(a_pub);
    a_pub = NULL;

    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc"));

    a_pub = new_identity("pep.test.alexander0@darthmama.org", "3C1E713D8519D7F907E3142D179EAA24A216E95A", "NotMe", NULL);
    a_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, a_pub);
    ASSERT_OK;
    free_identity(a_pub);
    a_pub = NULL;

    // Ok, see if we get anything back.
    stringlist_t* keylist = NULL;

    status = _own_keys_retrieve(session, &keylist, 0, true);
    ASSERT_OK;
    ASSERT_NULL(keylist);

    free_stringlist(keylist);
}

TEST_F(OwnKeysRetrieveTest, check_own_keys_retrieve_multi_idents_one_key) {
    // Setup own identity
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander0-0x3B7302DB_priv.asc",
                "pep.test.xander@pep-project.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB",
                PEP_OWN_USERID, "Xander in Wonderland", NULL, true
            );
    ASSERT_OK;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander0-0x3B7302DB_priv.asc",
                "pep.test.xander1@pep-project.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB",
                PEP_OWN_USERID, "Xander in Wonderland", NULL, true
            );
    ASSERT_OK;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander0-0x3B7302DB_priv.asc",
                "pep.test.xander2@pep-project.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB",
                PEP_OWN_USERID, "Xander in Wonderland", NULL, true
            );
    ASSERT_OK;

    // Ok, see if we get one back.
    stringlist_t* keylist = NULL;

    status = _own_keys_retrieve(session, &keylist, 0, true);
    ASSERT_OK;
    ASSERT_NOTNULL(keylist);
    ASSERT_NOTNULL(keylist->value);
    ASSERT_NULL(keylist->next);

    ASSERT_STREQ(keylist->value, "F4598A17D4690EB3B5B0F6A344F04E963B7302DB");

}

TEST_F(OwnKeysRetrieveTest, check_own_keys_retrieve_multi_idents_one_priv_key_multi_pub) {
    PEP_STATUS status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep.test.alexander5-0x0773CD29_pub.asc",
                "pep.test.alexander5@darthmama.org", "58BCC2BF2AE1E3C4FBEAB89AD7838ACA0773CD29",
                PEP_OWN_USERID, "Xander in Wonderland", NULL, false
            );
    ASSERT_OK;
    // Make it an own identity in the DB
    pEp_identity* me_pub = new_identity("pep.test.alexander5@darthmama.org", NULL, PEP_OWN_USERID, NULL);
    status = update_identity(session, me_pub);
    ASSERT_OK;
    ASSERT_STREQ(me_pub->fpr, "58BCC2BF2AE1E3C4FBEAB89AD7838ACA0773CD29");
    status = trust_personal_key(session, me_pub);
    ASSERT_OK;

    me_pub->me = true;
    status = set_identity(session, me_pub);
    free_identity(me_pub);
    me_pub = NULL;
    ASSERT_OK;

    // Own pub key
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc"));

    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.alexander5@darthmama.org", "74D79B4496E289BD8A71B70BA8E2C4530019697D", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    ASSERT_OK;
    free_identity(me_pub);
    me_pub = NULL;

    // Own pub key
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc"));

    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.alexander5@darthmama.org", "2E21325D202A44BFD9C607FCF095B202503B14D8", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    ASSERT_OK;
    free_identity(me_pub);
    me_pub = NULL;

    // Own pub key
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc"));

    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.alexander5@darthmama.org", "3C1E713D8519D7F907E3142D179EAA24A216E95A", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    ASSERT_OK;
    free_identity(me_pub);
    me_pub = NULL;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander0-0x3B7302DB_priv.asc",
                "pep.test.xander@pep-project.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB",
                PEP_OWN_USERID, "Xander in Wonderland", NULL, true
            );
    ASSERT_OK;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander0-0x3B7302DB_priv.asc",
                "pep.test.xander1@pep-project.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB",
                PEP_OWN_USERID, "Xander in Wonderland", NULL, true
            );
    ASSERT_OK;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander0-0x3B7302DB_priv.asc",
                "pep.test.xander2@pep-project.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB",
                PEP_OWN_USERID, "Xander in Wonderland", NULL, true
            );
    ASSERT_OK;

    // Ok, see if we get one back.
    stringlist_t* keylist = NULL;

    status = _own_keys_retrieve(session, &keylist, 0, true);
    ASSERT_OK;
    ASSERT_NOTNULL(keylist);
    ASSERT_NOTNULL(keylist->value);
    ASSERT_NULL(keylist->next);

    ASSERT_STREQ(keylist->value, "F4598A17D4690EB3B5B0F6A344F04E963B7302DB");
}
