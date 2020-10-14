#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for KeyManipulationTest
    class KeyManipulationTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;
            
            const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
            
            const char* alice_keyid = "9411D176FF00E97";
            const char* alice_email = "pep.test.alice@pep-project.org";
            const char* bob_fpr = "5C76378A62B04CF3F41BEC8D4940FC9FA1878736";
            const char* mary_fpr= "599B3D67800DB37E2DCE05C07F59F03CD04A226E";
            const char* erin_fpr = "1B0E197E8AE66277B8A024B9AEA69F509F8D7CBA";
            const char* erin_email = "pep-test-erin@pep-project.org";
            const char* bob_email = "pep.test.bob@pep-project.org";
            const string alice_user_id = PEP_OWN_USERID;
            const string bob_user_id = "BobId";
            const string mary_user_id = "MaryId";

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            KeyManipulationTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~KeyManipulationTest() override {
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

            void import_test_keys() {
                PEP_STATUS status = read_file_and_import_key(session,
                            "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
                assert(status == PEP_KEY_IMPORTED);
                status = set_up_ident_from_scratch(session,
                            "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                            "pep.test.alice@pep-project.org", alice_fpr,
                            alice_user_id.c_str(), "Alice in Wonderland", NULL, true
                        );
                assert(status == PEP_STATUS_OK);

                status = set_up_ident_from_scratch(session,
                            "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                            "pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), "Bob's Burgers",
                            NULL, false
                        );
                assert(status == PEP_STATUS_OK);

                status = read_file_and_import_key(session,
                             "test_keys/priv/pep-test-mary-0x7F59F03CD04A226E_priv.asc");
                assert(status == PEP_KEY_IMPORTED);

                status = set_up_ident_from_scratch(session,
                            "test_keys/pub/pep-test-mary-0x7F59F03CD04A226E_expired_pub.asc",
                            "1960@example.org", NULL, mary_user_id.c_str(), "Mary Smith",
                            NULL, false
                        );
                assert(status == PEP_STATUS_OK);
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
            // Objects declared here can be used by all tests in the KeyManipulationTest suite.

    };

}  // namespace

/***
Key manipulation functions to test:
 
pEpEngine.h: 
generate_keypair()
delete_keypair()
import_key()
export_key()
export_secret_key()
recv_key()
find_keys()
send_key()
get_key_rating()
renew_key()
revoke_key()
key_expired()
key_revoked()
set_revoked()
get_revoked()

***/

// generate_keypair

TEST_F(KeyManipulationTest, check_generate_keypair) {
    stringlist_t* keylist = NULL;
    pEp_identity* id = new_identity(
        "leon.schumacher@digitalekho.com",
        NULL,
        "23",
        "Leon Schumacher"
    );

    PEP_STATUS status = generate_keypair(session, id);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // Is it there?
    status = find_keys(session, id->address, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    free_stringlist(keylist);
}

TEST_F(KeyManipulationTest, check_generate_keypair_no_valid_session) {
    pEp_identity* id = new_identity(
        "leon.schumacher@digitalekho.com",
        NULL,
        "23",
        "Leon Schumacher"
    );

    PEP_STATUS status = generate_keypair(NULL, id);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
}

TEST_F(KeyManipulationTest, check_generate_keypair_no_identity) {
    PEP_STATUS status = generate_keypair(session, NULL);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
}

TEST_F(KeyManipulationTest, check_generate_keypair_has_fpr) {
    stringlist_t* keylist = NULL;
    pEp_identity* id = new_identity(
        "leon.schumacher@digitalekho.com",
        "8BD08954C74D830EEFFB5DEB2682A17F7C87F73D",
        "23",
        "Leon Schumacher"
    );

    PEP_STATUS status = generate_keypair(session, id);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);

}

TEST_F(KeyManipulationTest, check_generate_keypair_identity_without_user_id) {
    stringlist_t* keylist = NULL;
    pEp_identity* id = new_identity(
        "leon.schumacher@digitalekho.com",
        "",
        "",
        "Leon Schumacher"
    );

    PEP_STATUS status = generate_keypair(session, id);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);

}

TEST_F(KeyManipulationTest, check_generate_keypair_no_address) {
    stringlist_t* keylist = NULL;
    pEp_identity* id = new_identity(
        NULL,
        NULL,
        "23",
        "Leon Schumacher"
    );

    PEP_STATUS status = generate_keypair(session, id);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);

}

TEST_F(KeyManipulationTest, check_generate_keypair_seccond_key_for_same_adress) {
    stringlist_t* keylist = NULL;
    pEp_identity* id = new_identity(
        "leon.schumacher@digitalekho.com",
        NULL,
        "23",
        "Leon Schumacher"
    );

    pEp_identity* id2 = new_identity(
        "leon.schumacher@digitalekho.com",
        NULL,
        "24",
        "Leon Schumacher"
    );

    PEP_STATUS status = generate_keypair(session, id);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = find_keys(session, id->address, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    keylist = NULL;

    status = generate_keypair(session, id2);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = find_keys(session, id2->address, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    keylist = keylist->next;
    ASSERT_TRUE(keylist && keylist->value);
    free_stringlist(keylist);
}

// delete_keypair()
// only parameter testing as full test are done in in DeleteKeyTest.cc        

TEST_F(KeyManipulationTest, check_delete_keypair_no_session) {
    PEP_STATUS status = delete_keypair(NULL, alice_fpr);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
}

TEST_F(KeyManipulationTest, check_delete_keypair_no_fpr) {
    PEP_STATUS status = delete_keypair(session, NULL);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
}

TEST_F(KeyManipulationTest, check_delete_invalid_fpr) {
    const char* alice_to_long_fpr = "586500A9411D176FF00E974ABE3AAF59AC32CFE4F86500A9411D176FF00E974ABE3AAF59AC32CFE4F86500A9411D176FF00E974ABE3AAF59AC32CFE4F86500AA9";
    const char* bob_to_short_fpr = "BFCDB7F301DEEEB";
    
    const char* alice_not_hex_fpr = "6500A9411D176FF00E974ABE3AAF59AC32CFE4F86500A9411D176FF00E974ABE3AAF59AC32CFE4F86500A9411D176FF00E974ABE3AAF59AC32CFE4F8XXXXXXXX";
    const char* bob_not_hex_fpr = "ZZZCDB7F301DEEEB";

    PEP_STATUS status = delete_keypair(session, alice_to_long_fpr);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    status = delete_keypair(session, bob_to_short_fpr);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    status = delete_keypair(session, alice_not_hex_fpr);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    status = delete_keypair(session, bob_not_hex_fpr);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
}

TEST_F(KeyManipulationTest, check_delete_keypair_key_not_found) {
    import_test_keys();
    stringlist_t* keylist = NULL;

    PEP_STATUS status = delete_keypair(session, alice_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = find_keys(session, alice_email, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_FALSE(keylist && keylist->value);
    free_stringlist(keylist);

    status = delete_keypair(session, alice_fpr);
    ASSERT_EQ(status, PEP_KEY_NOT_FOUND);
}

//TEST_F(KeyManipulationTest, check_delete_keypair_by_key_id) {
//    import_test_keys();
//    stringlist_t* keylist = NULL;
//    PEP_STATUS status = find_keys(session, alice_user_id.c_str(), &keylist);
//    ASSERT_TRUE(keylist && keylist->value);
//    ASSERT_EQ(status, PEP_STATUS_OK);
//    status = delete_keypair(session, alice_keyid);
//    ASSERT_EQ(status, PEP_STATUS_OK);
//    status = find_keys(session, alice_user_id.c_str(), &keylist);
//    ASSERT_EQ(status, PEP_STATUS_OK);
//    ASSERT_FALSE(keylist && keylist->value);
//    free_stringlist(keylist);
//}

// import_key()
TEST_F(KeyManipulationTest, check_import_key) {
    string erin_pub = slurp("test_keys/pub/pep-test-erin-0x9F8D7CBA_pub.asc");
    identity_list* idlist = NULL; 
    PEP_STATUS status = import_key(session, erin_pub.c_str(), erin_pub.size(), &idlist);     
    ASSERT_EQ(status, PEP_KEY_IMPORTED);

    stringlist_t* keylist = NULL;
    status = find_keys(session, erin_email, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, erin_fpr);
    free_stringlist(keylist);
}

TEST_F(KeyManipulationTest, check_import_key_no_session) {
    string erin_pub = slurp("test_keys/pub/pep-test-erin-0x9F8D7CBA_pub.asc");
    identity_list* idlist = NULL; 
    PEP_STATUS status = import_key(NULL, erin_pub.c_str(), erin_pub.size(), &idlist);     
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
}

TEST_F(KeyManipulationTest, check_import_key_no_key_data) {
    string erin_pub = slurp("test_keys/pub/pep-test-erin-0x9F8D7CBA_pub.asc");
    identity_list* idlist = NULL; 
    PEP_STATUS status = import_key(session, NULL, erin_pub.size(), &idlist);     
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
}

//TEST_F(KeyManipulationTest, check_import_key_no_size) {
//    string erin_pub = slurp("test_keys/pub/pep-test-erin-0x9F8D7CBA_pub.asc");
//    identity_list* idlist = NULL; 
//    PEP_STATUS status = import_key(session, erin_pub.c_str(), NULL, &idlist);     
//    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
//}

TEST_F(KeyManipulationTest, check_import_key_wrong_size) {
    string erin_pub = slurp("test_keys/pub/pep-test-erin-0x9F8D7CBA_pub.asc");
    identity_list* idlist = NULL; 
    PEP_STATUS status = import_key(session, NULL, erin_pub.size()+1, &idlist);     
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    status = import_key(session, NULL, erin_pub.size()-1, &idlist);     
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
}


// export_key()
TEST_F(KeyManipulationTest, check_export_key) {
    import_test_keys();
    size_t keysize = 0;
    char* keydata = NULL;

    PEP_STATUS status = export_key(session, alice_fpr, &keydata, &keysize);     
    ASSERT_EQ(status, PEP_STATUS_OK);
    string alice_pub = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_TRUE(keydata && alice_pub.c_str()); 
    //ASSERT_STREQ(keydata, alice_pub.c_str()); 

    free(keydata);
}

TEST_F(KeyManipulationTest, check_export_key_no_session) {
    import_test_keys();
    size_t keysize = 0;
    char* keydata = NULL;

    PEP_STATUS status = export_key(NULL, alice_fpr, &keydata, &keysize);     
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free(keydata);
}

TEST_F(KeyManipulationTest, check_export_key_no_fpr) {
    import_test_keys();
    size_t keysize = 0;
    char* keydata = NULL;

    PEP_STATUS status = export_key(session, NULL, &keydata, &keysize);     
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free(keydata);
}

TEST_F(KeyManipulationTest, check_export_key_data_no_keydata) {
    import_test_keys();
    size_t keysize = 0;
    char* keydata = NULL;

    PEP_STATUS status = export_key(session, alice_fpr, NULL, &keysize);     
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free(keydata);
}

TEST_F(KeyManipulationTest, check_export_key_data_no_size) {
    import_test_keys();
    size_t keysize = 0;
    char* keydata = NULL;

    PEP_STATUS status = export_key(session, alice_fpr, &keydata, NULL);     
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free(keydata);
}

//TEST_F(KeyManipulationTest, check_export_key_by_keyid) {
//    import_test_keys();
//    size_t keysize = 0;
//    char* keydata = NULL;
//
//    PEP_STATUS status = export_key(session, alice_keyid, &keydata, &keysize);     
//    ASSERT_EQ(status, PEP_STATUS_OK);
//}
//TEST_F(KeyManipulationTest, check_export_key_size_missmatch) {
//    import_test_keys();
//    size_t keysize = 10;
//    char* keydata = NULL;
//
//    PEP_STATUS status = export_key(session, alice_fpr, &keydata, &keysize);     
//    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
//}
//TEST_F(KeyManipulationTest, check_export_key_data_not_null) {
//    import_test_keys();
//    size_t keysize = 0;
//    char* keydata = NULL;
//
//    PEP_STATUS status = export_key(session, alice_fpr, &keydata, &keysize);     
//    status = export_key(session, alice_fpr, &keydata, &keysize);     
//    //ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
//}

// export_secret_key()
TEST_F(KeyManipulationTest, check_export_secret_key) {
    import_test_keys();
    size_t keysize = 0;
    char* keydata = NULL;

    PEP_STATUS status = export_secret_key(session, alice_fpr, &keydata, &keysize);     
    cout << keydata; 
    ASSERT_EQ(status, PEP_STATUS_OK);
    free(keydata);
}

TEST_F(KeyManipulationTest, check_export_secret_key_no_session) {
    import_test_keys();
    size_t keysize = 0;
    char* keydata = NULL;

    PEP_STATUS status = export_secret_key(NULL, alice_fpr, &keydata, &keysize);     
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free(keydata);
}

TEST_F(KeyManipulationTest, check_export_secret_key_no_fpr) {
    import_test_keys();
    size_t keysize = 0;
    char* keydata = NULL;

    PEP_STATUS status = export_secret_key(session, NULL, &keydata, &keysize);     
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free(keydata);
}

TEST_F(KeyManipulationTest, check_export_secret_key_non_existing_fpr) {
    size_t keysize = 0;
    char* keydata = NULL;
    const char* anna_fpr = "AAAAAAAAAAAAAACFE4F86500A9411D176FF00E97"; 

    PEP_STATUS status = export_key(session, anna_fpr, &keydata, &keysize);     
    ASSERT_EQ(status, PEP_KEY_NOT_FOUND);
    free(keydata);
}

TEST_F(KeyManipulationTest, check_export_secret_key_no_keydata_parameter) {
    import_test_keys();
    size_t keysize = 0;
    char* keydata = NULL;

    PEP_STATUS status = export_secret_key(session, alice_fpr, NULL, &keysize);     
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free(keydata);
}

TEST_F(KeyManipulationTest, check_export_secret_key_no_keysize_parameter) {
    import_test_keys();
    size_t keysize = 0;
    char* keydata = NULL;

    PEP_STATUS status = export_secret_key(session, alice_fpr, &keydata, NULL);     
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free(keydata);
}

//TEST_F(KeyManipulationTest, check_recv_key){
//    PEP_STATUS status = recv_key(session, alice_fpr);
//    ASSERT_EQ(status, PEP_UNKNOWN_ERROR);
//}

TEST_F(KeyManipulationTest, check_find_keys) {
    import_test_keys();
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, alice_email, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist);
    ASSERT_STREQ(keylist->value, alice_fpr);
    free_stringlist(keylist);
}

TEST_F(KeyManipulationTest, check_find_keys_no_session) {
    import_test_keys();
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(NULL, alice_email, &keylist);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free_stringlist(keylist);
}

TEST_F(KeyManipulationTest, check_find_keys_no_pattern) {
    import_test_keys();
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, NULL, &keylist);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free_stringlist(keylist);
}

TEST_F(KeyManipulationTest, check_find_keys_no_keylist) {
    import_test_keys();
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, alice_email, NULL);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free_stringlist(keylist);
}

TEST_F(KeyManipulationTest, check_find_keys_by_address) {
    import_test_keys();
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, bob_email, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, bob_fpr);

   // keylist = NULL;
   // status = find_keys(session, alice_email, &keylist);
   // ASSERT_EQ(status, PEP_STATUS_OK);

   // ASSERT_TRUE(keylist && keylist->value);
   // ASSERT_STREQ(keylist->value, alice_fpr);
   free_stringlist(keylist);
}

TEST_F(KeyManipulationTest, check_find_keys_by_keyid) {
    import_test_keys();
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, alice_keyid, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, alice_fpr);
    free_stringlist(keylist);
}

TEST_F(KeyManipulationTest, check_find_keys_by_non_existing_adress) {
    import_test_keys();
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "pep.test.anna@pep-project.org", &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_FALSE(keylist && keylist->value);
    free_stringlist(keylist);
}

//TEST_F(KeyManipulationTest, check_send_key) {
//    import_test_keys();
//    PEP_STATUS status = send_key(session, "pep.test.alice@pep-project.org");
//    ASSERT_EQ(status, PEP_UNKNOWN_ERROR);
//}

TEST_F(KeyManipulationTest, check_get_key_rating) {
    import_test_keys();
    PEP_comm_type communication_type = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, alice_fpr, &communication_type); 
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(communication_type, PEP_ct_OpenPGP_unconfirmed);
}

TEST_F(KeyManipulationTest, check_get_key_rating_no_session) {
    import_test_keys();
    PEP_comm_type communication_type = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(NULL, alice_fpr, &communication_type); 
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
}

TEST_F(KeyManipulationTest, check_get_key_rating_no_fpr) {
    import_test_keys();
    PEP_comm_type communication_type = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, NULL, &communication_type); 
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
}

TEST_F(KeyManipulationTest, check_get_key_rating_no_comm_type) {
    import_test_keys();
    PEP_comm_type communication_type = PEP_ct_unknown;
    PEP_STATUS status = get_key_rating(session, alice_fpr, NULL); 
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
}

//TEST_F(KeyManipulationTest, check_get_key_rating_bad_fpr_format) {
//    import_test_keys();
//    PEP_comm_type communication_type = PEP_ct_unknown;
//    const char* aurelio_fpr = "ZZZZZAAF59AC32CFE4F86500A9411D176FF00E97";
//    PEP_STATUS status = get_key_rating(session, aurelio_fpr, &communication_type); 
//    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
//}

// renew_key()

//TEST_F(KeyManipulationTest, check_renew_key_expired_key_default) {
//    import_test_keys();
//    PEP_STATUS status = renew_key(session, mary_fpr, NULL); 
//    cout << status << endl;
//}
//TEST_F(KeyManipulationTest, check_renew_key_not_expired_key_default) {
//    import_test_keys();
//    PEP_STATUS status = renew_key(session, alice_fpr, NULL); 
//    cout << status << endl;
//}
//
TEST_F(KeyManipulationTest, check_renew_key_expired_key_one_year) {
    import_test_keys();
    time_t now = time(NULL);
    timestamp *ts = new_timestamp(now);
    ts->tm_year += 1;
    PEP_STATUS status = renew_key(session, mary_fpr, ts); 
    ASSERT_EQ(status, PEP_STATUS_OK); 
    // TODO: check expiry date of key before and after
}
TEST_F(KeyManipulationTest, check_renew_key_not_expired_key_one_year) {
    import_test_keys();
    time_t now = time(NULL);
    timestamp *ts = new_timestamp(now);
    ts->tm_year += 1;
    PEP_STATUS status = renew_key(session, alice_fpr, ts); 
    ASSERT_EQ(status, PEP_STATUS_OK); 
    // TODO: check expiry date of key before and after
}
