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
            const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
            const string alice_user_id = PEP_OWN_USERID;
            const string bob_user_id = "BobId";

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
// also check for PEP_OWN_USERID?
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

    stringlist_t* keylist = NULL;
    pEp_identity* id = new_identity(
        "leon.schumacher@digitalekho.com",
        NULL,
        "23",
        "Leon Schumacher"
    );

    PEP_STATUS status = generate_keypair(NULL, id);
    ASSERT_NE(status, PEP_STATUS_OK);
    
    // Should not be there 
    status = find_keys(session, id->address, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_FALSE(keylist && keylist->value);
    free_stringlist(keylist);
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
    ASSERT_NE(status, PEP_STATUS_OK);

    // Should not be there 
    status = find_keys(session, id->address, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_FALSE(keylist && keylist->value);
    free_stringlist(keylist);
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
// parameter                      return value        
//  missing/not valid session       PEP_ILLEGAL_VALUE             
//  missing fpr/id                  PEP_KEY_NOT_FOUND
//  existing key id                 PEP_STATUS_OK
//  existing fpr                    PEP_STATUS_OK
//  illegal value for key id        PEP_ILLEGAL_VALUE
//  illegal value for fpr           PEP_ILLEGAL_VALUE
//  ?                               PEP_OUT_OF_MEMORY
//  ?                               PEP_KEY_HAS_AMBIG_NAME

TEST_F(KeyManipulationTest, check_delete_keypair_no_session) {
    import_test_keys();
    stringlist_t* keylist = NULL;

    PEP_STATUS status = delete_keypair(NULL, alice_fpr);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free_stringlist(keylist);
}

TEST_F(KeyManipulationTest, check_delete_keypair_no_fpr) {
    import_test_keys();
    stringlist_t* keylist = NULL;

    PEP_STATUS status = delete_keypair(session, NULL);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    free_stringlist(keylist);
}

TEST_F(KeyManipulationTest, check_delete_keypair_own) {
    import_test_keys();
    stringlist_t* keylist = NULL;

    PEP_STATUS status = find_keys(session, alice_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, alice_fpr);
    free_stringlist(keylist);
    
    status = delete_keypair(session, alice_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    status = find_keys(session, alice_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_FALSE(keylist && keylist->value);
    free_stringlist(keylist);
}
