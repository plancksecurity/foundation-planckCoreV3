#include <stdlib.h>
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"
#include "mime.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for SetIdentityTest
    class SetIdentityTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            SetIdentityTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~SetIdentityTest() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

// FIXME: remove this useless cruft.

//const std::string mgmt_db_to_init = "/tmp/test-management.db";
//std::cerr << "get_main_test_home_dir() "  << get_main_test_home_dir() << "\n";
//std::cerr << "test_suite_name " << test_suite_name << "\n";
//std::cerr << "test_name " << test_name << "\n";
// Leave this empty if there are no files to copy to the home directory path
//std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>(); // FIXME: I might want to change this in case of initialisation failures, following other test cases --positron
// std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

//init_files.push_back(std::pair<std::string,std::string>(mgmt_db_to_init, std::string("pEp_test_home/SetIdentityTest/foo/.pEp/management.db")));
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
            // Objects declared here can be used by all tests in the SetIdentityTest suite.

    };

}  // namespace

#define CHECK_STATUS(expected)                                          \
    do {                                                                \
      PEP_STATUS _expected = (expected);                                \
      const char *_status_name = pEp_status_to_string (status);         \
      const char *_expected_name = pEp_status_to_string (_expected);    \
      if (status != _expected) {                                        \
          std::cerr << "Status is " << _status_name << " instead of "   \
                    << _expected_name << "\n";                          \
          ASSERT_EQ (status, _expected);                                \
      }                                                                 \
    } while (false)

#define CHECK_STATUS_OK  \
    CHECK_STATUS (PEP_STATUS_OK)

TEST_F(SetIdentityTest, foo) {
    // ASSERT_TRUE(true); 
    PEP_STATUS status = PEP_STATUS_OK;

    const char* own_username = "Me in test-from-outside";
    const char* own_address = "me-in-test-from-outside@ageinghacker.net";
    const char* own_id = PEP_OWN_USERID;
    const char* alice_username = "Alice";
    const char* alice_username_alt = "The all-new Alice";
    const char* alice_address = "alice@ageinghacker.net";
    const char* alice_temp_id = "TOFU_alice@ageinghacker.net";
    const char* alice_id = "the-real-alice";
    const char* alice_id_alt = "some-other-alice";
    const char* bob_username = "Bob";
    const char* bob_address = "bob@ageinghacker.net";
    const char* bob_temp_id = "TOFU_bob@ageinghacker.net";
    const char* bob_id = "the-real-bob";
    const char* carol_username = "Carol";
    const char* carol_username_alt = "The all-new Carol";
    const char* carol_address = "carol@ageinghacker.net";
    const char* carol_temp_id = "TOFU_carol@ageinghacker.net";
    const char* carol_id = "the-real-carol";
    const char* carol_id_alt = "another-carol";

    pEp_identity *own_identity = NULL;
    pEp_identity *alice_identity = NULL;
    pEp_identity *bob_identity = NULL;
    pEp_identity *carol_identity = NULL;

    pEp_identity *test_identity_1 = NULL;
    pEp_identity *test_identity_2 = NULL;

    //pEp_identity *from_identity = own_identity;
    //status = set_identity (session, alice_identity);
    own_identity = new_identity (own_address,
                                 NULL, // fpr
                                 NULL, //NULL, // user_id
                                 own_username);
    ASSERT_NE(own_identity, nullptr);
    alice_identity = new_identity (alice_address,
                                   NULL, // fpr
                                   NULL, //NULL, // user_id
                                   alice_username);
    ASSERT_NE(alice_identity, nullptr);
    bob_identity = new_identity (bob_address,
                                 NULL, // fpr
                                 NULL, //NULL, // user_id
                                 bob_username);
    ASSERT_NE(bob_identity, nullptr);
    carol_identity = new_identity (carol_address,
                                   NULL, // fpr
                                   NULL, //NULL, // user_id
                                   carol_username);
    ASSERT_NE(carol_identity, nullptr);

    // A1 (no id, empty database):
    status = set_identity (session, alice_identity);
    CHECK_STATUS_OK;
    // Check that the assigned id is what we think it is.
    status = get_identity (session, alice_address, alice_temp_id, & test_identity_1);
    CHECK_STATUS_OK;

    // Set an identity with no id, where there is already a non-temp id in the
    // database. A2.
    status = set_identity (session, alice_identity);
    CHECK_STATUS_OK;

    // change the id: B2 (temp -> non-temp)
    alice_identity->user_id = (char *) alice_id;
    status = set_identity (session, alice_identity);
    CHECK_STATUS_OK;
    // Check that the temp id is no longer there, replaced by the non-temp id.
    status = get_identity (session, alice_address, alice_temp_id, & test_identity_1);
    CHECK_STATUS (PEP_CANNOT_FIND_IDENTITY);

    // Set again, removing the id from the volatile copy while the non-temp id
    // is in the database: A3. 
    alice_identity->user_id = NULL;
    status = set_identity (session, alice_identity);
    CHECK_STATUS_OK;
    // Check that the entry with the non-temporary id is still there.
    status = get_identity (session, alice_address, alice_id,
                           & test_identity_1);
   
    // add another id: B4 (a second non-temp)
    alice_identity->user_id = (char *) alice_id_alt;
    status = set_identity (session, alice_identity);
    CHECK_STATUS_OK;

    // Check that we still have both.
    status = get_identity (session, alice_address, alice_id, & test_identity_1);
    CHECK_STATUS_OK;
    status = get_identity (session, alice_address, alice_id_alt, & test_identity_1);
    CHECK_STATUS_OK;

    // New identity, directly with a temporary id: B1, just like...
    bob_identity->user_id = (char *) bob_temp_id;
    status = set_identity (session, bob_identity);
    CHECK_STATUS_OK;

    // ...This: new identity, directly with a non-temporary id.  B1 again.
    carol_identity->user_id = (char *) carol_id;
    status = set_identity (session, carol_identity);
    CHECK_STATUS_OK;

    // Now change some non-key attribute and set again: B3.
    carol_identity->username = (char *) carol_username_alt;
    status = set_identity (session, carol_identity);
    CHECK_STATUS_OK;
    // ...and check.
    status = get_identity (session, carol_address, carol_id, & test_identity_1);
    CHECK_STATUS_OK;
    ASSERT_EQ (! strcmp(test_identity_1->username, carol_username_alt), true);

    // Insert a new identity with an unspecified id where more than one identity
    // with (of course non-temporary) ids already exist.  The semantics here
    // specified that an arbitrary one will be altered.
    // A4.
    alice_identity->username = (char *) alice_username_alt;
    alice_identity->user_id = NULL;
    status = set_identity (session, alice_identity);
    CHECK_STATUS_OK;
    // It is difficult to check that the update actually worked, because with
    // a get operation we might obtain either identity.

}

