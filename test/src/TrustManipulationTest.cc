// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include "mime.h"
#include "message_api.h"
#include "test_util.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for TrustManipulationTest
    class TrustManipulationTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            TrustManipulationTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~TrustManipulationTest() override {
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
                engine->prep(NULL, NULL, init_files);

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
            // Objects declared here can be used by all tests in the TrustManipulationTest suite.

    };

}  // namespace


TEST_F(TrustManipulationTest, check_trust_manipulation) {
    cout << "\n*** trust manipulation test ***\n\n";

    char* user_id = get_new_uuid();

    PEP_STATUS status = PEP_STATUS_OK;

    cout << "creating id for : ";
    char *uniqname = strdup("AAAAtestuser@testdomain.org");
    srandom(time(NULL));
    for(int i=0; i < 4;i++)
        uniqname[i] += random() & 0xf;

    cout << uniqname << "\n";
    pEp_identity * user = new_identity(uniqname, NULL, user_id, "Test User");
    status = generate_keypair(session, user);
    ASSERT_NE(user->fpr, nullptr);

    char* keypair1 = strdup(user->fpr);
    cout << "generated fingerprint \n";
    cout << user->fpr << "\n";

    cout << "Setting key 1 (" << user->fpr << ") as the default for the identity." << endl;
    // Put identity in the DB
    status = set_identity(session, user);

    cout << "creating second keypair for : " << uniqname << endl;

    pEp_identity * user_again = new_identity(uniqname, NULL, user_id, "Test User");
    status = generate_keypair(session, user_again);
    ASSERT_NE(user_again->fpr, nullptr);

    char* keypair2 = strdup(user_again->fpr);
    cout << "generated fingerprint \n";
    cout << user_again->fpr << "\n";

    ASSERT_STRNE(user->fpr, user_again->fpr);
    update_identity(session, user);
    ASSERT_STREQ(user->fpr, keypair1);
    cout << "Key 1 (" << user->fpr << ") is still the default for the identity after update_identity." << endl;

    // First, trust the SECOND key; make sure it replaces as the default
    cout << "Set trust bit for key 2 (" << keypair2 << ") and ensure it replaces key 1 as the default." << endl;
    status = trust_personal_key(session, user_again);
    status = update_identity(session, user);
    ASSERT_EQ(user->comm_type , PEP_ct_OpenPGP);
    ASSERT_STREQ(user->fpr, keypair2);
    cout << "Key 2 (" << user->fpr << ") is now the default for the identity after update_identity, and its comm_type is PEP_ct_OpenPGP (trust bit set!)." << endl;

    cout << "Now make key 2 not trusted (which also removes it as a default everywhere)." << endl;
    status = key_reset_trust(session, user);
    status = get_trust(session, user);
    ASSERT_STREQ(user->fpr, keypair2);
    ASSERT_EQ(user->comm_type , PEP_ct_OpenPGP_unconfirmed);
    cout << "Key 2 is untrusted in the DB." << endl;

    cout << "Now let's mistrust key 2 in the DB." << endl;
    // Now let's mistrust the second key.
    status = key_mistrusted(session, user);
    status = get_trust(session, user);
    ASSERT_STREQ(user->fpr, keypair2);
    ASSERT_EQ(user->comm_type , PEP_ct_mistrusted);
    cout << "Hoorah, we now do not trust key 2. (We never liked key 2 anyway.)" << endl;
    cout << "Now we call update_identity to see what gifts it gives us (should be key 1 with key 1's initial trust.)" << endl;
    status = update_identity(session, user);
    ASSERT_NE(user->fpr, nullptr);
    ASSERT_STREQ(user->fpr, keypair1);
    ASSERT_EQ(user->comm_type , PEP_ct_OpenPGP_unconfirmed);
    cout << "Yup, got key 1, and the trust status is PEP_ct_OpenPGP_unconfirmed." << endl;

    cout << "Let's mistrust key 1 too. It's been acting shifty lately." << endl;
    status = key_mistrusted(session, user);
    status = get_trust(session, user);
    ASSERT_STREQ(user->fpr, keypair1);
    ASSERT_EQ(user->comm_type , PEP_ct_mistrusted);
    cout << "Hoorah, we now do not trust key 1. (TRUST NO ONE)" << endl;
    cout << "Now we call update_identity to see what gifts it gives us (should be an empty key and a key not found comm_type.)" << endl;
    status = update_identity(session, user);
    ASSERT_EQ(user->fpr , NULL);
    ASSERT_EQ(user->comm_type , PEP_ct_key_not_found);
    cout << "Yup, we trust no keys from " << uniqname << endl;

    cout << "TODO: Add cases where we have multiple user_ids addressing a single key, and multiple identities with that key + mistrust" << endl;
    cout << "Passed all of our exciting messing with the trust DB. Moving on..." << endl;

    free(user_id);
    free(keypair1);
    free(uniqname);
    free_identity(user);
}
