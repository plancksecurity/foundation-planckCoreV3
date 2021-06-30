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
#include "TestUtilities.h"



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
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
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
            // Objects declared here can be used by all tests in the TrustManipulationTest suite.

    };

}  // namespace


TEST_F(TrustManipulationTest, check_trust_manipulation) {
    output_stream << "\n*** trust manipulation test ***\n\n";

    char* user_id = get_new_uuid();

    PEP_STATUS status = PEP_STATUS_OK;

    output_stream << "creating id for : ";
    char *uniqname = strdup("AAAAtestuser@testdomain.org");
    srandom(time(NULL));
    for(int i=0; i < 4;i++)
        uniqname[i] += random() & 0xf;

    output_stream << uniqname << "\n";
    pEp_identity * user = new_identity(uniqname, NULL, user_id, "Test User");
    status = generate_keypair(session, user);
    ASSERT_NOTNULL(user->fpr);

    char* keypair1 = strdup(user->fpr);
    output_stream << "generated fingerprint \n";
    output_stream << user->fpr << "\n";

    output_stream << "Setting key 1 (" << user->fpr << ") as the default for the identity." << endl;
    // Put identity in the DB
    status = set_identity(session, user);

    output_stream << "creating second keypair for : " << uniqname << endl;

    pEp_identity * user_again = new_identity(uniqname, NULL, user_id, "Test User");
    status = generate_keypair(session, user_again);
    ASSERT_NOTNULL(user_again->fpr);

    char* keypair2 = strdup(user_again->fpr);
    output_stream << "generated fingerprint \n";
    output_stream << user_again->fpr << "\n";

    ASSERT_STRNE(user->fpr, user_again->fpr);
    update_identity(session, user);
    ASSERT_STREQ(user->fpr, keypair1);
    output_stream << "Key 1 (" << user->fpr << ") is still the default for the identity after update_identity." << endl;

    // First, trust the SECOND key; make sure it replaces as the default
    output_stream << "Set trust bit for key 2 (" << keypair2 << ") and ensure it replaces key 1 as the default." << endl;
    status = trust_personal_key(session, user_again);
    status = update_identity(session, user);
    ASSERT_EQ(user->comm_type , PEP_ct_OpenPGP);
    ASSERT_STREQ(user->fpr, keypair2);
    output_stream << "Key 2 (" << user->fpr << ") is now the default for the identity after update_identity, and its comm_type is PEP_ct_OpenPGP (trust bit set!)." << endl;

    output_stream << "Now make key 2 not trusted (which also removes it as a default everywhere)." << endl;
    status = key_reset_trust(session, user);
    status = get_trust(session, user);
    ASSERT_STREQ(user->fpr, keypair2);
    ASSERT_EQ(user->comm_type , PEP_ct_OpenPGP_unconfirmed);
    output_stream << "Key 2 is untrusted in the DB." << endl;

    output_stream << "Now let's mistrust key 2 in the DB." << endl;
    // Now let's mistrust the second key.
    status = key_mistrusted(session, user);
    status = get_trust(session, user);
    ASSERT_STREQ(user->fpr, keypair2);
    ASSERT_EQ(user->comm_type , PEP_ct_mistrusted);
    output_stream << "Hoorah, we now do not trust key 2. (We never liked key 2 anyway.)" << endl;

    // Ok, here's where the test breaks when we remove key election. Update identity won't be giving us anything because there's no default.

//    output_stream << "Now we call update_identity to see what gifts it gives us (should be key 1 with key 1's initial trust.)" << endl;
    output_stream << "Now we call update_identity to see what gifts it gives us (should be NOTHING.)" << endl;
    status = update_identity(session, user);
    ASSERT_NULL(user->fpr);
    // Now set key 1 as the default again
    status = set_fpr_preserve_ident(session, user, keypair1, true);
    ASSERT_OK;
    status = update_identity(session, user);
    ASSERT_NOTNULL(user->fpr);
    ASSERT_STREQ(user->fpr, keypair1);
    ASSERT_EQ(user->comm_type , PEP_ct_OpenPGP_unconfirmed);
    output_stream << "Yup, got key 1, and the trust status is PEP_ct_OpenPGP_unconfirmed." << endl;

    output_stream << "Let's mistrust key 1 too. It's been acting shifty lately." << endl;
    status = key_mistrusted(session, user);
    status = get_trust(session, user);
    ASSERT_STREQ(user->fpr, keypair1);
    ASSERT_EQ(user->comm_type , PEP_ct_mistrusted);
    output_stream << "Hoorah, we now do not trust key 1. (TRUST NO ONE)" << endl;
    output_stream << "Now we call update_identity to see what gifts it gives us (should be an empty key and a key not found comm_type.)" << endl;
    status = update_identity(session, user);
    ASSERT_NULL(user->fpr );
    ASSERT_EQ(user->comm_type , PEP_ct_key_not_found);
    output_stream << "Yup, we trust no keys from " << uniqname << endl;

    output_stream << "TODO: Add cases where we have multiple user_ids addressing a single key, and multiple identities with that key + mistrust" << endl;
    output_stream << "Passed all of our exciting messing with the trust DB. Moving on..." << endl;

    free(user_id);
    free(keypair1);
    free(uniqname);
    free_identity(user);
}
