// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <string>
#include <iostream>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "pEpEngine.h"
#include "pEp_internal.h"
#include "stringpair.h"
#include "openpgp_compat.h"

#include "TestUtilities.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for PgpListKeysTest
    class PgpListKeysTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            PgpListKeysTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~PgpListKeysTest() override {
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

            void print_stringpair_list(stringpair_list_t* spl) {
                for ( ; spl != NULL; spl = spl->next) {
                    if (spl->value) {
                        output_stream << "Key:" << endl;
                        if (spl->value->key)
                            output_stream << "\tFPR: " << spl->value->key << endl;
                        if (spl->value->value)
                            output_stream << "\tUID: " << spl->value->value << endl;
                    }
                }
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the PgpListKeysTest suite.

    };

}  // namespace

// FIXME: This test appears to be inspection-only. That isn't super-helpful for regression testing.
TEST_F(PgpListKeysTest, check_pgp_list_keys) {

    output_stream << "Listing all the keys:" << endl;
    stringpair_list_t* all_the_ids = NULL;
    OpenPGP_list_keyinfo(session, "", &all_the_ids);
    print_stringpair_list(all_the_ids);
    free_stringpair_list(all_the_ids);

    output_stream << "**********************" << endl << endl << "Checking on Alice, Bob and John" << endl;
    all_the_ids = NULL;
    OpenPGP_list_keyinfo(session, "pEp Test", &all_the_ids);
    print_stringpair_list(all_the_ids);
    free_stringpair_list(all_the_ids);

    output_stream << "**********************" << endl << endl << "Compare to find_keys for Alice, Bob and John" << endl;
    stringlist_t* all_the_keys;
    find_keys(session, "pEp Test", &all_the_keys);
    stringlist_t* i;
    for (i = all_the_keys; i; i = i->next) {
        output_stream << i->value << endl;
    }
    free_stringlist(all_the_keys);


    output_stream << "**********************" << endl << endl << "Checking FPR" << endl;
    all_the_ids = NULL;
    OpenPGP_list_keyinfo(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", &all_the_ids);
    print_stringpair_list(all_the_ids);
    free_stringpair_list(all_the_ids);

    output_stream << "**********************" << endl << endl << "Checking on nothing" << endl;
    all_the_ids = NULL;
    OpenPGP_list_keyinfo(session, "ekhwr89234uh4rknfjsklejfnlskjflselkflkserjs", &all_the_ids);
    print_stringpair_list(all_the_ids);
    free_stringpair_list(all_the_ids);

    output_stream << "calling release()\n";
}
