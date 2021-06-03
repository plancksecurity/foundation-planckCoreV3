// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <iostream>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "map_asn1.h"

#include "TestUtilities.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for MapAsn1Test
    class MapAsn1Test : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            MapAsn1Test() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~MapAsn1Test() override {
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
            // Objects declared here can be used by all tests in the MapAsn1Test suite.

    };

}  // namespace


TEST_F(MapAsn1Test, check_map_asn1) {

    output_stream << "creating new identity...\n";

    pEp_identity *ident1 = new_identity("vb@dingens.org",
            "DB4713183660A12ABAFA7714EBE90D44146F62F4", "42", "Volker Birk");
    ASSERT_NOTNULL(ident1);
    ident1->lang[0] = 'd';
    ident1->lang[1] = 'e';
    ident1->comm_type = PEP_ct_pEp;

    output_stream << "converting identity to ASN.1...\n";

    Identity_t *ident_asn1 = Identity_from_Struct(ident1, NULL);
    ASSERT_NOTNULL(ident_asn1);

    output_stream << "converting identity from ASN.1...\n";

    pEp_identity *ident2 = Identity_to_Struct(ident_asn1, NULL);
    ASSERT_NOTNULL(ident2);

    ASSERT_STREQ(ident1->address,ident2->address);
    ASSERT_STREQ(ident1->fpr,ident2->fpr);
    ASSERT_STREQ(ident1->user_id,ident2->user_id);
    ASSERT_STREQ(ident1->username,ident2->username);
    ASSERT_EQ(ident2->comm_type, PEP_ct_pEp);
    ASSERT_STREQ(ident2->lang,"de");

    output_stream << "freeing identities...\n";

    asn_DEF_Identity.free_struct(&asn_DEF_Identity, ident_asn1, 0);
    free_identity(ident1);
    free_identity(ident2);
}
