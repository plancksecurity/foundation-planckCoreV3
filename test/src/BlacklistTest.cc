// This file is under GNU General Public License 3.0
// see LICENSE.txt

// #include <iostream>
// #include <iostream>
// #include <fstream>
// #include <string>
// #include <cstring> // for strcmp()
// #include <TEST_ASSERT.h>
// #include "blacklist.h"
// #include "keymanagement.h"
// #include "test_util.h"
//
// // This file is under GNU General Public License 3.0
// // see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring> // for strcmp()


#include <assert.h>

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "blacklist.h"
#include "keymanagement.h"
#include "test_util.h"
#include "TestConstants.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for BlacklistTest
    class BlacklistTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            BlacklistTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~BlacklistTest() override {
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
            // Objects declared here can be used by all tests in the BlacklistTest suite.

    };

}  // namespace


TEST_F(BlacklistTest, check_blacklist) {
    // blacklist test code

    output_stream << "adding 23 to blacklist\n";
    PEP_STATUS status2 = blacklist_add(session, "23");
    ASSERT_EQ(status2 , PEP_STATUS_OK);
    output_stream << "added.\n";

    bool listed;
    PEP_STATUS status3 = blacklist_is_listed(session, "23", &listed);
    ASSERT_EQ(status3 , PEP_STATUS_OK);
    ASSERT_TRUE(listed);
    output_stream << "23 is listed.\n";

    stringlist_t *blacklist;
    PEP_STATUS status6 = blacklist_retrieve(session, &blacklist);
    ASSERT_EQ(status6 , PEP_STATUS_OK);
    ASSERT_NE(blacklist, nullptr);

    bool in23 = false;
    output_stream << "the blacklist contains now: ";
    for (stringlist_t *bl = blacklist; bl && bl->value; bl = bl->next) {
        output_stream << bl->value << ", ";
        if (std::strcmp(bl->value, "23") == 0)
            in23 = true;
    }
    output_stream << "END\n";
    ASSERT_TRUE(in23);
    free_stringlist(blacklist);

    output_stream << "deleting 23 from blacklist\n";
    PEP_STATUS status4 = blacklist_delete(session, "23");
    ASSERT_EQ(status4 , PEP_STATUS_OK);
    output_stream << "deleted.\n";

    PEP_STATUS status5 = blacklist_is_listed(session, "23", &listed);
    ASSERT_EQ(status5 , PEP_STATUS_OK);
    ASSERT_TRUE(!listed);
    output_stream << "23 is not listed any more.\n";

    output_stream << "blacklist only key for identity / unblacklist key / add key" << endl;


    // 2797 65A2 FEB5 B7C7 31B8  61D9 3E4C EFD9 F7AF 4684 - this is the blacklisted key in blacklisted_pub.asc

    const string keytext = slurp("test_keys/pub/blacklisted_pub.asc");

    /* FIXME: put in automated test stuff (N.B. only gdb mem examination to this point to get
     *        fix in */
    /* import it into pep */
    PEP_STATUS status7 = import_key(session, keytext.c_str(), keytext.length(), NULL);

    const char* bl_fpr_1 = "279765A2FEB5B7C731B861D93E4CEFD9F7AF4684";
    const char* bl_fpr_2 = "634FAC4417E9B2A5DC2BD4AAC4AEEBBE7E62701B";
    bool is_blacklisted = false;

    // Clean up from previous runs
    PEP_STATUS status10 = blacklist_is_listed(session, bl_fpr_1, &is_blacklisted);
    if (is_blacklisted) {
        is_blacklisted = false;
        blacklist_delete(session, bl_fpr_1);
    }

    pEp_identity* blacklisted_identity = new_identity("blacklistedkeys@kgrothoff.org",
                                                      bl_fpr_1,
                                                      NULL,
                                                      "Blacklist Keypair");

    PEP_STATUS status8 = _update_identity(session, blacklisted_identity, true);

    // THERE IS NO BLACKLISTING OF PEP KEYS
    //blacklisted_identity->comm_type = PEP_ct_pEp;
    blacklisted_identity->comm_type = PEP_ct_OpenPGP_unconfirmed;

    PEP_STATUS status99 = set_identity(session, blacklisted_identity);

    trust_personal_key(session, blacklisted_identity);

    PEP_STATUS status999 = _update_identity(session, blacklisted_identity, true);

    ASSERT_EQ(blacklisted_identity->comm_type , PEP_ct_OpenPGP);

    PEP_STATUS status9 = blacklist_add(session, bl_fpr_1);
    status10 = blacklist_is_listed(session, bl_fpr_1, &is_blacklisted);
    PEP_STATUS status11 = _update_identity(session, blacklisted_identity, true);
    /* new!!! */
    ASSERT_TRUE(is_blacklisted);
    ASSERT_EQ(status11 , PEP_STATUS_OK);
    ASSERT_STREQ(bl_fpr_1, blacklisted_identity->fpr);

    bool id_def, us_def, addr_def;
    status11 = get_valid_pubkey(session, blacklisted_identity,
                                &id_def, &us_def, &addr_def, true, true);

    if (!(blacklisted_identity->fpr))
        output_stream << "OK! blacklisted_identity->fpr is empty. Yay!" << endl;
    else if (strcmp(blacklisted_identity->fpr, bl_fpr_2) == 0)
        output_stream << "OK! While this should be empty, you are probably running " <<
                "this in your home directory instead of the test environment " <<
                "and have leftover keys. This is an acceptable result here then. But you " <<
                "should probably clean up after yourself :)" << endl;
    else
        output_stream << "Not OK. blacklisted_identity->fpr is " << blacklisted_identity->fpr << "." << endl
             << "Expected it to be empty or (possibly) " << bl_fpr_2 << endl;

    ASSERT_TRUE(blacklisted_identity->fpr == NULL || blacklisted_identity->fpr[0] == '\0' || strcmp(blacklisted_identity->fpr, bl_fpr_2) == 0);

    pEp_identity *me = new_identity("alice@peptest.ch", NULL, "423", "Alice Miller");
    ASSERT_NE(me, nullptr);
    PEP_STATUS status24 = myself(session, me);
    ASSERT_EQ(status24 , PEP_STATUS_OK);

    message *msg23 = new_message(PEP_dir_outgoing);
    ASSERT_NE(msg23, nullptr);
    msg23->from = me;
    msg23->to = new_identity_list(identity_dup(blacklisted_identity));
    ASSERT_TRUE(msg23->to != NULL && msg23->to->ident != NULL);
    PEP_rating rating23;

    output_stream << "testing outgoing_message_rating() with blacklisted key in to\n";
    PEP_STATUS status23 = outgoing_message_rating(session, msg23, &rating23);
    ASSERT_EQ(status23 , PEP_STATUS_OK);
    ASSERT_EQ(rating23 , PEP_rating_unencrypted);

    free_message(msg23);

    const string keytext2 = slurp("test_keys/pub/blacklisted_pub2.asc");
    PEP_STATUS status14 = import_key(session, keytext2.c_str(), keytext2.length(), NULL);

    pEp_identity* blacklisted_identity2 = new_identity("blacklistedkeys@kgrothoff.org",
                                                       bl_fpr_2,
                                                        NULL,
                                                       "Blacklist Keypair");
    PEP_STATUS status15 = _update_identity(session, blacklisted_identity2, true);
    //
    // ASSERT_EQ((blacklisted_identity2->fpr && strcmp(blacklisted_identity2->fpr, bl_fpr_2) , 0), "blacklisted_identity2->fpr && strcmp(blacklisted_identity2->fpr);
    // if (blacklisted_identity2->fpr && strcmp(blacklisted_identity2->fpr, bl_fpr_2) == 0)
    //     output_stream << "blacklisted identity's fpr successfully replaced by the unblacklisted one" << endl;
    // // else
    // //     output_stream << "blacklisted_identity->fpr should be " << bl_fpr_2 << " but is " << blacklisted_identity->fpr << endl;
    //
    // PEP_STATUS status12 = blacklist_delete(session, bl_fpr_1);
    // PEP_STATUS status13 = _update_identity(session, blacklisted_identity, true);
    //
    // pEp_identity* stored_identity = new_identity("blacklistedkeys@kgrothoff.org",
    //                                               NULL,
    //                                               blacklisted_identity->user_id,
    //                                               "Blacklist Keypair");
    //
    // PEP_STATUS status00 = _update_identity(session, stored_identity, true);
    //
    // // FIXME
    // // ASSERT_EQ(stored_identity->comm_type , PEP_ct_pEp);

    free_identity(blacklisted_identity);
    free_identity(blacklisted_identity2);
}
