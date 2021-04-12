#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"
#include "key_reset.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for Engine909Test
    class Engine909Test : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            Engine909Test() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~Engine909Test() override {
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

                // Import a metric butt-ton of keys for this guy
                // 49C7FE09833876343FD4FD67C656C8004E07C834
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_0-0x4E07C834_pub.asc"));
                // ABB6BF06462407ACBD891D97E3F5D4A4C1FD228F
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_1-0xC1FD228F_pub.asc"));
                // 27B09563D2336803E5B856839DF8147A92385C04
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_2-0x92385C04_pub.asc"));
                // 05AA7FC20DFE1AA8B2D2B204A1FF3DF9D3EDE326
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_3-0xD3EDE326_pub.asc"));
                // 50A12577415CF1707A79BF6776CC9AF41B8570B4
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_4-0x1B8570B4_pub.asc"));
                // FE90889EFAB22D9B89DB80F23C0AAEA75C675C3C
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_5-0x5C675C3C_pub.asc"));
                // 00C71707CEC1F425A4615771AD499497B2C28E9F
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_6-0xB2C28E9F_pub.asc"));
                // E072098A2D251BC2755710048038D1D1883D71F3
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_7-0x883D71F3_pub.asc"));
                // F4EE21F2DA0CA3F876E36A87FDD8076ECC81EF57
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_8-0xCC81EF57_pub.asc"));
                // B96A40484B1E0C0AAA94EB8C35ACC57B5AB9AC75
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_9-0x5AB9AC75_pub.asc"));
                // CFD97E4207EE513D662CF581D37D9EC3C8B83BC8
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_10-0xC8B83BC8_pub.asc"));
                // 0400093BBB169BA7A84D5E83EABA745B93A1DDC8
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_11-0x93A1DDC8_pub.asc"));
                // C33D4C95615DC419D3C77DDFA49EDE13327EB6EE
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_12-0x327EB6EE_pub.asc"));
                // 2D8AF398E47206DE4BC88679C35B821A17659B14
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_13-0x17659B14_pub.asc"));
                // C8578E852E8F3EC6D1650D0C16EB40C0D583CC1A
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_14-0xD583CC1A_pub.asc"));
                // 57025D1AAF940660DA728F9E78E7F8C745C1D8B3
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_15-0x45C1D8B3_pub.asc"));
                // 9E66293A63A1420CF3C2C4D562597B8AFC2962EC
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_16-0xFC2962EC_pub.asc"));
                // 3CBFBB64221709B0DF05B917FCC4CEF36BFD2D78
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_17-0x6BFD2D78_pub.asc"));
                // 4C635756CFE51C37829A3063BAB33F509B497E61
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_18-0x9B497E61_pub.asc"));
                // BB5F0DAC750C0E1878D227A1346EDCFE6DDEBCE8
                ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/solas_dreadwolf_19-0x6DDEBCE8_pub.asc"));
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
            // Objects declared here can be used by all tests in the Engine909Test suite.

    };

}  // namespace


TEST_F(Engine909Test, check_engine909_no_default) {
    pEp_identity* solas = new_identity("solas_dreadwolf@darthmama.org", NULL, "SOLAS", "Totally Not Fen'Harel");

    // Make sure we FIND keys for the guy
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "solas_dreadwolf@darthmama.org", &keylist);
    ASSERT_OK;
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_NE(keylist->next, nullptr);

    // Ok, we're lazy, but we test this elsewhere.
    free_stringlist(keylist);

    // Now, the proof:
    status = update_identity(session, solas);
    ASSERT_OK;
    ASSERT_EQ(solas->fpr, nullptr);
}

TEST_F(Engine909Test, check_engine909_no_default_allow_true) {
    pEp_identity* solas = new_identity("solas_dreadwolf@darthmama.org", NULL, "SOLAS", "Totally Not Fen'Harel");

    // Make sure we FIND keys for the guy
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "solas_dreadwolf@darthmama.org", &keylist);
    ASSERT_OK;
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_NE(keylist->next, nullptr);

    // Ok, we're lazy, but we test this elsewhere.
    free_stringlist(keylist);

    // Now, the proof:
    status = _update_identity(session, solas, true);
    ASSERT_OK;
    ASSERT_NE(solas->fpr, nullptr);
}

TEST_F(Engine909Test, check_engine909_no_default_with_910_true) {
    config_key_election_disabled(session, true);

    pEp_identity* solas = new_identity("solas_dreadwolf@darthmama.org", NULL, "SOLAS", "Totally Not Fen'Harel");

    // Make sure we FIND keys for the guy
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "solas_dreadwolf@darthmama.org", &keylist);
    ASSERT_OK;
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_NE(keylist->next, nullptr);

    // Ok, we're lazy, but we test this elsewhere.
    free_stringlist(keylist);

    // Now, the proof:
    status = _update_identity(session, solas, true);
    ASSERT_OK;
    ASSERT_EQ(solas->fpr, nullptr);
}


TEST_F(Engine909Test, check_engine909_default) {
    const char* solas_fpr = "ABB6BF06462407ACBD891D97E3F5D4A4C1FD228F";
    pEp_identity* solas = new_identity("solas_dreadwolf@darthmama.org", solas_fpr, "SOLAS", "Totally Not Fen'Harel");

    // Make sure we FIND keys for the guy
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "solas_dreadwolf@darthmama.org", &keylist);
    ASSERT_OK;
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_NE(keylist->next, nullptr);

    // Ok, we're lazy, but we test this elsewhere.
    free_stringlist(keylist);

    // Set a default:
    solas->comm_type = PEP_ct_pEp_unconfirmed;
    status = set_identity(session, solas);
    ASSERT_OK;
    status = update_identity(session, solas);
    ASSERT_OK;
    ASSERT_NE(solas->fpr, nullptr);
    ASSERT_STREQ(solas->fpr, solas_fpr);
}

TEST_F(Engine909Test, check_engine909_default_with_910_true) {
    config_key_election_disabled(session, true);

    const char* solas_fpr = "ABB6BF06462407ACBD891D97E3F5D4A4C1FD228F";
    pEp_identity* solas = new_identity("solas_dreadwolf@darthmama.org", solas_fpr, "SOLAS", "Totally Not Fen'Harel");

    // Make sure we FIND keys for the guy
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "solas_dreadwolf@darthmama.org", &keylist);
    ASSERT_OK;
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_NE(keylist->next, nullptr);

    // Ok, we're lazy, but we test this elsewhere.
    free_stringlist(keylist);

    // Set a default:
    solas->comm_type = PEP_ct_pEp_unconfirmed;
    status = set_identity(session, solas);
    ASSERT_OK;
    status = _update_identity(session, solas, true);
    ASSERT_OK;
    ASSERT_NE(solas->fpr, nullptr);
    ASSERT_STREQ(solas->fpr, solas_fpr);
}

TEST_F(Engine909Test, check_engine909_mistrust) {
    const char* solas_fpr = "ABB6BF06462407ACBD891D97E3F5D4A4C1FD228F";
    pEp_identity* solas = new_identity("solas_dreadwolf@darthmama.org", solas_fpr, "SOLAS", "Totally Not Fen'Harel");

    // Make sure we FIND keys for the guy
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "solas_dreadwolf@darthmama.org", &keylist);
    ASSERT_OK;
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_NE(keylist->next, nullptr);

    // Ok, we're lazy, but we test this elsewhere.
    free_stringlist(keylist);

    // Set a default:
    solas->comm_type = PEP_ct_pEp_unconfirmed;
    status = set_identity(session, solas);
    ASSERT_OK;
    status = update_identity(session, solas);
    ASSERT_OK;
    ASSERT_NE(solas->fpr, nullptr);
    ASSERT_STREQ(solas->fpr, solas_fpr);

    // mistrust it
    status = key_mistrusted(session, solas);
    ASSERT_OK;
    free(solas->fpr);
    solas->fpr = NULL;
    solas->comm_type = PEP_ct_unknown;
    status = update_identity(session, solas);
    ASSERT_EQ(solas->fpr, nullptr);
}

TEST_F(Engine909Test, check_engine909_mistrust_allow_true) {
    const char* solas_fpr = "ABB6BF06462407ACBD891D97E3F5D4A4C1FD228F";
    pEp_identity* solas = new_identity("solas_dreadwolf@darthmama.org", solas_fpr, "SOLAS", "Totally Not Fen'Harel");

    // Make sure we FIND keys for the guy
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "solas_dreadwolf@darthmama.org", &keylist);
    ASSERT_OK;
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_NE(keylist->next, nullptr);

    // Ok, we're lazy, but we test this elsewhere.
    free_stringlist(keylist);

    // Set a default:
    solas->comm_type = PEP_ct_pEp_unconfirmed;
    status = set_identity(session, solas);
    ASSERT_OK;
    status = update_identity(session, solas);
    ASSERT_OK;
    ASSERT_NE(solas->fpr, nullptr);
    ASSERT_STREQ(solas->fpr, solas_fpr);

    // mistrust it
    status = key_mistrusted(session, solas);
    ASSERT_OK;
    free(solas->fpr);
    solas->fpr = NULL;
    solas->comm_type = PEP_ct_unknown;
    status = _update_identity(session, solas, true);
    ASSERT_NE(solas->fpr, nullptr);
}

TEST_F(Engine909Test, check_engine909_mistrust_with_910_true) {
    config_key_election_disabled(session, true);

    const char* solas_fpr = "ABB6BF06462407ACBD891D97E3F5D4A4C1FD228F";
    pEp_identity* solas = new_identity("solas_dreadwolf@darthmama.org", solas_fpr, "SOLAS", "Totally Not Fen'Harel");

    // Make sure we FIND keys for the guy
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "solas_dreadwolf@darthmama.org", &keylist);
    ASSERT_OK;
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_NE(keylist->next, nullptr);

    // Ok, we're lazy, but we test this elsewhere.
    free_stringlist(keylist);

    // Set a default:
    solas->comm_type = PEP_ct_pEp_unconfirmed;
    status = set_identity(session, solas);
    ASSERT_OK;
    status = update_identity(session, solas);
    ASSERT_OK;
    ASSERT_NE(solas->fpr, nullptr);
    ASSERT_STREQ(solas->fpr, solas_fpr);

    // mistrust it
    status = key_mistrusted(session, solas);
    ASSERT_OK;
    free(solas->fpr);
    solas->fpr = NULL;
    solas->comm_type = PEP_ct_unknown;
    status = _update_identity(session, solas, true);
    ASSERT_EQ(solas->fpr, nullptr);
}


TEST_F(Engine909Test, check_engine909_reset) {
    const char* solas_fpr = "ABB6BF06462407ACBD891D97E3F5D4A4C1FD228F";
    pEp_identity* solas = new_identity("solas_dreadwolf@darthmama.org", solas_fpr, "SOLAS", "Totally Not Fen'Harel");

    // Make sure we FIND keys for the guy
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "solas_dreadwolf@darthmama.org", &keylist);
    ASSERT_OK;
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_NE(keylist->next, nullptr);

    // Ok, we're lazy, but we test this elsewhere.
    free_stringlist(keylist);

    // Set a default:
    solas->comm_type = PEP_ct_pEp_unconfirmed;
    status = set_identity(session, solas);
    ASSERT_OK;
    status = update_identity(session, solas);
    ASSERT_OK;
    ASSERT_NE(solas->fpr, nullptr);
    ASSERT_STREQ(solas->fpr, solas_fpr);

    // reset it
    status = key_reset_identity(session, solas, solas_fpr);
    ASSERT_OK;
    free(solas->fpr);
    solas->fpr = NULL;
    solas->comm_type = PEP_ct_unknown;
    status = update_identity(session, solas);
    ASSERT_EQ(solas->fpr, nullptr);
}

TEST_F(Engine909Test, check_engine909_reset_with_910_true) {
    config_key_election_disabled(session, true);
    const char* solas_fpr = "ABB6BF06462407ACBD891D97E3F5D4A4C1FD228F";
    pEp_identity* solas = new_identity("solas_dreadwolf@darthmama.org", solas_fpr, "SOLAS", "Totally Not Fen'Harel");

    // Make sure we FIND keys for the guy
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "solas_dreadwolf@darthmama.org", &keylist);
    ASSERT_OK;
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_NE(keylist->next, nullptr);

    // Ok, we're lazy, but we test this elsewhere.
    free_stringlist(keylist);

    // Set a default:
    solas->comm_type = PEP_ct_pEp_unconfirmed;
    status = set_identity(session, solas);
    ASSERT_OK;
    status = update_identity(session, solas);
    ASSERT_OK;
    ASSERT_NE(solas->fpr, nullptr);
    ASSERT_STREQ(solas->fpr, solas_fpr);

    // reset it
    status = key_reset_identity(session, solas, solas_fpr);
    ASSERT_OK;
    free(solas->fpr);
    solas->fpr = NULL;
    solas->comm_type = PEP_ct_unknown;
    status = _update_identity(session, solas, true);
    ASSERT_EQ(solas->fpr, nullptr);
}
