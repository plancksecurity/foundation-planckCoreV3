// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"

#include "test_util.h"
#include "TestConstants.h"

#include "sync_api.h"


#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for EnterLeaveDeviceGroupTest
    class EnterLeaveDeviceGroupTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            EnterLeaveDeviceGroupTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~EnterLeaveDeviceGroupTest() override {
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
            // Objects declared here can be used by all tests in the EnterLeaveDeviceGroupTest suite.

    };

}  // namespace


TEST_F(EnterLeaveDeviceGroupTest, check_enter_device_group_no_own) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, false
                        );

    ASSERT_EQ(status , PEP_STATUS_OK);
    status = enter_device_group(session, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = update_identity(session, alice_id);
    ASSERT_EQ(alice_id->flags & PEP_idf_devicegroup, 0);

    free_identity(alice_id);
}

TEST_F(EnterLeaveDeviceGroupTest, check_enter_device_group_one_own_empty) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    ASSERT_EQ(status , PEP_STATUS_OK);
    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(alice_id->me);
    ASSERT_STREQ(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");

    pEp_identity* bob_id = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                                "pep.test.bob@pep-project.org", "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
                                "BOB", "Bob is not Alice", &bob_id, false
                        );
    status = update_identity(session, bob_id);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = enter_device_group(session, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = update_identity(session, bob_id);
    ASSERT_EQ(bob_id->flags & PEP_idf_devicegroup, 0);

    free_identity(alice_id);
    free_identity(bob_id);
}

TEST_F(EnterLeaveDeviceGroupTest, check_enter_device_group_one_own_one) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    ASSERT_EQ(status , PEP_STATUS_OK);
    status = myself(session, alice_id);

    ASSERT_TRUE(alice_id->me);
    ASSERT_STREQ(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    identity_list* ids_to_group = new_identity_list(alice_id);
    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    free_identity(alice_id);
}

TEST_F(EnterLeaveDeviceGroupTest, check_enter_device_group_one_reversed_by_many) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    ASSERT_EQ(status , PEP_STATUS_OK);
    status = myself(session, alice_id);

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Bob is Alice", &alice_id2, true
                        );

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );

    // First, add Alice to device group and ensure the other two are not added
    identity_list* ids_to_group = new_identity_list(alice_id);
    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id3->flags & PEP_idf_devicegroup, 0);

    // Note: this is a shortcut to omit alice_id from ident list
    ids_to_group->ident = alice_id2;

    identity_list_add(ids_to_group, alice_id3);

    // Add 2 and 3 to device group (hopefully removing alice_id)
    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    // Is alice_id in? (shouldn't be)
    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id->flags & PEP_idf_devicegroup, 0);

    // are 2 and 3 in? (should be)
    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id3->flags & PEP_idf_devicegroup, 0);

    free_identity_list(ids_to_group);
    free_identity(alice_id);
}

TEST_F(EnterLeaveDeviceGroupTest, check_enter_device_group_one_own_single_not_me) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    ASSERT_EQ(status , PEP_STATUS_OK);
    status = myself(session, alice_id);

    ASSERT_TRUE(alice_id->me);
    ASSERT_STREQ(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    identity_list* ids_to_group = new_identity_list(alice_id);
    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    pEp_identity* bob_id = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                                "pep.test.bob@pep-project.org", "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
                                "BOB", "Bob is not Alice", &bob_id, false
                        );

    ids_to_group->ident = bob_id;
    status = enter_device_group(session, ids_to_group);
    ASSERT_NE(status , PEP_STATUS_OK);
    status = update_identity(session, bob_id);
    ASSERT_EQ(bob_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    free_identity(alice_id);
    free_identity_list(ids_to_group);
}

TEST_F(EnterLeaveDeviceGroupTest, check_enter_device_group_one_own_single_many_w_not_me) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    ASSERT_EQ(status , PEP_STATUS_OK);
    status = myself(session, alice_id);

    ASSERT_TRUE(alice_id->me);
    ASSERT_STREQ(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    identity_list* ids_to_group = new_identity_list(alice_id);
    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );

    pEp_identity* bob_id = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                                "pep.test.bob@pep-project.org", "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
                                "BOB", "Bob is not Alice", &bob_id, false
                        );

    ids_to_group->ident = alice_id2;
    identity_list_add(ids_to_group, bob_id);
    identity_list_add(ids_to_group, alice_id3);
    status = enter_device_group(session, ids_to_group);
    ASSERT_NE(status , PEP_STATUS_OK);
    status = update_identity(session, bob_id);
    ASSERT_EQ(bob_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id3->flags & PEP_idf_devicegroup, 0);

    free_identity(alice_id);
    free_identity_list(ids_to_group);
}
TEST_F(EnterLeaveDeviceGroupTest, check_enter_device_group_many_own_add_explicit) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);

    identity_list* ids_to_group = new_identity_list(alice_id);
    identity_list_add(ids_to_group, alice_id2);
    identity_list_add(ids_to_group, alice_id3);
    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id3->flags & PEP_idf_devicegroup, 0);

    free_identity_list(ids_to_group);
}

TEST_F(EnterLeaveDeviceGroupTest, check_enter_device_group_many_empty) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = enter_device_group(session, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id3->flags & PEP_idf_devicegroup, 0);

    free_identity(alice_id);
    free_identity(alice_id2);
    free_identity(alice_id3);
}

TEST_F(EnterLeaveDeviceGroupTest, check_enter_device_group_many_own_one) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);

    identity_list* ids_to_group = new_identity_list(alice_id2);
    identity_list_add(ids_to_group, alice_id3);

    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id3->flags & PEP_idf_devicegroup, 0);

    identity_list* tmp = ids_to_group->next;
    ids_to_group->next = NULL;
    tmp->ident = NULL;
    free_identity_list(tmp);

    ids_to_group->ident = alice_id;

    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id3->flags & PEP_idf_devicegroup, 0);

    free_identity_list(ids_to_group);
    free_identity(alice_id2);
    free_identity(alice_id3);
}

TEST_F(EnterLeaveDeviceGroupTest, check_enter_device_group_many_own_many) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );

    pEp_identity* alice_id4 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_4@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Dave is Alice", &alice_id4, true
                        );

    pEp_identity* alice_id5 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_5@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Eustace is Alice", &alice_id5, true
                        );

    pEp_identity* alice_id6 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_6@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Francesca is Alice", &alice_id6, true
                        );


    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id4);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id5);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id6);
    ASSERT_EQ(status , PEP_STATUS_OK);

    identity_list* ids_to_group = new_identity_list(alice_id);
    identity_list_add(ids_to_group, alice_id2);
    identity_list_add(ids_to_group, alice_id3);

    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id3->flags & PEP_idf_devicegroup, 0);

    ids_to_group->ident = alice_id4;
    ids_to_group->next->ident = alice_id5;
    ids_to_group->next->next->ident = alice_id6;

    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id3->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id4);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id4->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id5);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id5->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id6);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id6->flags & PEP_idf_devicegroup, 0);

    free_identity_list(ids_to_group);
    free_identity(alice_id);
    free_identity(alice_id2);
    free_identity(alice_id3);
}

TEST_F(EnterLeaveDeviceGroupTest, check_enter_device_group_many_own_many_w_not_me) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );

    pEp_identity* alice_id4 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_4@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Dave is Alice", &alice_id4, true
                        );

    pEp_identity* alice_id5 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_5@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Eustace is Alice", &alice_id5, true
                        );

    pEp_identity* alice_id6 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_6@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Francesca is Alice", &alice_id6, true
                        );

    pEp_identity* bob_id = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                                "pep.test.bob@pep-project.org", "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
                                "BOB", "Bob is not Alice", &bob_id, false
                        );

    status = update_identity(session, bob_id);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id4);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id5);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id6);
    ASSERT_EQ(status , PEP_STATUS_OK);

    identity_list* ids_to_group = new_identity_list(alice_id);
    identity_list_add(ids_to_group, alice_id2);
    identity_list_add(ids_to_group, alice_id3);

    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id3->flags & PEP_idf_devicegroup, 0);

    ids_to_group->ident = alice_id4;
    ids_to_group->next->ident = alice_id5;
    ids_to_group->next->next->ident = alice_id6;
    ids_to_group->next->next->next = new_identity_list(bob_id);

    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_ILLEGAL_VALUE);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id3->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id4);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id4->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id5);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id5->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id6);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id6->flags & PEP_idf_devicegroup, 0);

    status = update_identity(session, bob_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(bob_id->flags & PEP_idf_devicegroup, 0);

    free_identity_list(ids_to_group);
    free_identity(alice_id);
    free_identity(alice_id2);
    free_identity(alice_id3);
}

TEST_F(EnterLeaveDeviceGroupTest, check_leave_device_group_empty) {
    PEP_STATUS status = leave_device_group(session);
    ASSERT_EQ(status , PEP_STATUS_OK);
}

TEST_F(EnterLeaveDeviceGroupTest, check_leave_device_group_sole) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    ASSERT_EQ(status , PEP_STATUS_OK);
    status = myself(session, alice_id);

    ASSERT_TRUE(alice_id->me);
    ASSERT_STREQ(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    identity_list* ids_to_group = new_identity_list(alice_id);
    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = leave_device_group(session);
    ASSERT_EQ(status , PEP_STATUS_OK);
    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id->flags & PEP_idf_devicegroup, 0);

    free_identity_list(ids_to_group);
}

TEST_F(EnterLeaveDeviceGroupTest, check_leave_device_group_one_in_one_out) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Bob is Alice", &alice_id2, true
                        );

    identity_list* ids_to_group = new_identity_list(alice_id);
    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = leave_device_group(session);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id2->flags & PEP_idf_devicegroup, 0);

    free_identity_list(ids_to_group);
    free_identity(alice_id2);
}

TEST_F(EnterLeaveDeviceGroupTest, check_leave_device_group_three_in) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );

    status = enter_device_group(session, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id3->flags & PEP_idf_devicegroup, 0);

    status = leave_device_group(session);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id3->flags & PEP_idf_devicegroup, 0);


    free_identity(alice_id);
    free_identity(alice_id2);
    free_identity(alice_id3);
}

TEST_F(EnterLeaveDeviceGroupTest, check_leave_device_group_two_in_one_out) {
    pEp_identity* alice_id = NULL;
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);

    identity_list* ids_to_group = new_identity_list(alice_id);
    identity_list_add(ids_to_group, alice_id2);
    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = enter_device_group(session, ids_to_group);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id3->flags & PEP_idf_devicegroup, 0);

    status = leave_device_group(session);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, alice_id);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id2);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id2->flags & PEP_idf_devicegroup, 0);

    status = myself(session, alice_id3);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(alice_id3->flags & PEP_idf_devicegroup, 0);

    free_identity_list(ids_to_group);
    free_identity(alice_id3);
}
