#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"
#include "group.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for GroupEncryptionTest
    class GroupEncryptionTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            GroupEncryptionTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~GroupEncryptionTest() override {
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
            // Objects declared here can be used by all tests in the GroupEncryptionTest suite.

    };

}  // namespace


TEST_F(GroupEncryptionTest, check_member_create_w_ident) {
    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    ASSERT_NE(bob, nullptr);
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(bob_mem, nullptr);
    ASSERT_EQ(bob, bob_mem->ident);
    ASSERT_EQ(bob_mem->adopted, false);

    free_member(bob_mem);
}

TEST_F(GroupEncryptionTest, check_member_create_null_ident) {
    pEp_identity* bob = NULL;
    pEp_member* bob_mem = new_member(bob);
    ASSERT_EQ(bob_mem, nullptr);

    // Make sure this doesn't crash
    free_member(bob_mem);
}

TEST_F(GroupEncryptionTest, check_new_memberlist_w_member) {
    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    ASSERT_NE(bob, nullptr);
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(bob_mem, nullptr);
    ASSERT_EQ(bob, bob_mem->ident);
    ASSERT_EQ(bob_mem->adopted, false);

    member_list* list = new_memberlist(bob_mem);
    ASSERT_NE(list, nullptr);
    ASSERT_EQ(bob_mem, list->member);
    ASSERT_EQ(list->next, nullptr);

    free_memberlist(list);
}


TEST_F(GroupEncryptionTest, check_new_memberlist_w_null) {
    pEp_member* bob_mem = NULL;

    member_list* list = new_memberlist(bob_mem);
    ASSERT_NE(list, nullptr);
    ASSERT_EQ(nullptr, list->member);
    ASSERT_EQ(list->next, nullptr);

    free_memberlist(list);
}

TEST_F(GroupEncryptionTest, check_memberlist_add_to_null) {
    pEp_member* bob_mem = NULL;

    member_list* list = new_memberlist(bob_mem);
    ASSERT_NE(list, nullptr);
    ASSERT_EQ(nullptr, list->member);
    ASSERT_EQ(list->next, nullptr);

    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    ASSERT_NE(bob, nullptr);
    bob_mem = new_member(bob);
    ASSERT_NE(bob_mem, nullptr);
    ASSERT_EQ(bob, bob_mem->ident);
    ASSERT_EQ(bob_mem->adopted, false);

    member_list* check = memberlist_add(list, bob_mem);

    ASSERT_EQ(check, list);
    ASSERT_EQ(list->member, bob_mem);
    ASSERT_EQ(list->member->ident, bob_mem->ident);
    ASSERT_EQ(list->next, nullptr);

    free_memberlist(list);
}

TEST_F(GroupEncryptionTest, check_memberlist_add_to_real_list) {
    pEp_identity* carol = new_identity("carol@bob.bob", NULL, "CAROL_ID", NULL);
    ASSERT_NE(carol, nullptr);
    pEp_member* carol_mem = new_member(carol);

    member_list* list = new_memberlist(carol_mem);
    ASSERT_NE(list, nullptr);
    ASSERT_EQ(carol_mem, list->member);
    ASSERT_EQ(list->next, nullptr);

    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    ASSERT_NE(bob, nullptr);
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(bob_mem, nullptr);
    ASSERT_EQ(bob, bob_mem->ident);
    ASSERT_EQ(bob_mem->adopted, false);

    member_list* check = memberlist_add(list, bob_mem);

    ASSERT_NE(nullptr, check);
    ASSERT_EQ(list->next, check);
    ASSERT_EQ(list->member, carol_mem);
    ASSERT_EQ(list->member->ident, carol);
    ASSERT_EQ(list->next->member, bob_mem);
    ASSERT_EQ(list->next->member->ident, bob);

    free_memberlist(list);
}

TEST_F(GroupEncryptionTest, check_memberlist_add_to_list_three) {
    pEp_identity* carol = new_identity("carol@bob.bob", NULL, "CAROL_ID", NULL);
    ASSERT_NE(carol, nullptr);
    pEp_member* carol_mem = new_member(carol);

    member_list* list = new_memberlist(carol_mem);
    ASSERT_NE(list, nullptr);
    ASSERT_EQ(carol_mem, list->member);
    ASSERT_EQ(list->next, nullptr);

    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    ASSERT_NE(bob, nullptr);
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(bob_mem, nullptr);
    ASSERT_EQ(bob, bob_mem->ident);
    ASSERT_EQ(bob_mem->adopted, false);

    member_list* check = memberlist_add(list, bob_mem);
    ASSERT_NE(nullptr, check);
    
    pEp_identity* solas = new_identity("solas@solas.solas", NULL, "SOLAS_ID", NULL);
    ASSERT_NE(solas, nullptr);
    pEp_member* solas_mem = new_member(solas);
    ASSERT_NE(solas_mem, nullptr);
    ASSERT_EQ(solas, solas_mem->ident);
    ASSERT_EQ(solas_mem->adopted, false);

    ASSERT_NE(check, memberlist_add(list, solas_mem));
    
    ASSERT_EQ(list->next, check);
    ASSERT_EQ(list->member, carol_mem);
    ASSERT_EQ(list->member->ident, carol);
    ASSERT_EQ(list->next->member, bob_mem);
    ASSERT_EQ(list->next->member->ident, bob);
    ASSERT_EQ(list->next->next->member, solas_mem);
    ASSERT_EQ(list->next->next->member->ident, solas);

    free_memberlist(list);
}

TEST_F(GroupEncryptionTest, check_new_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;

    // Create member list
    pEp_identity* carol = new_identity("carol@bob.bob", NULL, "CAROL_ID", NULL);
    ASSERT_NE(carol, nullptr);
    pEp_member* carol_mem = new_member(carol);

    member_list* list = new_memberlist(carol_mem);
    ASSERT_NE(list, nullptr);

    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(memberlist_add(list, bob_mem), nullptr);
    pEp_identity* solas = new_identity("solas@solas.solas", NULL, "SOLAS_ID", NULL);
    pEp_member* solas_mem = new_member(solas);
    ASSERT_NE(memberlist_add(list, solas_mem), nullptr);

    pEp_group* group = new_group(group_ident, group_leader, list);
    ASSERT_NE(group, nullptr);
    ASSERT_EQ(group->group_identity, group_ident);
    ASSERT_EQ(group->manager, group_leader);
    ASSERT_EQ(group->members, list);

    free_group(group);
}
