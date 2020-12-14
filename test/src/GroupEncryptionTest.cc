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

TEST_F(GroupEncryptionTest, check_create_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;

    // Create member list
    pEp_identity* carol = new_identity("carol@bob.bob", NULL, "CAROL_ID", "Carol");
    ASSERT_NE(carol, nullptr);
    pEp_member* carol_mem = new_member(carol);
    status = update_identity(session, carol);
    ASSERT_OK;

    member_list* list = new_memberlist(carol_mem);
    ASSERT_NE(list, nullptr);

    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    status = update_identity(session, bob);
    ASSERT_OK;
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(memberlist_add(list, bob_mem), nullptr);

    pEp_identity* solas = new_identity("solas@solas.solas", NULL, "SOLAS_ID", "The Dread Wolf, Betrayer of All");
    status = update_identity(session, solas);
    ASSERT_OK;
    pEp_member* solas_mem = new_member(solas);
    ASSERT_NE(memberlist_add(list, solas_mem), nullptr);

    pEp_group* group = NULL;
    status = group_create(session, group_ident, group_leader, list, &group);
    ASSERT_OK;
    ASSERT_NE(group, nullptr);
    ASSERT_EQ(group->group_identity, group_ident);
    ASSERT_NE(group->group_identity->flags & PEP_idf_group_ident, 0);
    ASSERT_EQ(group->manager, group_leader);
    ASSERT_EQ(group->manager->flags & PEP_idf_group_ident, 0);
    ASSERT_EQ(group->members, list); // We don't do anything to this list, so....

    free_group(group);
}

TEST_F(GroupEncryptionTest, check_membership_from_create_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;

    // Create member list
    pEp_identity* carol = new_identity("carol@bob.bob", NULL, "CAROL_ID", "Carol");
    ASSERT_NE(carol, nullptr);
    pEp_member* carol_mem = new_member(carol);
    status = update_identity(session, carol);
    ASSERT_OK;

    member_list* list = new_memberlist(carol_mem);
    ASSERT_NE(list, nullptr);

    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    status = update_identity(session, bob);
    ASSERT_OK;
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(memberlist_add(list, bob_mem), nullptr);

    pEp_identity* solas = new_identity("solas@solas.solas", NULL, "SOLAS_ID", "The Dread Wolf, Betrayer of All");
    status = update_identity(session, solas);
    ASSERT_OK;
    pEp_member* solas_mem = new_member(solas);
    ASSERT_NE(memberlist_add(list, solas_mem), nullptr);

    pEp_group* group = NULL;
    status = group_create(session, group_ident, group_leader, list, &group);
    ASSERT_OK;

    bool carol_found = false;
    bool solas_found = false;
    bool bob_found = false;

    member_list* retrieved_members = NULL;
    status = retrieve_full_group_membership(session, group_ident, &retrieved_members);
    ASSERT_OK;
    ASSERT_NE(retrieved_members, nullptr);

    for (member_list* curr_node = retrieved_members; curr_node && curr_node->member; curr_node = curr_node->next) {
        if (!curr_node->member->ident)
            break;
        pEp_identity* ident = curr_node->member->ident;
        if ((strcmp(ident->user_id, carol->user_id) == 0) && strcmp(ident->address, carol->address) == 0)
            carol_found = true;
        else if ((strcmp(ident->user_id, bob->user_id) == 0) && strcmp(ident->address, bob->address) == 0)
            bob_found = true;
        else if ((strcmp(ident->user_id, solas->user_id) == 0) && strcmp(ident->address, solas->address) == 0)
            solas_found = true;
        else
            ASSERT_STREQ("This message is just to make the test fail and give a message, we found an unexpected member node.", "FAIL");
        ASSERT_FALSE(curr_node->member->adopted);
    }

    ASSERT_TRUE(carol_found);
    ASSERT_TRUE(bob_found);
    ASSERT_TRUE(solas_found);

    free_group(group);
}

TEST_F(GroupEncryptionTest, check_null_membership_from_create_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;

    pEp_group* group = NULL;
    status = group_create(session, group_ident, group_leader, NULL, &group);
    ASSERT_OK;

    member_list* retrieved_members = NULL;
    status = retrieve_full_group_membership(session, group_ident, &retrieved_members);
    ASSERT_OK;
    ASSERT_EQ(retrieved_members, nullptr);

    free_group(group);
}

TEST_F(GroupEncryptionTest, check_null_manager_from_create_group) {

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    PEP_STATUS status = myself(session, group_ident);
    ASSERT_OK;

    pEp_group* group = NULL;
    status = group_create(session, group_ident, NULL, NULL, &group);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    ASSERT_EQ(group, nullptr);
}

TEST_F(GroupEncryptionTest, check_null_group_ident_from_create_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;

    pEp_group* group = NULL;
    status = group_create(session, NULL, group_leader, NULL, &group);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    ASSERT_EQ(group, nullptr);
}

TEST_F(GroupEncryptionTest, check_null_group_address_from_create_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;
    free(group_ident->address);
    group_ident->address = NULL;

    pEp_group* group = NULL;
    status = group_create(session, group_ident, group_leader, NULL, &group);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    ASSERT_EQ(group, nullptr);
}

TEST_F(GroupEncryptionTest, check_null_manager_address_from_create_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;
    free(group_leader->address);
    group_leader->address = NULL;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;

    pEp_group* group = NULL;
    status = group_create(session, group_ident, group_leader, NULL, &group);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    ASSERT_EQ(group, nullptr);
}

TEST_F(GroupEncryptionTest, check_add_invite) {
    pEp_identity* own_ident = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, own_ident);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;
    status = set_identity_flags(session, group_ident, group_ident->flags | PEP_idf_group_ident);
    ASSERT_OK;

    pEp_identity* manager = new_identity("bad_manager@bad.bad", NULL, "BAD_MANAGER", "bad_manager");
    status = update_identity(session, manager);
    ASSERT_OK;

    pEp_group* group = NULL;

    status = group_create(session, group_ident, manager, NULL, &group);
    ASSERT_OK;

    status = group_enable(session, group_ident);
    ASSERT_OK;

    status = add_own_membership_entry(session, group, own_ident);
    ASSERT_OK;

    status = retrieve_own_membership_info_for_group_and_identity(session, group, own_ident);
    ASSERT_OK;

    ASSERT_STREQ(group->manager->user_id, manager->user_id);
    ASSERT_STREQ(group->manager->address, manager->address);
    ASSERT_TRUE(group->active);
    ASSERT_FALSE(group->members->member->adopted);
    ASSERT_EQ(group->members->next, nullptr);
}

TEST_F(GroupEncryptionTest, check_join_group) {
    pEp_identity* own_ident = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, own_ident);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;
    status = set_identity_flags(session, group_ident, group_ident->flags | PEP_idf_group_ident);
    ASSERT_OK;

    pEp_identity* manager = new_identity("bad_manager@bad.bad", NULL, "BAD_MANAGER", "bad_manager");
    status = update_identity(session, manager);
    ASSERT_OK;

    pEp_group* group = NULL;

    status = group_create(session, group_ident, manager, NULL, &group);
    ASSERT_OK;

    status = group_enable(session, group_ident);
    ASSERT_OK;

    status = add_own_membership_entry(session, group, own_ident);
    ASSERT_OK;

    status = join_group(session, group_ident, own_ident);
    ASSERT_OK;

    status = retrieve_own_membership_info_for_group_and_identity(session, group, own_ident);
    ASSERT_OK;

    ASSERT_STREQ(group->manager->user_id, manager->user_id);
    ASSERT_STREQ(group->manager->address, manager->address);
    ASSERT_TRUE(group->active);
    ASSERT_TRUE(group->members->member->adopted);
    ASSERT_EQ(group->members->next, nullptr);
}

// join_group(session, *group_identity, *as_member);