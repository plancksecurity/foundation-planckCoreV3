#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"
#include "group.h"
#include "message_api.h"
#include "test_util.h"
#include "pEp_internal.h"

#include <gtest/gtest.h>

#define GECT_WRITEOUT 1

PEP_STATUS GECT_message_send_callback(message* msg);
PEP_STATUS GECT_ensure_passphrase_callback(PEP_SESSION session, const char* key);

static void* GECT_fake_this;

namespace {

	//The fixture for GroupEncryptionTest
    class GroupEncryptionTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

            vector<message*> m_queue;
            vector<string> pass_list;

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

            // yeah yeah, I played a lot of ESO over break.
            const char* manager_1_address = "fennarion@ravenwatch.house";
            const char* manager_1_name = "Fennarion of House Ravenwatch";
            const char* manager_1_fpr = "53A63A8DD7BB86C0D5D5DF92743FCA3C268B111B";
            const char* manager_1_prefix = "fennarion_0x268B111B";
            const char* manager_2_address = "vanus.galerion@mage.guild";
            const char* manager_2_name = "Vanus Galerion, the GOAT";
            const char* manager_2_fpr = "9800C0D0DCFBF7C7537E9E936A8A9FE79C875C78";
            const char* manager_2_prefix = "vanus.galerion_0x9C875C78";
            const char* member_1_address = "lyris@titanborn.skyrim";
            const char* member_1_name = "Lyris Titanborn";
            const char* member_1_fpr = "5824AAA2931821BDCDCD722F0FD5D60500E3D05A";
            const char* member_1_prefix = "lyris_0x00E3D05A";
            const char* member_2_address = "emperor@aquilarios.cyrodiil";
            const char* member_2_name = "The Prophet";
            const char* member_2_fpr = "A0FAE720349589348BD097C7B2A754FED1AC4929";
            const char* member_2_prefix = "emperor_0xD1AC4929";
            const char* member_3_address = "abner@tharn.cool";
            const char* member_3_name = "Go away, peasants!";
            const char* member_3_fpr = "39119E7972E36604F8D4C8815CC7EA7175909622";
            const char* member_3_prefix = "abner_0x75909622";
            const char* member_4_address = "sai_sahan@blades.hammerfall";
            const char* member_4_name = "Snow Lily Fan 20X6";
            const char* member_4_fpr = "1CD438E516506CCA9393933CBEFFD2F8FD070276";
            const char* member_4_prefix = "sai_sahan_0xFD070276";
            const char* group_1_address = "not_bad_vampires@ravenwatch.house";
            const char* group_1_name = "Totally Not Evil Vampires";
            const char* group_1_fpr = "1444A86CD0AEE6EA40F5C4ECDB4C2E8D0A7893F2";
            const char* group_1_prefix = "not_bad_vampires_0x0A7893F2";
            const char* group_2_address = "vanus_for_archmage@mage.guild";
            const char* group_2_name = "Vanus for Best Mage Ever Campaign";
            const char* group_2_fpr = "A39A9EE41E9D6380C8E5220E6DC64C166456E7C7";
            const char* group_2_prefix = "vanus_for_archmage_0x6456E7C7";

            string kf_name(const char* prefix, bool priv) {
                return string("test_keys/") + (priv ? "priv/" : "pub/") + prefix + (priv ? "_priv.asc" : "_pub.asc");
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).
                GECT_fake_this = (void*)this;

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

                // Get a new test Engine.
                engine = new Engine(test_path);
                ASSERT_NE(engine, nullptr);

                // Ok, let's initialize test directories etc.
                engine->prep(&GECT_message_send_callback, NULL, &GECT_ensure_passphrase_callback, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NE(engine->session, nullptr);
                session = engine->session;

                // Engine is up. Keep on truckin'
                m_queue.clear();
                pass_list.clear();
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                GECT_fake_this = NULL;
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

            const char* get_prefix_from_address(const char* address) {
                if (strcmp(address, member_1_address) == 0)
                    return member_1_prefix;
                if (strcmp(address, member_2_address) == 0)
                    return member_2_prefix;
                if (strcmp(address, member_3_address) == 0)
                    return member_3_prefix;
                if (strcmp(address, member_4_address) == 0)
                    return member_4_prefix;
                return NULL;
            }


        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the GroupEncryptionTest suite.

    };

}  // namespace

PEP_STATUS GECT_message_send_callback(message* msg) {
    ((GroupEncryptionTest*)GECT_fake_this)->m_queue.push_back(msg);
    return PEP_STATUS_OK;
}

PEP_STATUS GECT_ensure_passphrase_callback(PEP_SESSION session, const char* fpr) {
    return config_valid_passphrase(session, fpr, ((GroupEncryptionTest*)GECT_fake_this)->pass_list);
}

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
    ASSERT_STRNE(group_ident->fpr, group_leader->fpr);

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

TEST_F(GroupEncryptionTest, check_protocol_group_create) {
    pEp_identity* me = new_identity(manager_1_address, NULL, PEP_OWN_USERID, manager_1_name);
    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(manager_1_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, manager_1_fpr);
    ASSERT_OK;

    pEp_identity* member_1 = new_identity(member_1_address, NULL, "MEMBER1", member_1_name);
    read_file_and_import_key(session, kf_name(member_1_prefix, false).c_str());
    status = update_identity(session, member_1);
    ASSERT_OK;
    status = set_pEp_version(session, member_1, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_1);
    ASSERT_OK;
    pEp_identity* member_2 = new_identity(member_2_address, NULL, "MEMBER2", member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    status = update_identity(session, member_2);
    ASSERT_OK;
    status = set_pEp_version(session, member_2, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_2);
    ASSERT_OK;
    pEp_identity* member_3 = new_identity(member_3_address, NULL, "MEMBER3", member_3_name);
    read_file_and_import_key(session, kf_name(member_3_prefix, false).c_str());
    status = update_identity(session, member_3);
    ASSERT_OK;
    status = set_pEp_version(session, member_3, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_3);
    ASSERT_OK;
    pEp_identity* member_4 = new_identity(member_4_address, NULL, "MEMBER4", member_4_name);
    read_file_and_import_key(session, kf_name(member_4_prefix, false).c_str());
    status = update_identity(session, member_4);
    ASSERT_OK;
    status = set_pEp_version(session, member_4, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_4);
    ASSERT_OK;

    member_list* new_members = new_memberlist(new_member(member_1));
    ASSERT_NE(new_members, nullptr);
    memberlist_add(new_members, new_member(member_2));
    memberlist_add(new_members, new_member(member_3));
    memberlist_add(new_members, new_member(member_4));

    pEp_identity* group_ident = new_identity(group_1_address, NULL, PEP_OWN_USERID, group_1_name);

    pEp_group* group = NULL;
    status = group_create(session, group_ident, me, new_members, &group);
    ASSERT_OK;

    // Ok, we now have a bunch of messages to check.
    ASSERT_EQ(m_queue.size(), 4);

    for (int i = 0; i < 4; i++) {
        message* msg = m_queue[i];
        ASSERT_NE(msg, nullptr);
        ASSERT_NE(msg->from, nullptr);
        ASSERT_NE(msg->to, nullptr);
        ASSERT_NE(msg->to->ident, nullptr);
        ASSERT_EQ(msg->to->next, nullptr);
        ASSERT_STREQ(msg->from->address, manager_1_address);

#if GECT_WRITEOUT
            char* outdata = NULL;
            mime_encode_message(msg, false, &outdata, false);
            ASSERT_NE(outdata, nullptr);
            dump_out((string("test_mails/group_create_") + get_prefix_from_address(msg->to->ident->address) + ".eml").c_str(), outdata);
            free(outdata);
#endif
    }


    // MESSAGE LIST NOW INVALID.
    m_queue.clear();

    // FIXME: Check all of the DB stuff, etc
    // Ok, now let's see what's inside the box
    pEp_group* group_info = NULL;
    status = retrieve_group_info(session, group_ident, &group_info);
    ASSERT_OK;
    ASSERT_NE(group_info, nullptr);

    // This should literally be true - I'm comparing the pointers on purpose
    ASSERT_EQ(group_ident, group_info->group_identity);

    ASSERT_NE(group_info->manager, nullptr);
    ASSERT_STREQ(group_info->manager->user_id, me->user_id);
    ASSERT_STREQ(group_info->manager->address, me->address);

    status = myself(session, group_info->manager);
    ASSERT_OK;
    ASSERT_NE(group_info->manager->fpr, nullptr);
    ASSERT_STREQ(group_info->manager->fpr, manager_1_fpr);
    ASSERT_STREQ(group_info->manager->username, me->username);
    ASSERT_STREQ(group_info->manager->username, manager_1_name);

    ASSERT_TRUE(group_info->active);

    // Ok, time to check the member list. Tricky...
    const char* member_names[] = {member_1_name, member_2_name, member_3_name, member_4_name};
    const char* member_addrs[] = {member_1_address, member_2_address, member_3_address, member_4_address};
    const char* member_fprs[] = {member_1_fpr, member_2_fpr, member_3_fpr, member_4_fpr};

    bool found[] = {false, false, false, false};

    int count = 0;
    for (member_list* curr_member = group_info->members;
            curr_member && curr_member->member && curr_member->member->ident;
            curr_member = curr_member->next) {

        pEp_member* memb = curr_member->member;
        pEp_identity* ident = memb->ident;
        const char* userid = ident->user_id;
        const char* address = ident->address;
        ASSERT_NE(userid, nullptr);
        ASSERT_NE(address, nullptr);

        status = update_identity(session, ident);
        ASSERT_OK;

        const char* fpr = ident->fpr;
        const char* name = ident->username;
        ASSERT_NE(name, nullptr);
        ASSERT_NE(fpr, nullptr);

        ASSERT_FALSE(memb->adopted);

        int index = -1;

        for (int i = 0; i < 4; i++) {
            if (strcmp(member_names[i], name) == 0) {
                index = i;
                break;
            }
        }
        ASSERT_GT(index, -1);
        ASSERT_LT(index, 5);
        ASSERT_STREQ(member_addrs[index], address);
        ASSERT_STREQ(member_fprs[index], fpr);
        found[index] = true;
        count++;
    }

    ASSERT_EQ(count, 4);
    for (int i = 0; i < 4; i++) {
        ASSERT_TRUE(found[i]);
    }

    free_group(group);
}

TEST_F(GroupEncryptionTest, check_protocol_group_create_receive_member_1) {
    const char* own_id = "DIFFERENT_OWN_ID_FOR_KICKS";
    pEp_identity* me = new_identity(member_1_address, NULL, own_id, member_1_name);
    read_file_and_import_key(session, kf_name(member_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_1_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_1_fpr);
    ASSERT_OK;

    status = myself(session, me);

    ASSERT_STREQ(me->fpr, member_1_fpr);

    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    string msg_str = slurp(string("test_mails/group_create_") + member_1_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    // Ok, so that worked.
    stringpair_list_t* autoconsume = stringpair_list_find(msg->opt_fields, "pEp-auto-consume");
    ASSERT_NE(autoconsume, nullptr);

    // Let's see if the message did the right thing:
    pEp_identity* group_identity = new_identity(group_1_address, NULL, NULL, NULL);
    status = update_identity(session, group_identity);
    ASSERT_OK;
    ASSERT_TRUE(is_me(session, group_identity));
    ASSERT_NE(group_identity->flags & PEP_idf_group_ident, 0);
    // FIXME: Uncomment after ENGINE-878 is resolved
    //    ASSERT_STREQ(group_identity->username, group_1_name);
    ASSERT_STRNE(group_identity->user_id, PEP_OWN_USERID);
    pEp_identity* manager = new_identity(manager_1_address, NULL, NULL, NULL);
    status = update_identity(session, manager);
    ASSERT_OK;
    ASSERT_TRUE(!is_me(session, manager));
    ASSERT_EQ(manager->flags & PEP_idf_group_ident, 0);
    if (!is_me(session, msg->to->ident)) {
        status = update_identity(session, msg->to->ident);
        ASSERT_OK;
    }
    ASSERT_TRUE(is_me(session,msg->to->ident));
    ASSERT_STREQ(msg->to->ident->username, member_1_name);
    ASSERT_STREQ(msg->to->ident->address, member_1_address);

    // Ok, now let's see what's inside the box
    pEp_group* group_info = NULL;
    status = retrieve_group_info(session, group_identity, &group_info);
    ASSERT_OK;
    ASSERT_NE(group_info, nullptr);

    // This should literally be true - I'm comparing the pointers on purpose
    ASSERT_EQ(group_identity, group_info->group_identity);

    ASSERT_NE(group_info->manager, nullptr);
    ASSERT_STREQ(group_info->manager->user_id, manager->user_id);
    ASSERT_STREQ(group_info->manager->address, manager->address);
    ASSERT_STREQ(group_info->manager->user_id, manager->user_id);

    status = update_identity(session, group_info->manager);
    ASSERT_OK;
    ASSERT_NE(group_info->manager->fpr, nullptr);
    ASSERT_STREQ(group_info->manager->fpr, manager_1_fpr);
    ASSERT_STREQ(group_info->manager->username, manager->username);
    ASSERT_STREQ(group_info->manager->username, manager_1_name);

    // Are all non-mine groups are "inactive" (meaning it doesn't mean anything), or
    // they stay inactive until I am an active member? Ask vb. I think it's meaningless on
    // This end, but it appears we make it true when we create the group. Hmmm.
    // ASSERT_FALSE(group_info->active);
}

TEST_F(GroupEncryptionTest, check_protocol_group_create_receive_member_2) {
    const char* own_id = PEP_OWN_USERID;
    pEp_identity* me = new_identity(member_2_address, NULL, own_id, member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_2_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_2_fpr);
    ASSERT_OK;

    status = myself(session, me);

    ASSERT_STREQ(me->fpr, member_2_fpr);

    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    string msg_str = slurp(string("test_mails/group_create_") + member_2_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    // Ok, so that worked.
    stringpair_list_t* autoconsume = stringpair_list_find(msg->opt_fields, "pEp-auto-consume");
    ASSERT_NE(autoconsume, nullptr);

    // Let's see if the message did the right thing:
    pEp_identity* group_identity = new_identity(group_1_address, NULL, NULL, NULL);
    status = update_identity(session, group_identity);
    ASSERT_OK;
    ASSERT_TRUE(is_me(session, group_identity));
    ASSERT_NE(group_identity->flags & PEP_idf_group_ident, 0);
    // FIXME: Uncomment after ENGINE-878 is resolved
    //    ASSERT_STREQ(group_identity->username, group_1_name);
    pEp_identity* manager = new_identity(manager_1_address, NULL, NULL, NULL);
    status = update_identity(session, manager);
    ASSERT_OK;
    ASSERT_TRUE(!is_me(session, manager));
    ASSERT_EQ(manager->flags & PEP_idf_group_ident, 0);
    if (!is_me(session, msg->to->ident)) {
        status = update_identity(session, msg->to->ident);
        ASSERT_OK;
    }
    ASSERT_TRUE(is_me(session,msg->to->ident));
    ASSERT_STREQ(msg->to->ident->username, member_2_name);
    ASSERT_STREQ(msg->to->ident->address, member_2_address);
}

TEST_F(GroupEncryptionTest, check_protocol_group_create_receive_member_3) {
    const char* own_id = PEP_OWN_USERID;
    pEp_identity* me = new_identity(member_3_address, NULL, own_id, member_3_name);
    read_file_and_import_key(session, kf_name(member_3_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_3_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_3_fpr);
    ASSERT_OK;

    status = myself(session, me);

    ASSERT_STREQ(me->fpr, member_3_fpr);

    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    string msg_str = slurp(string("test_mails/group_create_") + member_3_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    // Ok, so that worked.
    stringpair_list_t* autoconsume = stringpair_list_find(msg->opt_fields, "pEp-auto-consume");
    ASSERT_NE(autoconsume, nullptr);

    // Let's see if the message did the right thing:
    pEp_identity* group_identity = new_identity(group_1_address, NULL, NULL, NULL);
    status = update_identity(session, group_identity);
    ASSERT_OK;
    ASSERT_TRUE(is_me(session, group_identity));
    ASSERT_NE(group_identity->flags & PEP_idf_group_ident, 0);
    // FIXME: Uncomment after ENGINE-878 is resolved
    //    ASSERT_STREQ(group_identity->username, group_1_name);
    pEp_identity* manager = new_identity(manager_1_address, NULL, NULL, NULL);
    status = update_identity(session, manager);
    ASSERT_OK;
    ASSERT_TRUE(!is_me(session, manager));
    ASSERT_EQ(manager->flags & PEP_idf_group_ident, 0);
    if (!is_me(session, msg->to->ident)) {
        status = update_identity(session, msg->to->ident);
        ASSERT_OK;
    }
    ASSERT_TRUE(is_me(session,msg->to->ident));
    ASSERT_STREQ(msg->to->ident->username, member_3_name);
    ASSERT_STREQ(msg->to->ident->address, member_3_address);
}

TEST_F(GroupEncryptionTest, check_protocol_group_create_receive_member_4) {
    const char* own_id = PEP_OWN_USERID;
    pEp_identity* me = new_identity(member_4_address, NULL, own_id, member_4_name);
    read_file_and_import_key(session, kf_name(member_4_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_4_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_4_fpr);
    ASSERT_OK;

    status = myself(session, me);

    ASSERT_STREQ(me->fpr, member_4_fpr);

    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    string msg_str = slurp(string("test_mails/group_create_") + member_4_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    // Ok, so that worked.
    stringpair_list_t* autoconsume = stringpair_list_find(msg->opt_fields, "pEp-auto-consume");
    ASSERT_NE(autoconsume, nullptr);

    // Let's see if the message did the right thing:
    pEp_identity* group_identity = new_identity(group_1_address, NULL, NULL, NULL);
    status = update_identity(session, group_identity);
    ASSERT_OK;
    ASSERT_TRUE(is_me(session, group_identity));
    ASSERT_NE(group_identity->flags & PEP_idf_group_ident, 0);
    // FIXME: Uncomment after ENGINE-878 is resolved
    //    ASSERT_STREQ(group_identity->username, group_1_name);
    pEp_identity* manager = new_identity(manager_1_address, NULL, NULL, NULL);
    status = update_identity(session, manager);
    ASSERT_OK;
    ASSERT_TRUE(!is_me(session, manager));
    ASSERT_EQ(manager->flags & PEP_idf_group_ident, 0);
    if (!is_me(session, msg->to->ident)) {
        status = update_identity(session, msg->to->ident);
        ASSERT_OK;
    }
    ASSERT_TRUE(is_me(session,msg->to->ident));
    ASSERT_STREQ(msg->to->ident->username, member_4_name);
    ASSERT_STREQ(msg->to->ident->address, member_4_address);
}


