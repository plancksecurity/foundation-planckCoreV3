// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "keymanagement.h"

#include "TestUtilities.h"
#include "TestConstants.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for OwnIdentitiesRetrieveTest
    class OwnIdentitiesRetrieveTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            OwnIdentitiesRetrieveTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~OwnIdentitiesRetrieveTest() override {
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
            // Objects declared here can be used by all tests in the OwnIdentitiesRetrieveTest suite.

    };

}  // namespace


TEST_F(OwnIdentitiesRetrieveTest, check_own_identities_retrieve) {
    stringlist_t* keylist = NULL;
    PEP_STATUS status = own_keys_retrieve(session, &keylist);
    ASSERT_NULL(keylist );
    ASSERT_OK;

    identity_list* id_list = NULL;
    status = own_identities_retrieve(session, &id_list);
    ASSERT_TRUE(id_list == NULL || !(id_list->ident));
    ASSERT_EQ(status, PEP_STATUS_OK);

    pEp_identity* me = new_identity("krista_b@darthmama.cool", NULL, "MyOwnId", "Krista B.");
    status = myself(session, me);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(me->fpr);

    // Ok, there's a me identity in the DB.
    // Call the naughty function.

    status = own_keys_retrieve(session, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(keylist);
    ASSERT_NOTNULL(keylist->value);
    output_stream << keylist->value << endl;

    status = own_identities_retrieve(session, &id_list);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NOTNULL(id_list);
    ASSERT_NOTNULL(id_list->ident);
}

TEST_F(OwnIdentitiesRetrieveTest, check_own_identities_retrieve_filter) {
    pEp_identity* sync_alice = new_identity("alice@darthmama.org", NULL, PEP_OWN_USERID, "Alice");
    pEp_identity* sync_bob = new_identity("bob@darthmama.org", NULL, PEP_OWN_USERID, "Bob");
    pEp_identity* no_sync_carol = new_identity("carol@darthmama.org", NULL, PEP_OWN_USERID, "Carol");
    pEp_identity* sync_dave = new_identity("dave@darthmama.org", NULL, PEP_OWN_USERID, "Dave");
    pEp_identity* no_sync_eddie = new_identity("eddie@darthmama.org", NULL, PEP_OWN_USERID, "Eddie");
    pEp_identity* no_sync_felicia = new_identity("felicia@darthmama.org", NULL, PEP_OWN_USERID, "Felicia");
    pEp_identity* sync_gordon = new_identity("gordon@darthmama.org", NULL, PEP_OWN_USERID, "Gordon");
    
    PEP_STATUS status = myself(session, sync_alice);
    ASSERT_OK;
    status = set_identity_flags(session, sync_alice, PEP_idf_devicegroup);    
    ASSERT_OK;
    status = myself(session, sync_alice);
    ASSERT_OK;
    ASSERT_NE(sync_alice->flags & PEP_idf_devicegroup, 0);

    status = myself(session, sync_bob);
    ASSERT_OK;
    status = set_identity_flags(session, sync_bob, PEP_idf_devicegroup);    
    ASSERT_OK;
    status = myself(session, sync_bob);
    ASSERT_OK;
    ASSERT_NE(sync_bob->flags & PEP_idf_devicegroup, 0);

    status = myself(session, no_sync_carol);
    ASSERT_OK;
    status = set_identity_flags(session, no_sync_carol, PEP_idf_not_for_sync);    
    ASSERT_OK;
    status = myself(session, no_sync_carol);
    ASSERT_OK;
    ASSERT_NE(no_sync_carol->flags & PEP_idf_not_for_sync, 0);

    status = myself(session, sync_dave);
    ASSERT_OK;
    status = set_identity_flags(session, sync_dave, PEP_idf_devicegroup);    
    ASSERT_OK;
    status = myself(session, sync_dave);
    ASSERT_OK;
    ASSERT_NE(sync_dave->flags & PEP_idf_devicegroup, 0);
    
    status = myself(session, no_sync_eddie);
    ASSERT_OK;
    status = set_identity_flags(session, no_sync_eddie, PEP_idf_not_for_sync);    
    ASSERT_OK;
    status = myself(session, no_sync_eddie);
    ASSERT_OK;
    ASSERT_NE(no_sync_eddie->flags & PEP_idf_not_for_sync, 0);

    status = myself(session, no_sync_felicia);
    ASSERT_OK;
    status = set_identity_flags(session, no_sync_felicia, PEP_idf_not_for_sync);    
    ASSERT_OK;
    status = myself(session, no_sync_felicia);
    ASSERT_OK;
    ASSERT_NE(no_sync_felicia->flags & PEP_idf_not_for_sync, 0);
    
    status = myself(session, sync_gordon);
    ASSERT_OK;
    status = set_identity_flags(session, sync_gordon, PEP_idf_devicegroup);    
    ASSERT_OK;
    status = myself(session, sync_gordon);
    ASSERT_OK;
    ASSERT_NE(sync_gordon->flags & PEP_idf_devicegroup, 0);
    
    identity_list* id_list = NULL;
    status = _own_identities_retrieve(session, &id_list, PEP_idf_not_for_sync);
    ASSERT_OK;
    ASSERT_NOTNULL(id_list);    
    
    const char* synced[] = {"alice@darthmama.org", "bob@darthmama.org", "dave@darthmama.org", "gordon@darthmama.org"};
    const char* unsynced[] = {"carol@darthmama.org", "eddie@darthmama.org", "felicia@darthmama.org"};
    
    identity_list* curr;
    int i = 0;
    bool sync_found = false;
    for ( ; i < 4; i++) {
        const char* curr_addr = synced[i];
        sync_found = false;
        for (curr = id_list; curr && curr->ident; curr = curr->next) {
            if (strcmp(curr_addr, curr->ident->address) == 0) {
                sync_found = true;
                break;
            }
        }    
        ASSERT_TRUE(sync_found);        
    }
    
    for (i = 0, curr = id_list; curr && curr->ident; curr = curr->next, i++) {}
    
    ASSERT_EQ(i, 4);    

    free_identity_list(id_list);
    id_list = NULL;
    
    status = _own_identities_retrieve(session, &id_list, PEP_idf_devicegroup);
    ASSERT_OK;
    ASSERT_NOTNULL(id_list);    
    
    bool no_sync_found = false;

    for ( ; i < 3; i++) {
        const char* curr_addr = unsynced[i];
        no_sync_found = false;
        for (curr = id_list; curr && curr->ident; curr = curr->next) {
            if (strcmp(curr_addr, curr->ident->address) == 0) {
                no_sync_found = true;
                break;
            }
        }    
        ASSERT_TRUE(no_sync_found);        
    }
    
    for (i = 0, curr = id_list; curr && curr->ident; curr = curr->next, i++) {}
    
    ASSERT_EQ(i, 3);    
}
