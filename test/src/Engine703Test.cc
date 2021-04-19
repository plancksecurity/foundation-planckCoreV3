#include <stdlib.h>
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"
#include "keymanagement.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for Engine703Test
    class Engine703Test : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            Engine703Test() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~Engine703Test() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

                init_files.push_back(std::pair<std::string, std::string>(std::string("test_files/2017-imported-key/keys.db"), std::string("keys.db")));
                init_files.push_back(std::pair<std::string, std::string>(std::string("test_files/2017-imported-key/management.db"), std::string("management.db")));

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
            // Objects declared here can be used by all tests in the Engine703Test suite.

    };

}  // namespace


TEST_F(Engine703Test, check_engine703_expired_imported) {
    
    // (pEp_identity) $1 = {
    //   address = 0x000000010160a460 "test010@exchange.peptest.ch"
    //   fpr = 0x000000010160a8c0 "D4B3091B5BC8BA5DF4A0BFD900187F11F2216F5F"
    //   user_id = 0x000000010160a760 "pEp_own_userId"
    //   username = 0x000000010160a8f0 "test010@exchange.peptest.ch"
    //   comm_type = PEP_ct_pEp
    //   lang = ""
    //   me = true
    //   major_ver = 0
    //   minor_ver = 0
    //   flags = 0
    // }
        
    identity_list* id_list = NULL;
    PEP_STATUS status = own_identities_retrieve(session, &id_list);
    ASSERT_EQ(status, PEP_STATUS_OK);    
    ASSERT_NOTNULL(id_list->ident);
    ASSERT_NULL(id_list->next);
    
    pEp_identity* me = id_list->ident;
    status = myself(session, me);
    ASSERT_STREQ(me->fpr, "D4B3091B5BC8BA5DF4A0BFD900187F11F2216F5F");
    
    // char* keydata = NULL;
    // status = export_key(session, me->fpr, &keydata);
    // 
    // ofstream outfile;
    // outfile.open("703_key.asc");
    // outfile << keydata;
    // outfile.close();
    
    free_identity_list(id_list);
}

TEST_F(Engine703Test, check_engine703_valid_renew) {
    
    // (pEp_identity) $1 = {
    //   address = 0x000000010160a460 "test010@exchange.peptest.ch"
    //   fpr = 0x000000010160a8c0 "D4B3091B5BC8BA5DF4A0BFD900187F11F2216F5F"
    //   user_id = 0x000000010160a760 "pEp_own_userId"
    //   username = 0x000000010160a8f0 "test010@exchange.peptest.ch"
    //   comm_type = PEP_ct_pEp
    //   lang = ""
    //   me = true
    //   major_ver = 0
    //   minor_ver = 0
    //   flags = 0
    // }
        
    identity_list* id_list = NULL;
    PEP_STATUS status = own_identities_retrieve(session, &id_list);
    ASSERT_EQ(status, PEP_STATUS_OK);    
    ASSERT_NOTNULL(id_list->ident);
    ASSERT_NULL(id_list->next);
    
    pEp_identity* me = id_list->ident;
    status = myself(session, me);
//    ASSERT_STREQ(me->fpr, "D4B3091B5BC8BA5DF4A0BFD900187F11F2216F5F");
    ASSERT_STRNE(me->fpr, nullptr);    
    char* keydata = NULL;
    size_t size = 0;
    status = export_secret_key(session, me->fpr, &keydata, &size);
    
    ofstream outfile;
    outfile.open("703_key_valid.asc");
    outfile << keydata;
    outfile.close();
    
    free_identity_list(id_list);
}
