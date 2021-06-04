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
#include "mime.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for Engine655Test
    class Engine655Test : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            Engine655Test() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~Engine655Test() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

                init_files.push_back(std::pair<std::string, std::string>(std::string("test_files/655_keys.db"), std::string("keys.db")));
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
            // Objects declared here can be used by all tests in the Engine655Test suite.

    };

}  // namespace


TEST_F(Engine655Test, check_engine655) {
    string msg_block = slurp("test_mails/655_msg_huss.eml"); 
    message* msg = NULL;
    PEP_STATUS status = mime_decode_message(msg_block.c_str(), msg_block.size(), &msg, NULL);
        
    for (int i = 0; i < 1; i++) {
        char* ptext = NULL;
        size_t psize = 0;
        stringlist_t* keylist = NULL;        
//        PEP_STATUS tmp = find_keys(session, "6E046FF9A390C79BA4D195368430B7E4E086F04B", &keylist);
//        ASSERT_NE(tmp, PEP_KEY_NOT_FOUND);
//        ASSERT_NE(keylist, nullptr);
        
        keylist = new_stringlist(strdup("16F07F382FB3CF5DF977005D1069C7CACF9C23C6"));
        stringlist_add(keylist, strdup("ECBA9555D9ADB1B68861B508032CCA777FFDBA14"));
        stringlist_add(keylist, strdup("EB4308E2D5B9FEEF7488D14CFEE4AE51914D566D"));
        stringlist_add(keylist, strdup("5FBDE3C9E10552B1DD6D9763E89759391DE04053")); // public only
        
        string keyfile_655_prefix = "655_";
        ofstream outfile;
        stringlist_t* curr_string = keylist;
        int j = 0;
        while (curr_string && curr_string->value) {
            PEP_STATUS keystatus = PEP_STATUS_OK;
            ASSERT_STRNE(curr_string->value, "");
            char* keyval = NULL;
            size_t keysize = 0;
            outfile.open(keyfile_655_prefix + curr_string->value + ".asc");
            keystatus = export_key(session, curr_string->value, &keyval, &keysize);
            EXPECT_EQ(keystatus, PEP_STATUS_OK);
            ASSERT_NE(keyval, nullptr);
            ASSERT_NE(keysize, 0);
            outfile << keyval;
            if (j != 3) {
                free(keyval);
                keyval = NULL;
                keystatus = export_secret_key(session, curr_string->value, &keyval, &keysize);
                ASSERT_NE(keyval, nullptr);                
                ASSERT_NE(keysize, 0);                
                outfile << endl << keyval;
            }    
            outfile.close();
            curr_string = curr_string->next; 
            j++;
            free(keyval);
        }
        free_stringlist(keylist);
        // won't verify, that's fine.
        string msg_block2 = msg->attachments->next->value;
        status = decrypt_and_verify(session, msg_block2.c_str(), msg_block2.size(), NULL, 0, &ptext, &psize, &keylist, NULL);
        ASSERT_EQ(status, PEP_DECRYPTED); // really, expect PEP_STATUS_OK, but it doesn't verify and msg may be broken
        outfile.open(keyfile_655_prefix + "decrypted_only.eml");
        outfile << ptext;
        outfile.close();
        
        // // Let's see what this does...
        // message* parse_verify;
        // status = mime_decode_message(ptext, psize, &parse_verify, NULL);    
        // 
        keylist = NULL;
        message* dec_msg = NULL;
        PEP_rating rating;
        PEP_decrypt_flags_t flags = 0;
        status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
        EXPECT_EQ(status, PEP_DECRYPTED);  // really, expect PEP_STATUS_OK, but it doesn't verify and msg may be broken
        // EXPECT_NE(ptext, nullptr);
        // EXPECT_NE(keylist, nullptr);
        // EXPECT_NE(psize, 0);
        free_stringlist(keylist);
        free(ptext);
    }
}
