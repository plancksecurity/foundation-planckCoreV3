#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for ImportKeyTest
    class ImportKeyTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            ImportKeyTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~ImportKeyTest() override {
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
            // Objects declared here can be used by all tests in the ImportKeyTest suite.

    };

}  // namespace


TEST_F(ImportKeyTest, check_import_fpr_pub_new) {
    PEP_STATUS status = PEP_STATUS_OK;
    
    string pubkey = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    stringlist_t* keylist = NULL;
    status = import_key(session, pubkey.c_str(), pubkey.size(), NULL, &keylist, NULL);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);
    ASSERT_STREQ(keylist->value, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    ASSERT_EQ(keylist->next, nullptr);
    
    // FIXME, check key is actually imported
}

TEST_F(ImportKeyTest, check_import_change_pub_new) {
    PEP_STATUS status = PEP_STATUS_OK;
    
    string pubkey = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    stringlist_t* keylist = NULL;
    uint64_t changes = 0;
    status = import_key(session, pubkey.c_str(), pubkey.size(), NULL, &keylist, &changes);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);
    ASSERT_STREQ(keylist->value, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    ASSERT_EQ(keylist->next, nullptr);
    ASSERT_EQ(changes, 1);
    // FIXME, check key is actually imported
}

TEST_F(ImportKeyTest, check_import_fpr_priv_new) {
    PEP_STATUS status = PEP_STATUS_OK;
    
    string pubkey = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    stringlist_t* keylist = NULL;
    status = import_key(session, pubkey.c_str(), pubkey.size(), NULL, &keylist, NULL);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);
    ASSERT_STREQ(keylist->value, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    ASSERT_EQ(keylist->next, nullptr);
    
    // FIXME, check key is actually imported
}

TEST_F(ImportKeyTest, check_import_change_pub_nochange) {
    PEP_STATUS status = PEP_STATUS_OK;
    
    string pubkey = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    stringlist_t* keylist = NULL;
    uint64_t changes = 0;
    status = import_key(session, pubkey.c_str(), pubkey.size(), NULL, &keylist, &changes);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);
    ASSERT_STREQ(keylist->value, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    ASSERT_EQ(keylist->next, nullptr);
    ASSERT_EQ(changes, 1);

    // import again!
    free_stringlist(keylist);
    keylist = NULL;
    changes = 0;
    status = import_key(session, pubkey.c_str(), pubkey.size(), NULL, &keylist, &changes);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);
    ASSERT_STREQ(keylist->value, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    ASSERT_EQ(keylist->next, nullptr);
    ASSERT_EQ(changes, 0);
}

TEST_F(ImportKeyTest, check_import_change_wo_fpr_illegal) {
    PEP_STATUS status = PEP_STATUS_OK;
    
    string pubkey = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    uint64_t changes = 0;
    status = import_key(session, pubkey.c_str(), pubkey.size(), NULL, NULL, &changes);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
}

TEST_F(ImportKeyTest, check_import_fpr_list_pub_concat) {
    // Contains 10 keys
    string pubkey_material = slurp("test_keys/pub/import_keys_multi_pub_concat.asc");
    stringlist_t* keylist = NULL;
    uint64_t changes = 0;
    PEP_STATUS status = import_key(session, pubkey_material.c_str(), pubkey_material.size(), NULL, &keylist, &changes);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);    
    ASSERT_EQ(stringlist_length(keylist), 10);
    ASSERT_EQ(changes, 1023); // 2^10 - 1
}

TEST_F(ImportKeyTest, check_import_fpr_list_priv_concat) {
    // Contains 10 keys
    string privkey_material = slurp("test_keys/priv/import_keys_multi_priv_concat.asc");
    stringlist_t* keylist = NULL;
    uint64_t changes = 0;
    PEP_STATUS status = import_key(session, privkey_material.c_str(), privkey_material.size(), NULL, &keylist, &changes);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);    
    ASSERT_EQ(stringlist_length(keylist), 10);
    ASSERT_EQ(changes, 1023); 
}

TEST_F(ImportKeyTest, check_import_fpr_list_priv_then_pub) {
    // Contains 10 keys
    string privkey_material = slurp("test_keys/priv/import_keys_multi_priv_concat.asc");
    stringlist_t* keylist = NULL;
    uint64_t changes = 0;
    PEP_STATUS status = import_key(session, privkey_material.c_str(), privkey_material.size(), NULL, &keylist, &changes);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);    
    ASSERT_EQ(stringlist_length(keylist), 10);
    ASSERT_EQ(changes, 1023); 
    free_stringlist(keylist);
    keylist = NULL;
    changes = 0;
    string pubkey_material = slurp("test_keys/pub/import_keys_multi_pub_concat.asc");
    status = import_key(session, pubkey_material.c_str(), pubkey_material.size(), NULL, &keylist, &changes);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);    
    ASSERT_EQ(stringlist_length(keylist), 10);
    ASSERT_EQ(changes, 0); 
}

TEST_F(ImportKeyTest, check_import_fpr_list_pub_then_priv) {
    // Contains 10 keys
    string pubkey_material = slurp("test_keys/pub/import_keys_multi_pub_concat.asc");
    stringlist_t* keylist = NULL;
    uint64_t changes = 0;
    PEP_STATUS status = import_key(session, pubkey_material.c_str(), pubkey_material.size(), NULL, &keylist, &changes);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);    
    ASSERT_EQ(stringlist_length(keylist), 10);
    ASSERT_EQ(changes, 1023); 
    free_stringlist(keylist);
    keylist = NULL;
    changes = 0;    
    string privkey_material = slurp("test_keys/priv/import_keys_multi_priv_concat.asc");
    status = import_key(session, privkey_material.c_str(), privkey_material.size(), NULL, &keylist, &changes);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);    
    ASSERT_EQ(stringlist_length(keylist), 10);
    ASSERT_EQ(changes, 1023); // This is always going to alter the key I guess
    free_stringlist(keylist);
}

TEST_F(ImportKeyTest, check_import_fpr_list_pub_blob) {
    // Contains 10 keys
    string pubkey_material = slurp("test_keys/pub/import_keys_multi_pub_serial_blob.asc");
    stringlist_t* keylist = NULL;
    uint64_t changes = 0;
    PEP_STATUS status = import_key(session, pubkey_material.c_str(), pubkey_material.size(), NULL, &keylist, &changes);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);    
    ASSERT_EQ(stringlist_length(keylist), 10);
    ASSERT_EQ(changes, 1023); // 2^10 - 1
}

TEST_F(ImportKeyTest, check_import_fpr_list_priv_blob) {
    // Contains 10 keys
    string privkey_material = slurp("test_keys/priv/import_keys_multi_priv_serial_blob.asc");
    stringlist_t* keylist = NULL;
    uint64_t changes = 0;
    PEP_STATUS status = import_key(session, privkey_material.c_str(), privkey_material.size(), NULL, &keylist, &changes);
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    ASSERT_NE(keylist, nullptr);    
    ASSERT_EQ(stringlist_length(keylist), 10);
    ASSERT_EQ(changes, 1023); 
}
