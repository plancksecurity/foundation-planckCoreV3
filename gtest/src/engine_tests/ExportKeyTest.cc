// This file is under GNU General Public License 3.0// see LICENSE.txt#include <stdlib.h>#include <cstring>#include <string>#include "test_util.h"#include "pEpEngine.h"#include <gtest/gtest.h>


namespace {

    //The fixture for ExportKeyTest
    class ExportKeyTest public ::testing::Test {
        public:
            Engine engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            ExportKeyTest() {
                // You can do set-up work for each test here.
            }

            ~ExportKeyTest() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
            }

            // Objects declared here can be used by all tests in the ExportKeyTest suite.
    };

}  // namespace


void ExportKeyTests::check_export_key_no_key() {
    char* keydata = NULL;
    size_t keysize = 0;
    PEP_STATUS status = export_key(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
                                   &keydata, &keysize);
    ASSERT_EQ(status , PEP_KEY_NOT_FOUND);
    free(keydata);
    keydata = NULL;
    keysize = 0;
    status = export_secret_key(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
                                   &keydata, &keysize);
    ASSERT_EQ(status , PEP_KEY_NOT_FOUND);
    free(keydata);

}

void ExportKeyTests::check_export_key_pubkey() {
    // Own pub key
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"),
                    "Unable to import test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");

    char* keydata = NULL;
    size_t keysize = 0;
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", &keylist);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39");
    free_stringlist(keylist);

    status = export_key(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
                                   &keydata, &keysize);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(keydata, nullptr);
    ASSERT_GT(keysize, 0);

    free(keydata);
}

void ExportKeyTests::check_export_key_secret_key() {
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"),
                    "Unable to import test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc"),
                    "Unable to import test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc");
    char* keydata = NULL;
    size_t keysize = 0;
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", &keylist);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39");
    free_stringlist(keylist);
    keylist = NULL;

    bool has_private = false;
    contains_priv_key(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", &has_private);
    ASSERT_TRUE(has_private);

    status = export_key(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
                                   &keydata, &keysize);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(keydata, nullptr);
    ASSERT_GT(keysize, 0);

    free(keydata);
    keydata = NULL;
    keysize = 0;
    status = export_secret_key(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
                                   &keydata, &keysize);
    ASSERT_EQ(status , PEP_STATUS_OK);

    free(keydata);
}


void ExportKeyTests::check_export_key_no_secret_key() {
    // Own pub key
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"),
                    "Unable to import test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");

    char* keydata = NULL;
    size_t keysize = 0;
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", &keylist);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39");

    status = export_key(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
                                   &keydata, &keysize);
    ASSERT_EQ(status , PEP_STATUS_OK);
    free(keydata);
    keydata = NULL;
    keysize = 0;
    status = export_secret_key(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
                                   &keydata, &keysize);
    ASSERT_EQ(status , PEP_KEY_NOT_FOUND);
    free(keydata);
}
