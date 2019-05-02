// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include <cpptest.h>
#include "test_util.h"

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "ExportKeyTests.h"

using namespace std;

ExportKeyTests::ExportKeyTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("ExportKeyTests::check_export_key_no_key"),
                                                                      static_cast<Func>(&ExportKeyTests::check_export_key_no_key)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("ExportKeyTests::check_export_key_no_secret_key"),
                                                                      static_cast<Func>(&ExportKeyTests::check_export_key_no_secret_key)));
}

void ExportKeyTests::check_export_key_no_key() {
    char* keydata = NULL;
    size_t keysize = 0;
    PEP_STATUS status = export_key(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", 
                                   &keydata, &keysize);
    TEST_ASSERT_MSG(status == PEP_KEY_NOT_FOUND, tl_status_string(status));
    free(keydata);
    keydata = NULL;
    keysize = 0;
    status = export_secret_key(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", 
                                   &keydata, &keysize);
    TEST_ASSERT_MSG(status == PEP_KEY_NOT_FOUND, tl_status_string(status));
    free(keydata);

    TEST_ASSERT(true);
}

void ExportKeyTests::check_export_key_no_secret_key() {
    // Own pub key
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"),
                    "Unable to import test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");

    char* keydata = NULL;
    size_t keysize = 0;
    PEP_STATUS status = export_key(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", 
                                   &keydata, &keysize);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    free(keydata);
    keydata = NULL;
    keysize = 0;
    status = export_secret_key(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", 
                                   &keydata, &keysize);
    TEST_ASSERT_MSG(status == PEP_KEY_NOT_FOUND, tl_status_string(status));
    free(keydata);
    TEST_ASSERT(true);
}
