// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring> // for strcmp()
#include "TestConstants.h"

#include "pEpEngine.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"

#include <cpptest.h>
#include "EngineTestSessionSuite.h"
#include "LookupTests.h"

using namespace std;

LookupTests::LookupTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("LookupTests::lookup"),
                                                                      static_cast<Func>(&LookupTests::lookup)));
}

void LookupTests::setup() {
    EngineTestSessionSuite::setup();
}

void LookupTests::tear_down() {
    EngineTestSessionSuite::tear_down();
}

void LookupTests::lookup() {
    // 1. create original identity
    const char* expected_address = "hans@xn--bcher-kva.tld";
    const char* fpr = "00B5BB6769B1F451705445E208AD6E9400D38894";
    const char* userid = "Hans";
    const char* username = "SuperDuperHans";
    const string pub_key = slurp("test_keys/pub/hans@xn--bcher-kva.tld_-0x08AD6E9400D38894_pub.asc");

    PEP_STATUS statuspub = import_key(session, pub_key.c_str(), pub_key.length(), NULL);
    TEST_ASSERT_MSG((statuspub == PEP_TEST_KEY_IMPORT_SUCCESS), "statuspub == PEP_STATUS_OK");

    pEp_identity* hans = new_identity(expected_address, NULL, userid, username);

    PEP_STATUS status = set_identity(session, hans);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    free_identity(hans);

    // Lookup using different spellings of the email address.
    const char *addresses[] = {
        // Check case folding.
        "hans@xn--bcher-kva.tld",
        "Hans@xn--bcher-kva.tld",
        "Hans@xn--Bcher-kva.tld",

        // Check puny code normalization.  Note: only Sequoia does
        // puny code normalization.
#ifdef USE_SEQUOIA
        "hans@bücher.tld",
        "Hans@bücher.tld",
        "HANS@BÜCHER.TLD",
#endif
    };

    for (int i = 0; i < sizeof(addresses) / sizeof(addresses[0]); i ++) {
        const char *address = addresses[i];

        pEp_identity *hans = new_identity(address, NULL, NULL, NULL); 
        PEP_STATUS status = update_identity(session, hans);
        TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));

        // We should always get the same fingerprint.
        TEST_ASSERT_MSG((hans->fpr), "hans->fpr");
        TEST_ASSERT_MSG((strcmp(hans->fpr, fpr) == 0), "strcmp(hans->fpr, fpr) == 0");

        // We don't compare hans->username or hans->user_id in case
        // the engine doesn't have the same concept of equality (as of
        // 2019.5, this is the case: pgp_sequoia.c does puny code
        // normalization, but the engine doesn't).
        TEST_ASSERT_MSG((hans->username), "hans->username");
        TEST_ASSERT_MSG((hans->user_id), "hans->user_id");

        // We should get the address that we looked up; no
        // normalization is done.
        TEST_ASSERT_MSG((strcmp(hans->address, address) == 0), "strcmp(hans->address, address) == 0");

        TEST_ASSERT_MSG((!hans->me), "!hans->me"); 
        TEST_ASSERT_MSG((hans->comm_type == PEP_ct_OpenPGP_unconfirmed), "hans->comm_type == PEP_ct_OpenPGP_unconfirmed");

        cout << "PASS: update_identity() correctly retrieved OpenPGP key for '" << expected_address << "' using '" << address << "'" << endl << endl;
        free_identity(hans);
    }
}
