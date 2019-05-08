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
    const char* address = "hans@xn--bcher-kva.tld";
    const char* fpr = "00B5BB6769B1F451705445E208AD6E9400D38894";
    const char* userid = "Hans";
    const char* username = "SuperDuperHans";
    const string pub_key = slurp("test_keys/pub/hans@xn--bcher-kva.tld_-0x08AD6E9400D38894_pub.asc");

    PEP_STATUS statuspub = import_key(session, pub_key.c_str(), pub_key.length(), NULL);
    TEST_ASSERT_MSG((statuspub == PEP_TEST_KEY_IMPORT_SUCCESS), "statuspub == PEP_STATUS_OK");

    pEp_identity* hans = new_identity(address, NULL, userid, username);

    PEP_STATUS status = set_identity(session, hans);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    free_identity(hans);

    // Lookup using different spellings of the email address.
    const char *addresses[] = {
        "hans@xn--bcher-kva.tld",
        "Hans@xn--bcher-kva.tld",
        "Hans@xn--Bcher-kva.tld",
        "hans@bücher.tld",
        "Hans@bücher.tld",
        "HANS@BÜCHER.TLD",
    };

    for (int i = 0; i < sizeof(addresses) / sizeof(addresses[0]); i ++) {
        const char *address = addresses[i];

        pEp_identity *hans = new_identity(address, NULL, NULL, NULL); 
        PEP_STATUS status = update_identity(session, hans);
        TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
        TEST_ASSERT_MSG((hans->fpr), "hans->fpr");
        TEST_ASSERT_MSG((strcmp(hans->fpr, fpr) == 0), "strcmp(hans->fpr, fpr) == 0");
        TEST_ASSERT_MSG((hans->username), "hans->username");
        TEST_ASSERT_MSG((hans->user_id), "hans->user_id");

        cout << "hans->username: " << hans->username << endl;
        cout << "username: " << username << endl;

        cout << "hans->user_id: " << hans->user_id << endl;
        cout << "userid: " << userid << endl;

        TEST_ASSERT_MSG((strcmp(hans->username, username) == 0), "strcmp(hans->username, username) == 0");
        TEST_ASSERT_MSG((strcmp(hans->user_id, userid) == 0), "strcmp(hans->user_id, userid) == 0");

        TEST_ASSERT_MSG((!hans->me), "!hans->me"); 
        TEST_ASSERT_MSG((hans->comm_type == PEP_ct_OpenPGP_unconfirmed), "hans->comm_type == PEP_ct_OpenPGP_unconfirmed");
        TEST_ASSERT_MSG((strcmp(hans->address, address) == 0), "strcmp(hans->address, address) == 0");

        cout << "PASS: update_identity() correctly retrieved extant record with matching address, id, and username" << endl << endl;
        free_identity(hans);
    }
}
