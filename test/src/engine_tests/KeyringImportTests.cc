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
#include "KeyringImportTests.h"

using namespace std;

KeyringImportTests::KeyringImportTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyringImportTests::import"),
                                                                      static_cast<Func>(&KeyringImportTests::import)));
}

void KeyringImportTests::setup() {
    EngineTestSessionSuite::setup();
}

void KeyringImportTests::tear_down() {
    EngineTestSessionSuite::tear_down();
}

void KeyringImportTests::import() {
    const string pub_key = slurp("test_keys/pub/pep-test-keyring.asc");

    PEP_STATUS statuspub = import_key(session, pub_key.c_str(), pub_key.length(), NULL);
    TEST_ASSERT_MSG((statuspub == PEP_TEST_KEY_IMPORT_SUCCESS), "statuspub == PEP_STATUS_OK");

    struct entry {
        const char *fingerprint;
        const char *address;
    };

    struct entry entries[] = {
      { "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
        "pep.test.alice@pep-project.org" },
      { "3D8D9423D03DDF61B60161150313D94A1CCBC7D7",
        "pep.test.apple@pep-project.org" },
      { "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
        "pep.test.bob@pep-project.org" },
      { "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42",
        "pep-test-carol@pep-project.org" },
      { "E8AC9779A2D13A15D8D55C84B049F489BB5BCCF6",
        "pep-test-dave@pep-project.org" },
      { "1B0E197E8AE66277B8A024B9AEA69F509F8D7CBA",
        "pep-test-erin@pep-project.org" },
      { "B022B74476D8A8E1F01E55FBAB6972569A7FC670",
        "pep-test-frank@pep-project.org" },
      { "906C9B8349954E82C5623C3C8C541BD4E203586C",
        "pep-test-gabrielle@pep-project.org" },
      { "AA2E4BEB93E5FE33DEFD8BE1135CD6D170DCF575",
        "pep.test.john@pep-project.org" },
    };

    for (int i = 0; i < sizeof(entries) / sizeof(entries[0]); i ++) {
        const char *address = entries[i].address;
        const char *fpr = entries[i].fingerprint;

        cout << "Looking up: " << address << ", should have fingerprint: " << fpr << endl;
        pEp_identity *id = new_identity(address, NULL, NULL, NULL);
        PEP_STATUS status = update_identity(session, id);
        TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
        cout << "Got: " << (id->fpr ?: "NULL") << " -> " << (id->address ?: "NULL") << endl;

        // We should always get the same fingerprint.
        TEST_ASSERT_MSG((id->fpr), "id->fpr");
        TEST_ASSERT_MSG((strcmp(id->fpr, fpr) == 0), "strcmp(id->fpr, fpr) == 0");

        free_identity(id);
    }
}
