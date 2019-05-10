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
#include "RevocationTests.h"

using namespace std;

RevocationTests::RevocationTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("RevocationTests::revocation"),
                                                                      static_cast<Func>(&RevocationTests::revocation)));
}

void RevocationTests::setup() {
    EngineTestSessionSuite::setup();
}

void RevocationTests::tear_down() {
    EngineTestSessionSuite::tear_down();
}

void RevocationTests::revocation() {
    // Read the key.
    const string key = slurp("test_keys/priv/pep-test-linda-0xDCD555B6055ADE22_priv.asc");

    PEP_STATUS status = import_key(session, key.c_str(), key.length(), NULL);
    TEST_ASSERT_MSG((status == PEP_TEST_KEY_IMPORT_SUCCESS), "status == PEP_STATUS_OK");

    pEp_identity* pre = new_identity("linda@example.org", NULL, NULL, NULL);
    status = update_identity(session, pre);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((pre->comm_type == PEP_ct_OpenPGP_unconfirmed), tl_ct_string(pre->comm_type));

    // Read in the revocation certificate.
    const string rev = slurp("test_keys/priv/pep-test-linda-0xDCD555B6055ADE22.rev");

    status = import_key(session, rev.c_str(), rev.length(), NULL);
    TEST_ASSERT_MSG((status == PEP_TEST_KEY_IMPORT_SUCCESS), "status == PEP_STATUS_OK");

    pEp_identity* post = new_identity("linda@example.org", NULL, NULL, NULL);
    status = update_identity(session, post);
    // PEP_KEY_UNSUITABLE => revoked (or something similar).
    TEST_ASSERT_MSG((status == PEP_KEY_UNSUITABLE), tl_status_string(status));
    TEST_ASSERT_MSG((post->comm_type == PEP_ct_key_revoked), tl_ct_string(post->comm_type));
}
