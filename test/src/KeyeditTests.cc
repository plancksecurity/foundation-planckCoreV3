// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring>

#include "pEpEngine.h"
#include "platform.h"

#include <cpptest.h>
#include "EngineTestSessionSuite.h"
#include "KeyeditTests.h"

using namespace std;

KeyeditTests::KeyeditTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyeditTests::check_keyedit"),
                                                                      static_cast<Func>(&KeyeditTests::check_keyedit)));
}

void KeyeditTests::check_keyedit() {

    // generate test key

    cout << "\ngenerating key for keyedit test\n";
    pEp_identity *identity = new_identity(
            "expire@dingens.org",
            NULL,
            "423",
            "expire test key"
        );
    TEST_ASSERT_MSG((identity), "identity");
    PEP_STATUS generate_status = generate_keypair(session, identity);
    cout << "generate_keypair() exits with " << generate_status << "\n";
    TEST_ASSERT_MSG((generate_status == PEP_STATUS_OK), "generate_status == PEP_STATUS_OK");
    cout << "generated key is " << identity->fpr << "\n";

    string key(identity->fpr);
    free_identity(identity);

    // keyedit test code

    timestamp *ts = new_timestamp(time(0));
    ts->tm_year += 2;

    cout << "key shell expire on " << asctime(ts) << "\n";

    PEP_STATUS status2 = renew_key(session, key.c_str(), ts);
    cout << "renew_key() exited with " << status2 << "\n";
    TEST_ASSERT_MSG((status2 == PEP_STATUS_OK), "status2 == PEP_STATUS_OK");
    free_timestamp(ts);

    cout << "key renewed.\n";

    cout << "key will be revoked\n";
    PEP_STATUS status3 = revoke_key(session, key.c_str(), "revoke test");
    cout << "revoke_key() exited with " << status3 << "\n";
    TEST_ASSERT_MSG((status3 == PEP_STATUS_OK), "status3 == PEP_STATUS_OK");
    
    cout << "key revoked.\n";

    // Because pEp's policy is never to delete keys from the keyring and delete_keypair
    // though gnupg makes responding to a dialog mandatory under Debian, we will not test
    // this anymore.
    
    // cout << "deleting key pair " << key.c_str() << "\n";
    // PEP_STATUS delete_status = delete_keypair(session, key.c_str());
    // cout << "delete_keypair() exits with " << delete_status << "\n";
    // TEST_ASSERT_MSG((delete_status == PEP_STATUS_OK), "delete_status == PEP_STATUS_OK");
}
