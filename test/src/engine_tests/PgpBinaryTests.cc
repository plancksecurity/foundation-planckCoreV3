// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <iostream>

#include "pEpEngine.h"
#include "message_api.h"

#include <cpptest.h>
#include "EngineTestSessionSuite.h"
#include "PgpBinaryTests.h"

using namespace std;

PgpBinaryTests::PgpBinaryTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("PgpBinaryTests::check_pgp_binary"),
                                                                      static_cast<Func>(&PgpBinaryTests::check_pgp_binary)));
}

void PgpBinaryTests::check_pgp_binary() {

    // pgp_binary test code

    const char *path;
    PEP_STATUS status2 = get_binary_path(PEP_crypt_OpenPGP, &path);
    TEST_ASSERT(status2 == PEP_STATUS_OK);
#ifdef USE_GPG
    TEST_ASSERT(path);
#endif
    if (path)
        cout << "PGP binary at " << path << "\n";
    else
        cout << "no PGP binary path available\n";

    cout << "calling release()\n";
}
