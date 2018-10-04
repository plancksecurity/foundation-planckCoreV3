// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "UserIdCollisionTests.h"

using namespace std;

UserIdCollisionTests::UserIdCollisionTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("UserIdCollisionTests::check_user_id_collision"),
                                                                      static_cast<Func>(&UserIdCollisionTests::check_user_id_collision)));
}

void UserIdCollisionTests::check_user_id_collision() {
    TEST_ASSERT(true);
}

