// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "UserIdCollusionTests.h"

using namespace std;

UserIdCollusionTests::UserIdCollusionTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("UserIdCollusionTests::check_user_id_collusion"),
                                                                      static_cast<Func>(&UserIdCollusionTests::check_user_id_collusion)));
}

void UserIdCollusionTests::check_user_id_collusion() {
    TEST_ASSERT(true);
}

