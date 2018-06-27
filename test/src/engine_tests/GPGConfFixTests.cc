// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "GPGConfFixTests.h"

using namespace std;

GPGConfFixTests::GPGConfFixTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_g_p_g_conf_fix"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_g_p_g_conf_fix)));
}

void GPGConfFixTests::check_g_p_g_conf_fix() {
    TEST_ASSERT(true);
}

