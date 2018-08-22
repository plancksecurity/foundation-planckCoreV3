// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "KeyResetMessageTests.h"

using namespace std;

KeyResetMessageTests::KeyResetMessageTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyResetMessageTests::check_key_reset_message"),
                                                                      static_cast<Func>(&KeyResetMessageTests::check_key_reset_message)));
}

void KeyResetMessageTests::check_key_reset_message() {
    TEST_ASSERT(true);
}

