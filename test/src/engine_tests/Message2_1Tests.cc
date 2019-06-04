// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include <cpptest.h>
#include "test_util.h"

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "Message2_1Tests.h"

using namespace std;

Message2_1Tests::Message2_1Tests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Message2_1Tests::check_message2_1"),
                                                                      static_cast<Func>(&Message2_1Tests::check_message2_1)));
}

void Message2_1Tests::check_message2_1() {
    TEST_ASSERT(true);
}

