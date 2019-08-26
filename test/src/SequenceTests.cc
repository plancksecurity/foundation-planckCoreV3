// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <iostream>
#include <string>
#include <cstring> // for std::strdup()
#include <assert.h>
#include "pEpEngine.h"

#include "EngineTestSuite.h"
#include "EngineTestSessionSuite.h"
#include "SequenceTests.h"

using namespace std;

SequenceTests::SequenceTests(string suitename, string test_home_dir) : 
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {            
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SequenceTests::check_sequences"),
                                                                      static_cast<Func>(&SequenceTests::check_sequences)));
}

void SequenceTests::check_sequences() {
    cout << "\n*** sequence_test ***\n\n";

    // sequence test code

    int32_t value1;
    PEP_STATUS status2 = sequence_value(session, "test1", &value1);
    assert(status2 == PEP_STATUS_OK);

    cout << "test sequence: " << value1 << "\n";

    int32_t value2;
    PEP_STATUS status3 = sequence_value(session, "test1", &value2);
    assert(status3 == PEP_STATUS_OK);

    cout << "test sequence: " << value2 << "\n";
    assert(value2 == value1 + 1);
}
