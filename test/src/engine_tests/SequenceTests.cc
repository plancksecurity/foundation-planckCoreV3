// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <iostream>
#include <string>
#include <cstring> // for std::strdup()
#include <assert.h>
#include "pEpEngine.h"

#include "EngineTestSuite.h"
#include "EngineTestIndividualSuite.h"
#include "SequenceTests.h"

using namespace std;

SequenceTests::SequenceTests(string suitename, string test_home_dir) : 
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {            
    TEST_ADD(SequenceTests::check_sequences);
}

void SequenceTests::check_sequences() {
    cout << "\n*** sequence_test ***\n\n";

    // sequence test code

    int32_t value1 = 0;
    char *name1 = strdup("test");
    assert(name1);
    PEP_STATUS status2 = sequence_value(session, name1, &value1);
    assert(status2 == PEP_STATUS_OK);

    cout << "test sequence: " << value1 << "\n";

    int32_t value2 = 0;
    PEP_STATUS status3 = sequence_value(session, name1, &value2);
    assert(status3 == PEP_STATUS_OK);

    cout << "test sequence: " << value2 << "\n";
    assert(value2 == value1 + 1);
//    free(name1);

    cout << "testing sequence violation\n";
    int32_t value3 = value2;
    PEP_STATUS status4 = sequence_value(session, name1, &value3);
    assert(status4 == PEP_SEQUENCE_VIOLATED);

    cout << "testing sequence non-violation\n";
    int32_t value4 = value2 + 1;
    PEP_STATUS status5 = sequence_value(session, name1, &value4);
    assert(status5 == PEP_STATUS_OK);

    cout << "testing UUID generation\n";
    int32_t value5 = 0;
    char name2[37] = { 0, };
    PEP_STATUS status6 = sequence_value(session, name2, &value5);
    assert(status6 == PEP_OWN_SEQUENCE);
    cout << "UUID created: " << name2 << "\n";

    cout << "set sequence value\n";
    int32_t value6 = value2 + 10;
    PEP_STATUS status7 = sequence_value(session, name1, &value6);
    assert(status7 == PEP_STATUS_OK);
    cout << "value set to " << value6 << "\n";
}
