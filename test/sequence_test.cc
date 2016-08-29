#include <iostream>
#include <string>
#include <assert.h>
#include "pEpEngine.h"

using namespace std;

int main() {
    cout << "\n*** sequence_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

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
    free(name1);

    cout << "testing sequence violation\n";
    int32_t value3 = value2 - 1;
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
    assert(status6 == PEP_STATUS_OK);
    cout << "UUID created: " << name2 << "\n";

    cout << "calling release()\n";
    release(session);
    return 0;
}

