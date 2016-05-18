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

    int32_t value1;
    PEP_STATUS status2 = sequence_value(session, "test", &value1);
    assert(status2 == PEP_STATUS_OK);

    cout << "test sequence: " << value1 << "\n";

    int32_t value2;
    PEP_STATUS status3 = sequence_value(session, "test", &value2);
    assert(status3 == PEP_STATUS_OK);

    cout << "test sequence: " << value2 << "\n";
    assert(value2 == value1 + 1);

    cout << "calling release()\n";
    release(session);
    return 0;
}

