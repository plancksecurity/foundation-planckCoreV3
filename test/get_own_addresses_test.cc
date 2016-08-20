#include <iostream>
#include <string>
#include <assert.h>
#include "pEpEngine_test.h"
#include "pEpEngine.h"

using namespace std;

int main() {
    cout << "\n*** get_own_addresses_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    ASSERT_STATUS(status1);
    assert(session);
    cout << "init() completed.\n";

    // get_own_addresses test code

    cout << "calling get_own_addresses()\n";
    stringlist_t *addresses = NULL;
    PEP_STATUS status2 = get_own_addresses(session, &addresses);
    ASSERT_STATUS(status2);
    assert(addresses);
    cout << "success.\n";

    cout << "addresses received:\n";
    for (stringlist_t *_a = addresses; _a && _a->value; _a = _a->next)
        cout << _a->value << "\n";
    cout << ".\n";

    cout << "calling release()\n";
    release(session);
    return 0;
}

