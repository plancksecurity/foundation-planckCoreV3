#include <iostream>
#include <string>
#include <assert.h>
#include "pEpEngine.h"

using namespace std;

int main() {
    cout << "\n*** crashdump_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // MODULE test code

    char *text;
    PEP_STATUS status2 = get_crashdump_log(session, 0, &text);
    assert(status2 == PEP_STATUS_OK);
    cout << text;

    cout << "calling release()\n";
    release(session);
    return 0;
}

