#include <iostream>
#include <string>
#include <assert.h>
#include "message_api.h"

using namespace std;

int main() {
    cout << "\n*** pgp_binary_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // pgp_binary test code

    const char *path;
    PEP_STATUS status2 = get_binary_path(PEP_crypt_OpenPGP, &path);
    assert(status2 == PEP_STATUS_OK);
#ifdef USE_GPG
    assert(path);
#endif
    if (path)
        cout << "PGP binary at " << path << "\n";
    else
        cout << "no PGP binary path available\n";

    cout << "calling release()\n";
    release(session);
    return 0;
}

