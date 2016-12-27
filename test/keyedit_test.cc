// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "platform.h"

#include <iostream>
#include <fstream>
#include <string>
#include <assert.h>

#include "pEpEngine.h"

using namespace std;

int main() {
    cout << "\n*** keyedit_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // generate test key

    cout << "\ngenerating key for keyedit test\n";
    pEp_identity *identity = new_identity(
            "expire@dingens.org",
            NULL,
            "423",
            "expire test key"
        );
    assert(identity);
    PEP_STATUS generate_status = generate_keypair(session, identity);
    cout << "generate_keypair() exits with " << generate_status << "\n";
    assert(generate_status == PEP_STATUS_OK);
    cout << "generated key is " << identity->fpr << "\n";

    string key(identity->fpr);
    free_identity(identity);

    // keyedit test code

    timestamp *ts = new_timestamp(time(0));
    ts->tm_year += 2;

    cout << "key shell expire on " << asctime(ts) << "\n";

    PEP_STATUS status2 = renew_key(session, key.c_str(), ts);
    cout << "renew_key() exited with " << status2 << "\n";
    assert(status2 == PEP_STATUS_OK);
    free_timestamp(ts);

    cout << "key renewed.\n";

    cout << "key will be revoked\n";
    PEP_STATUS status3 = revoke_key(session, key.c_str(), "revoke test");
    cout << "revoke_key() exited with " << status3 << "\n";
    assert(status3 == PEP_STATUS_OK);
    
    cout << "key revoked.\n";

    cout << "deleting key pair " << key.c_str() << "\n";
    PEP_STATUS delete_status = delete_keypair(session, key.c_str());
    cout << "delete_keypair() exits with " << delete_status << "\n";
    assert(delete_status == PEP_STATUS_OK);

    cout << "calling release()\n";
    release(session);
    return 0;
}

