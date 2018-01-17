// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <iostream>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()
#include <assert.h>
#include "pEpEngine.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"

using namespace std;

int main() {
    cout << "\n*** userid_alias_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status = init(&session);
    assert(status == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string alice_priv_key = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    
    PEP_STATUS statuspub = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    PEP_STATUS statuspriv = import_key(session, alice_priv_key.c_str(), alice_priv_key.length(), NULL);
    assert(statuspub == PEP_STATUS_OK);
    assert(statuspriv == PEP_STATUS_OK);

    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", PEP_OWN_USERID, "Alice Test");

    const char* alias1 = "TheBigCheese";
    const char* alias2 = "PEBKAC";

    char* own_id = NULL;
    status = get_default_own_userid(session, &own_id);
    if (!own_id)
        own_id = strdup(PEP_OWN_USERID);
    
    cout << "First, set up an identity with PEP_OWN_USERID as user_id." << endl;
    status = myself(session, alice);
    assert(status == PEP_STATUS_OK);
    cout << "After myself, user_id is " << alice->user_id << endl;
    assert(strcmp(alice->user_id, own_id) == 0);
    
    cout << "Now set up an identity with " << alias1 << " as user_id." << endl;
    free(alice->user_id);
    
    alice->user_id = strdup(alias1);
    status = myself(session, alice);
    assert(status == PEP_STATUS_OK);
    cout << "After myself, user_id is " << alice->user_id << endl;
    assert(strcmp(alice->user_id, own_id) == 0);

    cout << "Now set up an identity with " << alias2 << " as user_id." << endl;
    free(alice->user_id);
    
    alice->user_id = strdup(alias2);
    status = myself(session, alice);
    assert(status == PEP_STATUS_OK);
    cout << "After myself, user_id is " << alice->user_id << endl;
    assert(strcmp(alice->user_id, own_id) == 0);    

    char* default_id = NULL;
    status = get_userid_alias_default(session, alias1, &default_id);
    assert(status == PEP_STATUS_OK);
    cout << "Default user_id for " << alias1 << " is " << default_id << endl;
    assert(strcmp(default_id, own_id) == 0);
    
    free(default_id);
    default_id = NULL;
    status = get_userid_alias_default(session, alias2, &default_id);
    assert(status == PEP_STATUS_OK);
    cout << "Default user_id for " << alias2 << " is " << default_id << endl;
    assert(strcmp(default_id, own_id) == 0);
    
    
    return 0;
}
