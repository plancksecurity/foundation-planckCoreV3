// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>
#include "mime.h"
#include "message_api.h"
#include "test_util.h"

using namespace std;

int main() {
    cout << "\n*** trust manipulation test ***\n\n";

    PEP_SESSION session;

    char* user_id = get_new_uuid();
    
    cout << "calling init()\n";
    PEP_STATUS status = init(&session);   
    assert(status == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    cout << "creating id for : ";
    char *uniqname = strdup("AAAAtestuser@testdomain.org");
    srandom(time(NULL));
    for(int i=0; i < 4;i++)
        uniqname[i] += random() & 0xf;
    
    cout << uniqname << "\n";
    pEp_identity * user = new_identity(uniqname, NULL, user_id, "Test User");
    status = generate_keypair(session, user);
    assert(user->fpr);

    char* keypair1 = strdup(user->fpr);
    cout << "generated fingerprint \n";
    cout << user->fpr << "\n";

    cout << "Setting key 1 (" << user->fpr << ") as the default for the identity." << endl;
    // Put identity in the DB
    status = set_identity(session, user);

    cout << "creating second keypair for : " << uniqname << endl;
    
    pEp_identity * user_again = new_identity(uniqname, NULL, user_id, "Test User");
    status = generate_keypair(session, user_again);
    assert(user_again->fpr);

    char* keypair2 = strdup(user_again->fpr);
    cout << "generated fingerprint \n";
    cout << user_again->fpr << "\n";

    assert(strcmp(user->fpr, user_again->fpr) != 0);
    update_identity(session, user);
    assert(strcmp(user->fpr, keypair1) == 0);
    cout << "Key 1 (" << user->fpr << ") is still the default for the identity after update_identity." << endl;

    // First, trust the SECOND key; make sure it replaces as the default
    cout << "Set trust bit for key 2 (" << keypair2 << ") and ensure it replaces key 1 as the default." << endl;
    status = trust_personal_key(session, user_again);
    status = update_identity(session, user);
    assert(user->comm_type == PEP_ct_OpenPGP);
    assert(strcmp(user->fpr, keypair2) == 0);
    cout << "Key 2 (" << user->fpr << ") is now the default for the identity after update_identity, and its comm_type is PEP_ct_OpenPGP (trust bit set!)." << endl;

    cout << "Now make key 2 not trusted (which also removes it as a default everywhere)." << endl;
    status = key_reset_trust(session, user);
    status = get_trust(session, user);
    assert(strcmp(user->fpr, keypair2) == 0);
    assert(user->comm_type == PEP_ct_OpenPGP_unconfirmed);
    cout << "Key 2 is untrusted in the DB." << endl;

    cout << "Now let's mistrust key 2 in the DB." << endl;
    // Now let's mistrust the second key.
    status = key_mistrusted(session, user);
    status = get_trust(session, user);
    assert(strcmp(user->fpr, keypair2) == 0);
    assert(user->comm_type == PEP_ct_mistrusted);
    cout << "Hoorah, we now do not trust key 2. (We never liked key 2 anyway.)" << endl;
    cout << "Now we call update_identity to see what gifts it gives us (should be key 1 with key 1's initial trust.)" << endl;    
    status = update_identity(session, user);
    assert(strcmp(user->fpr, keypair1) == 0);
    assert(user->comm_type == PEP_ct_OpenPGP_unconfirmed);
    cout << "Yup, got key 1, and the trust status is PEP_ct_OpenPGP_unconfirmed." << endl;
    
    cout << "Passed all of our exciting messing with the trust DB. Moving on..." << endl;
 
    free(user_id);
    free(keypair1);
    free(uniqname);
    free_identity(user);
    release(session);
    
    return 0;
}
