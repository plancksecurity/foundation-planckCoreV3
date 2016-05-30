#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>
#include "mime.h"
#include "message_api.h"

using namespace std;

int main() {
    cout << "\n*** revoke_regen_attach_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    cout << "creating own id for : ";
    char *uniqname = strdup("AAAAtestuser@testdomain.org");
    for(int i=0; i < 4;i++)
        uniqname[i] += random() & 0xf;
    
    cout << uniqname << "\n";
    pEp_identity * me = new_identity(uniqname, NULL, PEP_OWN_USERID, "Test User");
    free(uniqname);
    myself(session, me);

    cout << "generated fingerprint \n";
    cout << me->fpr << "\n";

    const char *prev_fpr = strdup(me->fpr);
    
    key_compromized(session, me);

    cout << "re-generated fingerprint \n";
    cout << me->fpr << "\n";
    
    assert(strcmp(me->fpr, prev_fpr));


    // TODO test that revocation is attached to message for some time...

    return 0;
}

