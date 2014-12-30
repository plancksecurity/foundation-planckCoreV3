#include <iostream>
#include <assert.h>
#include "message_api.h"

using namespace std;

int main() {
    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    pEp_identity * me = new_identity("outlooktest@dingens.org", NULL, "23", "Outlook Test");
    me->me = true;
    identity_list *to = new_identity_list(new_identity("vb@dingens.org", NULL, "42", "Volker Birk"));

    message *msg = new_message(PEP_dir_outgoing, me, to, "hello, world");

    free_message(msg);

    cout << "calling release()\n";
    release(session);
    return 0;
}

