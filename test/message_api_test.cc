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

    cout << "creating message…\n";
    pEp_identity * me = new_identity("outlooktest@dingens.org", NULL, "23", "Outlook Test");
    me->me = true;
    identity_list *to = new_identity_list(new_identity("vb@dingens.org", NULL, "42", "Volker Birk"));
    message *msg = new_message(PEP_dir_outgoing, me, to, "hello, world");
    assert(msg);
    cout << "message created.\n";

    cout << "encrypting message…\n";
    message *enc_msg;
    cout << "calling encrypt_message()\n";
    PEP_STATUS status2 = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_pieces);
    assert(status2 == PEP_STATUS_OK);
    assert(enc_msg);
    cout << "message encrypted.\n";

    cout << "freeing messages…\n";
    free_message(msg);
    free_message(enc_msg);
    cout << "done.\n";

    cout << "calling release()\n";
    release(session);
    return 0;
}

