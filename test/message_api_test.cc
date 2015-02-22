#include <iostream>
#include <assert.h>
#include "message_api.h"

using namespace std;

int main() {
    cout << "\n*** message_api_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // message_api test code

    cout << "creating message…\n";
    pEp_identity * me = new_identity("outlooktest@dingens.org", NULL, "23", "Outlook Test");
    me->me = true;
    identity_list *to = new_identity_list(new_identity("vb@dingens.org", NULL, "42", "Volker Birk"));
    message *msg = new_message(PEP_dir_outgoing, me, to, "hello, world");
    assert(msg);
    cout << "message created.\n";

    cout << "encrypting message as MIME multipart…\n";
    message *enc_msg3;
    cout << "calling encrypt_message()\n";
    PEP_STATUS status3 = encrypt_message(session, msg, NULL, &enc_msg3, PEP_enc_MIME_multipart);
    assert(status3 == PEP_STATUS_OK);
    assert(enc_msg3);
    cout << "message encrypted.\n";
    free_message(enc_msg3);
    
    cout << "freeing messages…\n";
    free_message(msg);
    cout << "done.\n";

    cout << "calling release()\n";
    release(session);
    return 0;
}

