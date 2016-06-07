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
    cout << "\n*** message_api_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // message_api test code

    cout << "creating message…\n";
    pEp_identity * me2 = new_identity("outlooktest@dingens.org", NULL, PEP_OWN_USERID, "Outlook Test");
    me2->me = true;
    identity_list *to2 = new_identity_list(new_identity("vb@dingens.org", NULL, "42", "Volker Birk"));
    message *msg2 = new_message(PEP_dir_outgoing);
    assert(msg2);
    msg2->from = me2;
    msg2->to = to2;
    msg2->shortmsg = strdup("hello, world");
    cout << "message created.\n";

    char *text2;
    PEP_STATUS status2 = mime_encode_message(msg2, false, &text2);
    assert(status2 == PEP_STATUS_OK);
    assert(text2);

    cout << "decrypted:\n\n";
    cout << text2 << "\n";

    free(text2);

    cout << "encrypting message as MIME multipart…\n";
    message *enc_msg2;
    cout << "calling encrypt_message()\n";
    status2 = encrypt_message(session, msg2, NULL, &enc_msg2, PEP_enc_PGP_MIME);
    assert(status2 == PEP_STATUS_OK);
    assert(enc_msg2);
    cout << "message encrypted.\n";
    
    status2 = mime_encode_message(enc_msg2, false, &text2);
    assert(status2 == PEP_STATUS_OK);
    assert(text2);

    cout << "encrypted:\n\n";
    cout << text2 << "\n";

    message *msg3;
    PEP_STATUS status3 = mime_decode_message(text2, strlen(text2), &msg3);
    assert(status3 == PEP_STATUS_OK);
    string string3 = text2;
    free(text2);

    unlink("msg4.asc");
    ofstream outFile3("msg4.asc");
    outFile3.write(string3.c_str(), string3.size());
    outFile3.close();

    message *msg4;
    stringlist_t *keylist4;
    PEP_color color;
    PEP_decrypt_flags_t flags;
    
    PEP_STATUS status4 = decrypt_message(session, enc_msg2, &msg4, &keylist4, &color, &flags);
    assert(status4 == PEP_STATUS_OK);
    assert(msg4);
    assert(keylist4);
    assert(color);

    cout << "keys used:";
    stringlist_t *kl4;
    for (kl4 = keylist4; kl4 && kl4->value; kl4 = kl4->next)
        cout << " " << kl4->value;
    cout << "\n\n";

    free_stringlist(keylist4);

    cout << "freeing messages…\n";
    free_message(msg4);
    free_message(msg3);
    free_message(msg2);
    free_message(enc_msg2);
    cout << "done.\n";

    cout << "calling release()\n";
    release(session);
    return 0;
}

