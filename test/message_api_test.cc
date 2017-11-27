// This file is under GNU General Public License 3.0
// see LICENSE.txt

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
    pEp_identity * me2 = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    // pEp_identity * me2 = new_identity("test@nokey.plop", NULL, PEP_OWN_USERID, "Test no key");
    me2->me = true;
    identity_list *to2 = new_identity_list(new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test"));
    // identity_list *to2 = new_identity_list(new_identity("still@nokey.blup", NULL, "42", "Still no key"));
    message *msg2 = new_message(PEP_dir_outgoing);
    assert(msg2);
    msg2->from = me2;
    msg2->to = to2;
    msg2->shortmsg = strdup("hello, world");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "message created.\n";

    char *text2 = nullptr;
    PEP_STATUS status2 = mime_encode_message(msg2, false, &text2);
    assert(status2 == PEP_STATUS_OK);
    assert(text2);

    cout << "decrypted:\n\n";
    cout << text2 << "\n";

    free(text2);

    cout << "encrypting message as MIME multipart…\n";
    message *enc_msg2 = nullptr;
    cout << "calling encrypt_message()\n";
    status2 = encrypt_message(session, msg2, NULL, &enc_msg2, PEP_enc_PGP_MIME, 0);
    cout << "encrypt_message() returns " << status2 << '.' << endl;
    assert(status2 == PEP_STATUS_OK);
    assert(enc_msg2);
    cout << "message encrypted.\n";
    
    status2 = mime_encode_message(enc_msg2, false, &text2);
    assert(status2 == PEP_STATUS_OK);
    assert(text2);

    cout << "encrypted:\n\n";
    cout << text2 << "\n";

    message *msg3 = nullptr;
    PEP_STATUS status3 = mime_decode_message(text2, strlen(text2), &msg3);
    assert(status3 == PEP_STATUS_OK);
    const string string3 = text2;
    //free(text2);

    unlink("msg4.asc");
    ofstream outFile3("msg4.asc");
    outFile3.write(string3.c_str(), string3.size());
    outFile3.close();

    message *msg4 = nullptr;
    stringlist_t *keylist4 = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    
    PEP_STATUS status4 = decrypt_message(session, enc_msg2, &msg4, &keylist4, &rating, &flags);
    assert(status4 == PEP_STATUS_OK);
    assert(msg4);
    assert(keylist4);
    assert(rating);
    PEP_comm_type ct = enc_msg2->from->comm_type;
    assert(ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed );

    free_stringpair_list(enc_msg2->opt_fields);
    enc_msg2->opt_fields = NULL;

    cout << "keys used:";

    for (stringlist_t* kl4 = keylist4; kl4 && kl4->value; kl4 = kl4->next)
    {
        cout << " " << kl4->value;
    }
    cout << "\n\n";

    free_stringlist(keylist4);

    cout << "opening msg_no_key.asc for reading\n";
    ifstream inFile3 ("msg_no_key.asc");
    assert(inFile3.is_open());

    string text3;

    cout << "reading msg_no_key.asc sample\n";
    while (!inFile3.eof()) {
        static string line;
        getline(inFile3, line);
        text3 += line + "\r\n";
    }
    inFile3.close();

    message *msg5 = nullptr;
    PEP_STATUS status5 = mime_decode_message(text3.c_str(), text3.length(), &msg5);
    assert(status5 == PEP_STATUS_OK);

    message *msg6 = nullptr;
    stringlist_t *keylist5 = nullptr;
    PEP_rating rating2;
    PEP_decrypt_flags_t flags2;
    PEP_STATUS status6 = decrypt_message(session, msg5, &msg6, &keylist5, &rating2, &flags2);
    assert(status6 == PEP_DECRYPT_NO_KEY);
    assert(msg6 == NULL);
    assert(keylist5 == NULL);
    assert(rating2 == PEP_rating_have_no_key);
    cout << "rating :" << rating2 << "\n";
    free_stringlist(keylist5);

    cout << "\nTesting MIME_encrypt_message / MIME_decrypt_message...\n\n";

    cout << "opening alice_bob_encrypt_test_plaintext_mime.eml for reading\n";
    ifstream inFile4 ("test_mails/alice_bob_encrypt_test_plaintext_mime.eml");
    assert(inFile4.is_open());
    
    string text4;
    
    cout << "reading alice_bob_encrypt_test_plaintext_mime.eml sample\n";
    while (!inFile4.eof()) {
        static string line;
        getline(inFile4, line);
        text4 += line + "\r\n";
    }
    inFile4.close();
    
    const char* out_msg_plain = text4.c_str();
    
//    const char* out_msg_plain = "From: krista@kgrothoff.org\nTo: Volker <vb@pep-project.org>\nSubject: Test\nContent-Type: text/plain; charset=utf-8\nContent-Language: en-US\nContent-Transfer-Encoding:quoted-printable\n\ngaga\n\n";
    char* enc_msg = NULL;
    char* dec_msg = NULL;

    PEP_STATUS status7 = MIME_encrypt_message(session, text4.c_str(), text4.length(), NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
//    PEP_STATUS status7 = MIME_encrypt_message(session, out_msg_plain, strlen(out_msg_plain), NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    assert(status7 == PEP_STATUS_OK);
    
    cout << enc_msg << endl;

    string text5 = enc_msg;
    
    PEP_decrypt_flags_t dec_flags;
    stringlist_t* keys_used;
    
    PEP_STATUS status8 = MIME_decrypt_message(session, text5.c_str(), text5.length(), &dec_msg, &keys_used, &rating, &dec_flags);
    assert(status8 == PEP_STATUS_OK);
    
    cout << dec_msg << endl;
    
    
    cout << "freeing messages…\n";
    free_message(msg4);
    free_message(msg3);
    free_message(msg2);
    free_message(enc_msg2);
    free_message(msg6);
    free_message(msg5);
    cout << "done.\n";

    free(enc_msg);
    free(dec_msg);
    cout << "calling release()\n";
    release(session);
    return 0;
}
