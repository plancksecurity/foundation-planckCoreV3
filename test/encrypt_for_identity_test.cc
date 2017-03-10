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
    cout << "\n*** encrypt_for_identity_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // message_api test code

    cout << "creating message…\n";
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test");
    alice->me = true;
    identity_list* to_list = new_identity_list(bob); // to bob
    message* outgoing_message = new_message(PEP_dir_outgoing);
    assert(outgoing_message);
    outgoing_message->from = alice;
    outgoing_message->to = to_list;
    outgoing_message->shortmsg = strdup("Greetings, humans!");
    outgoing_message->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "message created.\n";

    char* encoded_text = nullptr;
    PEP_STATUS status = mime_encode_message(outgoing_message, false, &encoded_text);
    assert(status == PEP_STATUS_OK);
    assert(encoded_text);

    cout << "decrypted:\n\n";
    cout << encoded_text << "\n";

    free(encoded_text);

    cout << "encrypting message as MIME multipart…\n";
    message* encrypted_msg = nullptr;
    cout << "calling encrypt_message_for_identity()\n";
    status = encrypt_message_for_self(session, alice, outgoing_message, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_default);
    cout << "encrypt_message() returns " << std::hex << status << '.' << endl;
    assert(status == PEP_STATUS_OK);
    assert(encrypted_msg);
    cout << "message encrypted.\n";
    
    status = mime_encode_message(encrypted_msg, false, &encoded_text);
    assert(status == PEP_STATUS_OK);
    assert(encoded_text);

    cout << "encrypted:\n\n";
    cout << encoded_text << "\n";

    message* decoded_msg = nullptr;
    status = mime_decode_message(encoded_text, strlen(encoded_text), &decoded_msg);
    assert(status == PEP_STATUS_OK);
    const string string3 = encoded_text;

    unlink("msg_encrypt_for_self.asc");
    ofstream outFile3("msg_encrypt_for_self.asc");
    outFile3.write(string3.c_str(), string3.size());
    outFile3.close();

    message* decrypted_msg = nullptr;
    stringlist_t* keylist_used = nullptr;

    PEP_rating rating;
    PEP_decrypt_flags_t flags;

    status = decrypt_message(session, encrypted_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    assert(status == PEP_STATUS_OK);
    assert(decrypted_msg);
    assert(keylist_used);
    assert(rating);
    PEP_comm_type ct = encrypted_msg->from->comm_type;
    assert(ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed );

    cout << "keys used:\n";

    for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next)
    {
        cout << "\t " << kl4->value << endl;
        assert(strcasecmp("4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", kl4->value) == 0);
        cout << "Encrypted for Alice! Yay! It worked!" << endl;
    }
    cout << "Encrypted ONLY for Alice! Test passed. Move along. These are not the bugs you are looking for." << endl;
 
    cout << "freeing messages…\n";
    free_message(encrypted_msg);
    free_message(decrypted_msg);
    free_message(outgoing_message);
    cout << "done.\n";

    cout << "calling release()\n";
    release(session);
    return 0;
}
