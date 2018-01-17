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
#include "keymanagement.h"
#include "test_util.h"

using namespace std;

int main() {
    cout << "\n*** message_2.0_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    PEP_comm_type carol_comm_type = PEP_ct_OpenPGP_unconfirmed;

    // message_api test code

    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string alice_priv_key = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    const string carol_pub_key = slurp("test_keys/pub/pep-test-carol-0x42A85A42_pub.asc");
    const string carol_priv_key = slurp("test_keys/priv/pep-test-carol-0x42A85A42_priv.asc");

    PEP_STATUS statuspub = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    PEP_STATUS statuspriv = import_key(session, alice_priv_key.c_str(), alice_priv_key.length(), NULL);
    assert(statuspub == PEP_STATUS_OK);
    assert(statuspriv == PEP_STATUS_OK);
    statuspub = import_key(session, carol_pub_key.c_str(), carol_pub_key.length(), NULL);
    statuspriv = import_key(session, carol_priv_key.c_str(), carol_priv_key.length(), NULL);
    assert(statuspub == PEP_STATUS_OK);
    assert(statuspriv == PEP_STATUS_OK);

    cout << "creating message…\n";
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", PEP_OWN_USERID, "Alice Test");
    pEp_identity* carol = new_identity("pep-test-carol@pep-project.org", NULL, "TOFU_pep-test-carol@pep-project.org", "Carol Test");

    PEP_STATUS alice_status = update_identity(session, alice);
    PEP_STATUS carol_status = update_identity(session, carol);

    PEP_STATUS status = update_trust_for_fpr(session, alice->fpr, PEP_ct_pEp);
    status = update_trust_for_fpr(session, carol->fpr, carol_comm_type);
    
    PEP_STATUS mystatus = myself(session, alice);
    assert(mystatus == PEP_STATUS_OK);
    alice_status = update_identity(session, alice);
    alice_status = update_identity(session, carol);
    assert(alice->comm_type == PEP_ct_pEp);
    assert(carol->comm_type == carol_comm_type);
    
    identity_list* to_list = new_identity_list(carol); // to carol
    message* outgoing_message = new_message(PEP_dir_outgoing);
    assert(outgoing_message);
    outgoing_message->from = alice;
    outgoing_message->to = to_list;
    outgoing_message->shortmsg = strdup("Greetings, humans!");
    outgoing_message->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_message->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
//    outgoing_message->id = strdup("blahblahyourmama@pep-project.org");
    outgoing_message->references = new_stringlist("one-839274982347239847@pep-project.org");
    stringlist_add(outgoing_message->references, "two-dfddffd839274982347239847@pep-project.org");
    stringlist_add(outgoing_message->references, "three-OMGWTFBBQ.edfddffd839274982347239847@pep-project.org");
    
    cout << "message created.\n";

    char* encoded_text = nullptr;
    status = mime_encode_message(outgoing_message, false, &encoded_text);
    assert(status == PEP_STATUS_OK);
    assert(encoded_text);

    cout << "unencrypted:\n\n";
    cout << encoded_text << "\n";

    free(encoded_text);

    cout << "encrypting message as MIME multipart…\n";
    message* encrypted_msg = nullptr;
    cout << "calling encrypt_message\n";
    status = encrypt_message(session, outgoing_message, NULL, 
        &encrypted_msg, PEP_enc_PGP_MIME, 0);
    cout << "encrypt_message() returns " << std::hex << status << '.' << endl;
    assert(status == PEP_STATUS_OK);
    assert(encrypted_msg);
    cout << "message encrypted.\n";
    
    encrypted_msg->enc_format = PEP_enc_none;
    status = mime_encode_message(encrypted_msg, false, &encoded_text);
    assert(status == PEP_STATUS_OK);
    assert(encoded_text);
     
    cout << "encrypted:\n\n";
    cout << encoded_text << "\n";
     
    char* decrypted_text;
    
    message* decrypted_msg = nullptr;
    stringlist_t* keylist_used = nullptr;
    
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
     
//    MIME_decrypt_message(session, encoded_text, strlen(encoded_text), &decrypted_text, &keylist_used, &rating, &flags);
    
//    cout << "HEY!" << endl;
//    cout << decrypted_text << endl;
    
    message* decoded_msg = nullptr;
    status = mime_decode_message(encoded_text, strlen(encoded_text), &decoded_msg);
    assert(status == PEP_STATUS_OK);
    const string string3 = encoded_text;
      
    unlink("msg_2.0.asc");
    ofstream outFile3("msg_2.0.asc");
    outFile3.write(string3.c_str(), string3.size());
    outFile3.close();
    
    // message* decrypted_msg = nullptr;
    // stringlist_t* keylist_used = nullptr;
    // 
    // PEP_rating rating;
    // PEP_decrypt_flags_t flags;
    // 
    stringpair_t* autoconsume = new_stringpair("pEp-auto-consume", "yes");
    stringpair_list_add(encrypted_msg->opt_fields, autoconsume);
    status = decrypt_message(session, encrypted_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    assert(decrypted_msg);
    assert(keylist_used);
    assert(rating);
    //assert(status == PEP_STATUS_OK && rating == PEP_rating_reliable);
    //PEP_comm_type ct = encrypted_msg->from->comm_type;
    //assert(ct == PEP_ct_pEp);
    
    cout << "keys used:\n";
    
    for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next)
    {
       cout << "\t " << kl4->value << endl;
    }
     
    decrypted_msg->enc_format = PEP_enc_none; 
    status = _mime_encode_message_internal(decrypted_msg, false, &encoded_text, false);
    assert(status == PEP_STATUS_OK);
    assert(encoded_text);
    cout << "Decrypted message: " << endl;
    cout << encoded_text << endl;
     
    cout << "freeing messages…\n";
    free_message(encrypted_msg);
    free_message(decrypted_msg);
    free_message(outgoing_message);
    cout << "done.\n";
    
    cout << "calling release()\n";
    release(session);
    return 0;
}
