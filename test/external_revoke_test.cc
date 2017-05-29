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

using namespace std;

int main() {
    cout << "\n*** external_revoke_test.cc ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status = init(&session);   
    assert(status == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

#ifndef NETPGP

    // Create sender ID
    
    pEp_identity * me = new_identity("pep.test.apple@pep-project.org", NULL, PEP_OWN_USERID, "Alice Cooper");
    status = update_identity(session, me);
    status = trust_personal_key(session, me);
    status = update_identity(session, me);
    
    // Create key

    cout << "creating new id for : ";
    char *uniqname = strdup("AAAAtestuser@testdomain.org");
    srandom(time(NULL));
    for(int i=0; i < 4;i++)
        uniqname[i] += random() & 0xf;
    
    cout << uniqname << "\n";
    pEp_identity * recip1 = new_identity(uniqname, NULL, NULL, "Test User");

    status = generate_keypair(session, recip1);
    
    cout << "generated fingerprint \n";
    cout << recip1->fpr << "\n";

    // Trust it
    recip1->me = false;
    status = update_identity(session, recip1);
    status = trust_personal_key(session, recip1);
    status = update_identity(session, recip1);

    const char* r1_userid = (recip1->user_id ? strdup(recip1->user_id) : NULL);

    // encrypt something to the key
    cout << "creating message…\n";
    identity_list* to_list = new_identity_list(identity_dup(recip1)); // to bob
    message* outgoing_message = new_message(PEP_dir_outgoing);
    assert(outgoing_message);
    outgoing_message->from = identity_dup(me);
    outgoing_message->to = to_list;
    outgoing_message->shortmsg = strdup("Greetings, humans!");
    outgoing_message->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_message->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "message created.\n";

    message* encrypted_outgoing_msg = NULL;
    
    status = encrypt_message(session, outgoing_message, NULL, &encrypted_outgoing_msg, PEP_enc_PGP_MIME, 0);
    
    // check status
    assert(status == PEP_STATUS_OK);
    assert(encrypted_outgoing_msg);

    // check comm_type
    cout << "comm_type: " << encrypted_outgoing_msg->to->ident->comm_type << endl;

    assert(encrypted_outgoing_msg->to->ident->comm_type == PEP_ct_OpenPGP);
    status = get_trust(session, recip1);
    
    cout << "Recip's trust DB comm_type = " << hex << recip1->comm_type << endl;
    assert(recip1->comm_type == PEP_ct_OpenPGP);

    // decrypt message
    free_message(outgoing_message);
    outgoing_message = NULL;

    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;

    status = decrypt_message(session, encrypted_outgoing_msg, &outgoing_message, &keylist, &rating, &flags);
    assert(status == PEP_STATUS_OK);
    assert(rating >= PEP_rating_trusted);

    // check rating
    cout << "Rating of decrypted message to trusted recip: " << rating << endl;

    // check comm_type
    status = get_trust(session, recip1);
    
    cout << "Recip's trust DB comm_type = " << recip1->comm_type << endl;

    // externally revoke key
    // (note - as of 23.5.17, revoke_key() doesn't touch the trust db, just the keyring, so we can do this)

    status = get_identity(session, uniqname, r1_userid, &recip1);
    
    status = revoke_key(session, recip1->fpr, "encrypt_for_identity_test");

    
    // free messages
    free_message(outgoing_message);
    free_message(encrypted_outgoing_msg);
    outgoing_message = NULL;
    encrypted_outgoing_msg = NULL;
    
    // encrypt something to the key
    cout << "creating message…\n";
    to_list = new_identity_list(identity_dup(recip1)); // to bob
    outgoing_message = new_message(PEP_dir_outgoing);
    assert(outgoing_message);
    outgoing_message->from = identity_dup(me);
    outgoing_message->to = to_list;
    outgoing_message->shortmsg = strdup("Greetings, humans!");
    outgoing_message->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_message->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "message created.\n";

    encrypted_outgoing_msg = NULL;
    message* decrypted_msg = NULL;

    status = encrypt_message(session, outgoing_message, NULL, &encrypted_outgoing_msg, PEP_enc_PGP_MIME, 0);

    // check comm_type
    if (encrypted_outgoing_msg)
        cout << "comm_type: " << encrypted_outgoing_msg->to->ident->comm_type << endl;
    else
        cout << "comm_type: " << outgoing_message->to->ident->comm_type << endl;
        
    status = get_trust(session, recip1);

    cout << "Recip's trust DB comm_type = " << hex << recip1->comm_type << endl;

    // decrypt message
//    free_message(outgoing_message);
//    outgoing_message = NULL;

    status = decrypt_message(session, outgoing_message, &decrypted_msg, &keylist, &rating, &flags);

    // check rating
    cout << "Rating of decrypted message to trusted recip: " << rating << endl;

    // check comm_type
    if (decrypted_msg)
        cout << "comm_type: " << decrypted_msg->to->ident->comm_type << endl;
    else
        cout << "comm_type: " << outgoing_message->to->ident->comm_type << endl;
    
    status = get_trust(session, recip1);
    
    cout << "Recip's trust DB comm_type = " << hex << recip1->comm_type << endl;

    // generate new key
    status = generate_keypair(session, recip1);
    
    cout << "generated fingerprint \n";
    cout << recip1->fpr << "\n";

    // PART DEUX
    
    // Create key

    // DO NOT trust it

    // encrypt something to the key

    // check rating

    // check comm_type

    // externally revoke key
    
    // encrypt something to the key

    // check rating

    // check comm_type


    // PART TROIS
    
    // Create key

    // DO NOT trust it

    // encrypt something to the key

    // check rating

    // check comm_type

    // externally revoke key
    
    // encrypt something to the key

    // check rating

    // check comm_type
    
    free(uniqname);
#else
    cout << "Sorry, test is not defined for NETPGP at this time." << endl;
    
#endif
    
    release(session);

    return 0;
}
