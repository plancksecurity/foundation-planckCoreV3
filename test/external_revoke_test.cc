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
    cout << "\n*** external_revoke_test.cc ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status = init(&session);   
    assert(status == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

#ifndef NETPGP
    char* fprs[2];

    const string fenris_pub_key = slurp("test_keys/pub/pep.test.fenris-0x4F3D2900_pub.asc");
    const string fenris_priv_key = slurp("test_keys/priv/pep.test.fenris-0x4F3D2900_priv.asc");

    assert(fenris_pub_key.length() != 0);
    assert(fenris_priv_key.length() != 0);
    
    PEP_STATUS statuspub = import_key(session, fenris_pub_key.c_str(), fenris_pub_key.length(), NULL);
    PEP_STATUS statuspriv = import_key(session, fenris_priv_key.c_str(), fenris_priv_key.length(), NULL);
    assert(statuspub == PEP_STATUS_OK);
    assert(statuspriv == PEP_STATUS_OK);

    // Create sender ID
    
    pEp_identity * me = new_identity("pep.test.fenris@thisstilldoesntwork.lu", "0969FA229DF21C832A64A04711B1B9804F3D2900", PEP_OWN_USERID, "Fenris Hawke");
    status = myself(session, me);
    
    // Create key
    cout << "Creating new id for : ";
    char *uniqname = strdup("AAAAtestuser@testdomain.org");
    srandom(time(NULL));
    for(int i=0; i < 4;i++)
        uniqname[i] += random() & 0xf;
    
    cout << uniqname << "\n";
    pEp_identity * recip1 = new_identity(uniqname, NULL, NULL, "Test User");

    status = generate_keypair(session, recip1);
    
    cout << "Generated fingerprint ";
    cout << recip1->fpr << "\n";

    fprs[0] = strdup(recip1->fpr);
    
    cout << endl << "*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*" << endl;
    cout << "Trust and revoke single key, ensure trust changes, then generate new key and ensure rating is correct." << endl;
    cout << "*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*" << endl << endl;
    
    cout << endl << "---------------------------------------------------------" << endl;
    cout << "1a. Encrypt message for trusted partner." << endl;
    cout << "---------------------------------------------------------" << endl << endl;

    cout << "Trusting personal key for " << uniqname << endl;
    recip1->me = false;
    // Trust it
    status = update_identity(session, recip1);
    status = trust_personal_key(session, recip1);
    status = update_identity(session, recip1);
    
    // TODO: Check trust?
    cout << "Done! Trusted personal key with fpr " << recip1->fpr << " for " << uniqname << endl;

    const char* r1_userid = (recip1->user_id ? strdup(recip1->user_id) : NULL);

    
    // encrypt something to the key
    cout << "Creating message…\n";
    identity_list* to_list = new_identity_list(identity_dup(recip1)); // to bob
    message* outgoing_msg = new_message(PEP_dir_outgoing);
    assert(outgoing_msg);
    outgoing_msg->from = identity_dup(me);
    outgoing_msg->to = to_list;
    outgoing_msg->shortmsg = strdup("Greetings, humans!");
    outgoing_msg->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "Message created.\n";

    message* encrypted_outgoing_msg = NULL;

    cout << "Encrypting message to " << uniqname << "…\n";    
    status = encrypt_message(session, outgoing_msg, NULL, &encrypted_outgoing_msg, PEP_enc_PGP_MIME, 0);
    cout << "Encrypted message with status " << tl_status_string(status) << endl;
    // check status
    assert(status == PEP_STATUS_OK);
    assert(encrypted_outgoing_msg);

    cout << "Checking message recipient comm_type from message." << endl;
    // check comm_type
    cout << "comm_type: " << tl_ct_string(encrypted_outgoing_msg->to->ident->comm_type) << endl;
    assert(encrypted_outgoing_msg->to->ident->comm_type == PEP_ct_OpenPGP);
    
    status = get_trust(session, recip1);
    
    cout << "Recip's trust DB comm_type = " << hex << tl_ct_string(recip1->comm_type) << endl;
    assert(recip1->comm_type == PEP_ct_OpenPGP); // FIXME: PEP_ct_pEp???

    // decrypt message
    free_message(outgoing_msg);
    outgoing_msg = NULL;

    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;

    cout << endl << "---------------------------------------------------------" << endl;
    cout << "1b. Decrypt message that was encrypted for trusted partner." << endl;
    cout << "---------------------------------------------------------" << endl << endl;

    cout << "Decrypting message." << endl;
    status = decrypt_message(session, encrypted_outgoing_msg, &outgoing_msg, &keylist, &rating, &flags);
    cout << "Decrypted message with status " << tl_status_string(status) << endl;
    assert(status == PEP_STATUS_OK);
    assert(rating == PEP_rating_trusted);

    // check rating
    cout << "Rating of decrypted message to trusted recip: " << tl_rating_string(rating) << endl;
    assert(rating == PEP_rating_trusted); // FIXME: trusted and anonymised?
    
    // check comm_type
    status = get_trust(session, recip1);

    cout << "Recip's trust DB comm_type = " << tl_ct_string(recip1->comm_type) << endl;
    assert(recip1->comm_type == PEP_ct_OpenPGP); // FIXME: PEP_ct_pEp???

    cout << endl << "---------------------------------------------------------" << endl;
    cout << "2a. Revoke key for (currently) trusted partner." << endl;
    cout << "---------------------------------------------------------" << endl << endl;
    // externally revoke key
    // (note - as of 23.5.17, revoke_key() doesn't touch the trust db, just the keyring, so we can do this)

    cout << "Revoking key." << endl;
    status = get_identity(session, uniqname, r1_userid, &recip1);    
    status = revoke_key(session, recip1->fpr, "encrypt_for_identity_test");
    cout << "Status of revocation call for " << recip1->fpr << " is "<< tl_status_string(status) << endl;

    // free messages
    free_message(outgoing_msg);
    free_message(encrypted_outgoing_msg);
    outgoing_msg = NULL;
    encrypted_outgoing_msg = NULL;
    
    // encrypt something to the key
    cout << "creating message…\n";
    to_list = new_identity_list(identity_dup(recip1)); // to bob
    outgoing_msg = new_message(PEP_dir_outgoing);
    assert(outgoing_msg);
    outgoing_msg->from = identity_dup(me);
    outgoing_msg->to = to_list;
    outgoing_msg->shortmsg = strdup("Greetings, humans!");
    outgoing_msg->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "message created.\n";

    encrypted_outgoing_msg = NULL;
    message* decrypted_msg = NULL;

    cout << endl << "---------------------------------------------------------" << endl;
    cout << "2b. Encrypt message for recip whose key has been externally revoked in the keyring, not the app." << endl;
    cout << "---------------------------------------------------------" << endl << endl;

    status = encrypt_message(session, outgoing_msg, NULL, &encrypted_outgoing_msg, PEP_enc_PGP_MIME, 0);
    cout << "Encryption returns with status " << tl_status_string(status) << endl;
    assert (status == PEP_KEY_UNSUITABLE);
    assert (encrypted_outgoing_msg == NULL);
    status = update_identity(session, recip1);
    assert (recip1->comm_type = PEP_ct_key_revoked);

    cout << endl << "---------------------------------------------------------" << endl;
    cout << "2c. Check trust of recip, whose only key has been revoked, once an encryption attempt has been made." << endl;
    cout << "---------------------------------------------------------" << endl << endl;

    assert(recip1->fpr == NULL);
    recip1->fpr = fprs[0];
    status = get_trust(session, recip1);
    recip1->fpr = NULL;

    cout << "Recip's trust DB comm_type = " << hex << tl_ct_string(recip1->comm_type) << endl;
    assert(recip1->comm_type == PEP_ct_key_revoked);

    free_message(decrypted_msg);
    free_message(outgoing_msg);
    outgoing_msg = NULL;
    decrypted_msg = NULL;

    cout << endl << "---------------------------------------------------------" << endl;
    cout << "3a. Generate new key, but don't explicitly trust it." << endl;
    cout << "---------------------------------------------------------" << endl << endl;

    // now: generate new key
    free(recip1->fpr);
    recip1->fpr = NULL;
    status = generate_keypair(session, recip1);
    
    cout << "Generated fingerprint \n";
    cout << recip1->fpr << "\n";
    fprs[1] = strdup(recip1->fpr);

    // try again
    cout << endl << "---------------------------------------------------------" << endl;
    cout << "3b. Try to send something to the email address of our revoked friend, make sure a new key is used to encrypt." << endl;
    cout << "---------------------------------------------------------" << endl << endl;
    
    // encrypt something to the key
    cout << "Creating message…\n";
    
    // cout << "First, update identity though!\n";
    // status = update_identity(session, recip1);
    to_list = new_identity_list(identity_dup(recip1)); // to bob
    outgoing_msg = new_message(PEP_dir_outgoing);
    assert(outgoing_msg);
    outgoing_msg->from = identity_dup(me);
    outgoing_msg->to = to_list;
    outgoing_msg->shortmsg = strdup("Greetings, humans!");
    outgoing_msg->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "Message created.\n";

    status = encrypt_message(session, outgoing_msg, NULL, &encrypted_outgoing_msg, PEP_enc_PGP_MIME, 0);
    PEP_comm_type ct = (encrypted_outgoing_msg ? encrypted_outgoing_msg->to->ident->comm_type : outgoing_msg->to->ident->comm_type);
    

    // CHECK STATUS???
    cout << "Encryption returns with status " << tl_status_string(status) << endl;

    // check comm_type
    cout << "comm_type: " << tl_ct_string(ct) << endl;
    assert(ct == PEP_ct_OpenPGP_unconfirmed);
    
    status = get_trust(session, recip1);

    cout << "Recip's trust DB comm_type (should be unknown, as we're using a keyring-only key, not in DB) = " << hex << tl_ct_string(recip1->comm_type) << endl;
    assert(recip1->comm_type != PEP_ct_OpenPGP_unconfirmed);

    // decrypt message
//    free_message(outgoing_msg);
//    outgoing_msg = NULL;

    cout << endl << "---------------------------------------------------------" << endl;
    cout << "3c. Decrypt... that... message!" << endl;
    cout << "---------------------------------------------------------" << endl << endl;


    status = decrypt_message(session, encrypted_outgoing_msg, &decrypted_msg, &keylist, &rating, &flags);
    cout << "Decryption returns with status " << tl_status_string(status) << endl;
    assert(status == PEP_STATUS_OK);
    assert(decrypted_msg);
    
    // check rating
    cout << "Rating of decrypted message to trusted recip: " << tl_rating_string(rating) << endl;
    assert(rating == PEP_rating_reliable);

    status = update_identity(session, decrypted_msg->to->ident);
    ct = (decrypted_msg ? decrypted_msg->to->ident->comm_type : outgoing_msg->to->ident->comm_type);

    cout << "comm_type: " << tl_ct_string(ct) << endl;
    assert(ct == PEP_ct_OpenPGP_unconfirmed);
    
    status = get_trust(session, recip1);
    
    cout << "Recip's trust DB comm_type (should be unknown - there's nothing in the DB) = " << hex << tl_ct_string(recip1->comm_type) << endl;
    assert(recip1->comm_type == PEP_ct_unknown);

    free_message(encrypted_outgoing_msg);
    free_message(decrypted_msg);
    free_message(outgoing_msg);
    outgoing_msg = NULL;
    decrypted_msg = NULL;
    encrypted_outgoing_msg = NULL;

    free_identity(me);
    free_identity(recip1);
    free(uniqname);
    
    delete_keypair(session, fprs[0]);    
    delete_keypair(session, fprs[1]);
    
    free(fprs[0]);
    free(fprs[1]);
    
#else
    cout << "Sorry, test is not defined for NETPGP at this time." << endl;
    
#endif
    
    release(session);

    return 0;
}
