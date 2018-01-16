// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <iostream>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()
#include <assert.h>
#include "blacklist.h"
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"
#include "test_util.h"

using namespace std;

int main() {
    cout << "\n*** encrypt_missing_private_key_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";
    
    pEp_identity* no_key_identity = new_identity("blacklistself@kgrothoff.org",
                                                      NULL,
                                                      PEP_OWN_USERID,
                                                      "Blacklist Self");
    no_key_identity->me = true;
    PEP_STATUS status8 = myself(session, no_key_identity);
    assert (status8 == PEP_STATUS_OK);

    /* Now let's try to encrypt a message. */
        
    message* tmp_msg = NULL;
    message* enc_msg = NULL;
    
    const string mailtext = slurp("test_mails/blacklist_no_key.eml");

    PEP_STATUS status = mime_decode_message(mailtext.c_str(), mailtext.length(), &tmp_msg);
    assert(status == PEP_STATUS_OK);
    
    status = update_identity(session, tmp_msg->from);
    identity_list* to_list = tmp_msg->to;

    while (to_list) {
        if (to_list->ident)
            update_identity(session, to_list->ident);
        to_list = to_list->next;
    }
    
    // This isn't incoming, though... so we need to reverse the direction
    tmp_msg->dir = PEP_dir_outgoing;
    status = encrypt_message(session,
                             tmp_msg,
                             NULL,
                             &enc_msg,
                             PEP_enc_PGP_MIME,
                             0);
    assert(status == PEP_STATUS_OK);
    

    char* new_key = enc_msg->from->fpr;
    cout << "Encrypted with key " << new_key << endl;
    
    status = delete_keypair(session, new_key);
    PEP_STATUS status14 = myself(session, no_key_identity);

    free_message(tmp_msg);    
    free_message(enc_msg);
    
    cout << "calling release()\n";
    release(session);
    return 0;
}
