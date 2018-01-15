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
    cout << "\n*** revoke_regen_attach_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status = init(&session);   
    assert(status == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    cout << "creating own id for : ";
    char *uniqname = strdup("AAAAtestuser@testdomain.org");
    srandom(time(NULL));
    for(int i=0; i < 4;i++)
        uniqname[i] += random() & 0xf;
    
    cout << uniqname << "\n";
    pEp_identity * me = new_identity(uniqname, NULL, PEP_OWN_USERID, "Test User");
    free(uniqname);
    myself(session, me);

    cout << "generated fingerprint \n";
    cout << me->fpr << "\n";

    const char *prev_fpr = strdup(me->fpr);
    
    cout << "revoke \n";
    
    key_mistrusted(session, me);

    cout << "re-generated fingerprint \n";
    cout << me->fpr << "\n";
    
    assert(strcmp(me->fpr, prev_fpr));
    cout << "New fpr is: " << me->fpr;
    
    me->fpr = NULL;
    me->comm_type = PEP_ct_unknown;
    myself(session, me);
    
    identity_list *to = new_identity_list(new_identity("pep.test.alice@pep-project.org", NULL, "42", "pEp Test Alice (test key don't use)"));
    message *msg = new_message(PEP_dir_outgoing);
    assert(msg);
    msg->from = me;
    msg->to = to;
    msg->shortmsg = strdup("hello, world");
    cout << "message created.\n";

    cout << "encrypting message as MIME multipart…\n";
    message *enc_msg;
    cout << "calling encrypt_message()\n";
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    assert(status == PEP_STATUS_OK);
    assert(enc_msg);
    cout << "message encrypted.\n";

    // cout << msg->attachments->filename;
    // int bl_len = bloblist_length(msg->attachments);
    // cout << "Message contains " << bloblist_length(msg->attachments) << " attachments." << endl;
    // assert(bloblist_length(msg->attachments) == 2);
    // assert(strcmp(msg->attachments->filename, "file://pEpkey.asc") == 0);
    // assert(strcmp(msg->attachments->next->filename, "file://pEpkey.asc") == 0);
    // 
    // cout << "message contains 2 key attachments.\n";

    free_message(msg);
    free_message(enc_msg);
   
    // TODO: check that revoked key isn't sent after some time.

    release(session);

    return 0;
}
