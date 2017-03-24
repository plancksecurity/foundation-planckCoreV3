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
    cout << "\n*** sign_verify_blob_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // message_api test code

    cout << "creating message…\n";
    pEp_identity * me2 = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    me2->me = true;
    identity_list *to2 = new_identity_list(new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test"));
    message *msg2 = new_message(PEP_dir_outgoing);
    assert(msg2);
    msg2->from = me2;
    msg2->to = to2;
    msg2->shortmsg = strdup("Sample Beacon Message");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "message created.\n";
 
    const size_t BUFFERSIZE = 1024;
    char buffer[BUFFERSIZE];
    
    std::ifstream fin("test_data/random_blob.pEp", ios::in | ios::binary );
    fin.read(buffer, BUFFERSIZE);  

    size_t blob_size = fin.gcount(); 
    assert(blob_size == 999); 

    PEP_STATUS status1_5 = prepare_beacon_message(session, buffer, blob_size, msg2); 
    assert(status1_5 == PEP_STATUS_OK);

    cout << "*** beacon blob signed and attached to message:" << endl;
      
    char *text2 = nullptr;
    PEP_STATUS status2 = mime_encode_message(msg2, false, &text2);
    assert(status2 == PEP_STATUS_OK);
    assert(text2);

    cout << "encoded:\n\n";
    cout << text2 << "\n";

    message *msg3 = nullptr;
    PEP_STATUS status3 = mime_decode_message(text2, strlen(text2), &msg3);
    assert(status3 == PEP_STATUS_OK);

    char* signing_fpr = NULL;
    PEP_STATUS status4 = verify_beacon_message(session, msg3, &signing_fpr);
    assert(status4 == PEP_VERIFIED || status4 == PEP_VERIFIED_AND_TRUSTED);

    cout << "*** beacon blob in encoded message extracted and verified!!!!:" << endl;
    assert(strcmp("4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", signing_fpr) == 0);

    cout << "*** Beacon signed by " << signing_fpr << ", as expected. SUCCESS!!!!" << endl;    

    cout << "calling release()\n";
    release(session);

    cout << "\n*** PASSED: sign_verify_blob_test ***\n\n";
    return 0;
}
