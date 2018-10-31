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

int main(int argc, char* argv[]) {
    cout << "\n*** MIME encrypt and decrypt testing program ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status = init(&session);
    assert(status == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    if (argc < 2) {
        cout << "ERROR: filename required." << endl;
        return -1;
    }
        
    const string mailfile = slurp(argv[1]);
    char* enc_msg = NULL;
    
    status = MIME_encrypt_message(session, mailfile.c_str(), mailfile.size(), NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    
    cout << enc_msg << endl << endl;

    release(session);
    return 0;
}
    
