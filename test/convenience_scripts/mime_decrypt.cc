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
#include "TestUtils.h"

using namespace std;

int main(int argc, char* argv[]) {
    cout << "\n*** MIME encrypt and decrypt testing program ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status = init(&session, NULL, NULL);
    assert(status == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    if (argc < 2) {
        cout << "ERROR: filename required." << endl;
        return -1;
    }
        
    const string mailfile = slurp(argv[1]);
    char* dec_msg = NULL;
    
    stringlist_t* keylist = NULL;
    
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    
    flags = 0;
    char* modified_src = NULL;
    status = MIME_decrypt_message(session, mailfile.c_str(), mailfile.size(), &dec_msg, &keylist, &rating, &flags, &modified_src);

    cout << dec_msg << endl << endl;

    cout << "Rating is " << tl_rating_string(rating) << endl;
    
    release(session);
    return 0;
}
    
