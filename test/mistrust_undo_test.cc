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
    cout << "\n*** mistrust_undo_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status = init(&session);   
    assert(status == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    cout << "importing key 0x39E5DAB5." << endl;
    const string pub_key = slurp("test_keys/pub/mistrust.undo.test-0x39E5DAB5_pub.asc");

    assert(pub_key.length() != 0);
    
    PEP_STATUS statuspub = import_key(session, pub_key.c_str(), pub_key.length(), NULL);
    assert(statuspub == PEP_STATUS_OK);
    cout << "Key imported." << endl << endl;
    
    cout << "Setting up identity for mistrust.undo.test@pep-project.org and making comm_type PEP_ct_pEp."  << endl;
    pEp_identity* recip1 = new_identity("mistrust.undo.test@pep-project.org", NULL, "TOFU_mistrust.undo.test@pep-project.org", "Mistrust Undo");
    status = update_identity(session,recip1);
    assert(status == PEP_STATUS_OK);
    assert(strcmp(recip1->fpr, "BACC7A60A88A39A25D99B4A545D7542F39E5DAB5") == 0);
    
    // First, we need the fpr to be in the DB system.
    status = set_identity(session,recip1);
    // Then we update the trust.
    // This is not an external function. We use it to expedite the test since we don't do a sync exchange here.
    status = update_trust_for_fpr(session, recip1->fpr, PEP_ct_pEp);
    // Then we retrieve the new trust.
    status = update_identity(session,recip1);
    assert(status == PEP_STATUS_OK);
    assert(recip1->comm_type == PEP_ct_pEp);
    assert(strcmp(recip1->fpr, "BACC7A60A88A39A25D99B4A545D7542F39E5DAB5") == 0);
    cout << "mistrust.undo.test@pep-project.org set up and comm_type is PEP_ct_pEp."  << endl << endl;

    // Ok, mistrust away
    cout << "Mistrusting mistrust.undo.test@pep-project.org (BACC7A60A88A39A25D99B4A545D7542F39E5DAB5)."  << endl;   
    status = key_mistrusted(session, recip1);
    assert(status == PEP_STATUS_OK);
    status = update_identity(session,recip1);
    assert(status == PEP_STATUS_OK);
    assert(recip1->comm_type == PEP_ct_mistrusted);
    cout << "Mistrusted mistrust.undo.test@pep-project.org (BACC7A60A88A39A25D99B4A545D7542F39E5DAB5) and comm_type set to PEP_ct_mistrusted)." << endl  << endl;    
    
    cout << "Undo mistrust (restore identity and trust in DB)" << endl;
    // Undo it
    status = undo_last_mistrust(session);
    assert(status == PEP_STATUS_OK);
    status = update_identity(session, recip1);
    assert(recip1->comm_type == PEP_ct_pEp);
    assert(strcmp(recip1->fpr, "BACC7A60A88A39A25D99B4A545D7542F39E5DAB5") == 0);
    cout << "Undo mistrust (restore identity and trust in DB) - trust is now PEP_ct_pEp." << endl << endl;

    cout << "Success!!!" << endl << endl;
    
    free_identity(recip1);
    release(session);

    return 0;
}
