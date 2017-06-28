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
    cout << "\n*** case_and_dot_address_test.cc ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status = init(&session);   
    assert(status == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";
    
    
    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string alice_priv_key = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");

    const char* alice_email_case = "pEp.teST.AlICe@pEP-pRoJeCt.ORG";
    const char* alice_email_dot = "pe.p.te.st.a.l.i.ce@pep-project.org";
    const char* alice_email_dotless = "peptestalice@pep-project.org";
    const char* alice_email_case_and_dot = "PE.p.teS.t.ALICE@pep-project.OrG";

    PEP_STATUS statuspub = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    PEP_STATUS statuspriv = import_key(session, alice_priv_key.c_str(), alice_priv_key.length(), NULL);
    assert(statuspub == PEP_STATUS_OK);
    assert(statuspriv == PEP_STATUS_OK);

    pEp_identity * alice_id = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    status = update_identity(session, alice_id);
    assert(alice_id->fpr);
    assert(strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0);
    free_identity(alice_id);
    alice_id = NULL;

    alice_id = new_identity(alice_email_case, NULL, PEP_OWN_USERID, "Alice Test");
    status = update_identity(session, alice_id);
    assert(alice_id->fpr);
    assert(strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0);
    free_identity(alice_id);
    alice_id = NULL;

    alice_id = new_identity(alice_email_dot, NULL, PEP_OWN_USERID, "Alice Test");
    status = update_identity(session, alice_id);
    assert(alice_id->fpr);
    assert(strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0);
    free_identity(alice_id);
    alice_id = NULL;

    alice_id = new_identity(alice_email_dotless, NULL, PEP_OWN_USERID, "Alice Test");
    status = update_identity(session, alice_id);
    assert(alice_id->fpr);
    assert(strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0);
    free_identity(alice_id);
    alice_id = NULL;

    alice_id = new_identity(alice_email_case_and_dot, NULL, PEP_OWN_USERID, "Alice Test");
    status = update_identity(session, alice_id);
    assert(alice_id->fpr);
    assert(strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0);
    free_identity(alice_id);
    alice_id = NULL;
    
    release(session);

    return 0;
}
