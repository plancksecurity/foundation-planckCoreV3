// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <time.h>
#include <iostream>
#include <fstream>

#include "pEpEngine.h"
#include "platform.h"
#include "mime.h"
#include "message_api.h"
#include "test_util.h"

#include <cpptest.h>
#include "EngineTestSessionSuite.h"
#include "MistrustUndoTests.h"

using namespace std;

MistrustUndoTests::MistrustUndoTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("MistrustUndoTests::check_mistrust_undo"),
                                                                      static_cast<Func>(&MistrustUndoTests::check_mistrust_undo)));
}

void MistrustUndoTests::check_mistrust_undo() {
    PEP_STATUS status = PEP_STATUS_OK;

    cout << "importing key 0x39E5DAB5." << endl;
    const string pub_key = slurp("test_keys/pub/mistrust.undo.test-0x39E5DAB5_pub.asc");

    TEST_ASSERT(pub_key.length() != 0);
    
    PEP_STATUS statuspub = import_key(session, pub_key.c_str(), pub_key.length(), NULL);
    TEST_ASSERT(statuspub == PEP_STATUS_OK);
    cout << "Key imported." << endl << endl;
    
    cout << "Setting up identity for mistrust.undo.test@pep-project.org and making comm_type PEP_ct_pEp."  << endl;
    pEp_identity* recip1 = new_identity("mistrust.undo.test@pep-project.org", NULL, "TOFU_mistrust.undo.test@pep-project.org", "Mistrust Undo");
    status = update_identity(session,recip1);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(strcmp(recip1->fpr, "BACC7A60A88A39A25D99B4A545D7542F39E5DAB5") == 0);
    
    // First, we need the fpr to be in the DB system.
    status = set_identity(session,recip1);
    // Then we update the trust.
    // This is not an external function. We use it to expedite the test since we don't do a sync exchange here.
    status = update_trust_for_fpr(session, recip1->fpr, PEP_ct_pEp);
    // Then we retrieve the new trust.
    status = update_identity(session,recip1);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(recip1->comm_type == PEP_ct_pEp);
    TEST_ASSERT(strcmp(recip1->fpr, "BACC7A60A88A39A25D99B4A545D7542F39E5DAB5") == 0);
    cout << "mistrust.undo.test@pep-project.org set up and comm_type is PEP_ct_pEp."  << endl << endl;

    // Ok, mistrust away
    cout << "Mistrusting mistrust.undo.test@pep-project.org (BACC7A60A88A39A25D99B4A545D7542F39E5DAB5)."  << endl;   
    status = key_mistrusted(session, recip1);
    TEST_ASSERT(status == PEP_STATUS_OK);
    status = update_identity(session,recip1);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(recip1->comm_type == PEP_ct_key_not_found);
    recip1->fpr = strdup("BACC7A60A88A39A25D99B4A545D7542F39E5DAB5");
    status = get_trust(session, recip1);
    TEST_ASSERT(recip1->comm_type == PEP_ct_mistrusted);
     
    cout << "Mistrusted mistrust.undo.test@pep-project.org (BACC7A60A88A39A25D99B4A545D7542F39E5DAB5) and comm_type IN DB set to PEP_ct_mistrusted)." << endl  << endl;    
    
    cout << "Undo mistrust (restore identity and trust in DB)" << endl;
    // Undo it
    status = undo_last_mistrust(session);
    TEST_ASSERT(status == PEP_STATUS_OK);
    status = update_identity(session, recip1);
    TEST_ASSERT(recip1->comm_type == PEP_ct_pEp);
    TEST_ASSERT(strcmp(recip1->fpr, "BACC7A60A88A39A25D99B4A545D7542F39E5DAB5") == 0);
    cout << "Undo mistrust (restore identity and trust in DB) - trust is now PEP_ct_pEp." << endl << endl;

    cout << "Success!!!" << endl << endl;
    
    free_identity(recip1);
}
