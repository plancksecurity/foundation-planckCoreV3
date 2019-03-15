// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include "mime.h"
#include "message_api.h"
#include "test_util.h"
#include "TestConstants.h"

#include "EngineTestSuite.h"
#include "EngineTestSessionSuite.h"
#include "CaseAndDotAddressTests.h"

using namespace std;

CaseAndDotAddressTests::CaseAndDotAddressTests(string suitename, string test_home_dir) : 
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {            
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("CaseAndDotAddressTests::check_case_and_dot_address"),
                                                                      static_cast<Func>(&CaseAndDotAddressTests::check_case_and_dot_address)));
}

void CaseAndDotAddressTests::check_case_and_dot_address() {
    cout << "\n*** case_and_dot_address_test.cc ***\n\n";
    
    char* user_id = get_new_uuid();
    
    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");

    const char* alice_email_case = "pEp.teST.AlICe@pEP-pRoJeCt.ORG";
    const char* alice_email_dot = "pe.p.te.st.a.l.i.ce@pep-project.org";
    const char* alice_email_dotless = "peptestalice@pep-project.org";
    const char* alice_email_case_and_dot = "PE.p.teS.t.ALICE@pep-project.OrG";

    PEP_STATUS statuspub = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    TEST_ASSERT_MSG((statuspub == PEP_TEST_KEY_IMPORT_SUCCESS), "statuspub == PEP_STATUS_OK");

    pEp_identity * alice_id = new_identity("pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", user_id, "Alice Test");

    PEP_STATUS status = trust_personal_key(session, alice_id);

    pEp_identity * new_alice_id = new_identity("pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", user_id, "Alice Test");
    status = update_identity(session, new_alice_id);
    TEST_ASSERT_MSG((new_alice_id->fpr), "new_alice_id->fpr");
    TEST_ASSERT_MSG((strcmp(new_alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0), "strcmp(new_alice_id->fpr, \"4ABE3AAF59AC32CFE4F86500A9411D176FF00E97\") == 0");
    free_identity(new_alice_id);
    free_identity(alice_id);
    alice_id = NULL;
    new_alice_id = NULL;

    alice_id = new_identity(alice_email_case, NULL, user_id, "Alice Test");
    status = update_identity(session, alice_id);
    TEST_ASSERT_MSG((alice_id->fpr), "alice_id->fpr");
    cout << "Alice email: " << alice_email_case << " Alice fpr (should be 4ABE3AAF59AC32CFE4F86500A9411D176FF00E97): " << alice_id->fpr << endl;
    TEST_ASSERT_MSG((strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0), "strcmp(alice_id->fpr, \"4ABE3AAF59AC32CFE4F86500A9411D176FF00E97\") == 0");
    free_identity(alice_id);
    alice_id = NULL;

    alice_id = new_identity(alice_email_dot, NULL, user_id, "Alice Test");
    status = update_identity(session, alice_id);
    TEST_ASSERT_MSG((alice_id->fpr), "alice_id->fpr");
    cout << "Alice email: " << alice_email_dot << " Alice fpr (should be 4ABE3AAF59AC32CFE4F86500A9411D176FF00E97): " << alice_id->fpr << endl;
    TEST_ASSERT_MSG((strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0), "strcmp(alice_id->fpr, \"4ABE3AAF59AC32CFE4F86500A9411D176FF00E97\") == 0");
    free_identity(alice_id);
    alice_id = NULL;

    alice_id = new_identity(alice_email_dotless, NULL, user_id, "Alice Test");
    status = update_identity(session, alice_id);
    TEST_ASSERT_MSG((alice_id->fpr), "alice_id->fpr");
    cout << "Alice email: " << alice_email_dotless << " Alice fpr (should be 4ABE3AAF59AC32CFE4F86500A9411D176FF00E97): " << alice_id->fpr << endl;
    TEST_ASSERT_MSG((strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0), "strcmp(alice_id->fpr, \"4ABE3AAF59AC32CFE4F86500A9411D176FF00E97\") == 0");
    free_identity(alice_id);
    alice_id = NULL;

    alice_id = new_identity(alice_email_case_and_dot, NULL, user_id, "Alice Test");
    status = update_identity(session, alice_id);
    TEST_ASSERT_MSG((alice_id->fpr), "alice_id->fpr");
    cout << "Alice email: " << alice_email_case_and_dot << " Alice fpr (should be 4ABE3AAF59AC32CFE4F86500A9411D176FF00E97): " << alice_id->fpr << endl;
    TEST_ASSERT_MSG((strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0), "strcmp(alice_id->fpr, \"4ABE3AAF59AC32CFE4F86500A9411D176FF00E97\") == 0");
    free_identity(alice_id);
    alice_id = NULL;
}
