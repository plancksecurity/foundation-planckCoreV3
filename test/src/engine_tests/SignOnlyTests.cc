// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <cpptest.h>

#include "pEpEngine.h"

#include "test_util.h"
#include "EngineTestIndividualSuite.h"
#include "SignOnlyTests.h"

using namespace std;

SignOnlyTests::SignOnlyTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SignOnlyTests::check_sign_only"),
                                                                      static_cast<Func>(&SignOnlyTests::check_sign_only)));
}

void SignOnlyTests::check_sign_only() {
    slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");    
    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    string msg_text = "Grrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr! I mean, yo. Greetings to Meesti.\n - Alice";
    char* signed_text = NULL;
    size_t signed_text_size = 0;

    stringlist_t* keylist = NULL;
    
    PEP_STATUS status = sign_only(session, msg_text.c_str(), msg_text.size(), alice_fpr, &signed_text, &signed_text_size);
    TEST_ASSERT(status == PEP_STATUS_OK);
    cout << signed_text << endl;
        
    status = verify_text(session, msg_text.c_str(), msg_text.size(),
                         signed_text, signed_text_size, &keylist);
    TEST_ASSERT(status == PEP_VERIFIED);
    TEST_ASSERT(keylist);
    TEST_ASSERT(keylist->value);
    TEST_ASSERT(strcmp(keylist->value, alice_fpr) == 0);
    
    // FIXME: free stuff
    
    TEST_ASSERT(true);
}
