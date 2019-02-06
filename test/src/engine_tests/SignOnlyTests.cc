// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cstring>
#include <cpptest.h>
#include <fstream>

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
    ofstream test_file;
    test_file.open("signed_text.txt");
    test_file << msg_text;
    test_file.close();
    char* signed_text = NULL;
    size_t signed_text_size = 0;

    stringlist_t* keylist = NULL;
    
    PEP_STATUS status = sign_only(session, msg_text.c_str(), msg_text.size(), alice_fpr, &signed_text, &signed_text_size);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    cout << signed_text << endl;
    test_file.open("signature.txt");
    test_file << signed_text;
    test_file.close();
        
    status = verify_text(session, msg_text.c_str(), msg_text.size(),
                         signed_text, signed_text_size, &keylist);

#ifndef USE_NETPGP                         
    TEST_ASSERT_MSG(status == PEP_VERIFIED, tl_status_string(status));
#else    
    TEST_ASSERT_MSG(status == PEP_VERIFIED_AND_TRUSTED, tl_status_string(status));
#endif
    TEST_ASSERT(keylist);
    TEST_ASSERT(keylist->value);
    TEST_ASSERT(strcmp(keylist->value, alice_fpr) == 0);
    
    // FIXME: free stuff
    
    TEST_ASSERT(true);
}
