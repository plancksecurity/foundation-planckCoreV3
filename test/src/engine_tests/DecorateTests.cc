// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-textoutput.h>
#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>
#include <sstream>
#include "mime.h"
#include "message_api.h"
#include "test_util.h"

#include "EngineTestSuite.h"
#include "EngineTestIndividualSuite.h"
#include "DecorateTests.h"

using namespace std;

DecorateTests::DecorateTests(string suitename, string test_home_dir) : 
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {            
    TEST_ADD(DecorateTests::check_decorate);
}

void DecorateTests::check_decorate() {

    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string alice_priv_key = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    const string bob_pub_key = slurp("test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
    PEP_STATUS statuspub = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    PEP_STATUS statuspriv = import_key(session, alice_priv_key.c_str(), alice_priv_key.length(), NULL);
    PEP_STATUS statusbob = import_key(session, bob_pub_key.c_str(), bob_pub_key.length(), NULL);
    TEST_ASSERT(statuspub == PEP_STATUS_OK);
    TEST_ASSERT(statuspriv == PEP_STATUS_OK);
    TEST_ASSERT(statusbob == PEP_STATUS_OK);

    cout << "creating message…\n";
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test");
    alice->me = true;
    identity_list* to_list = new_identity_list(bob); // to bob
    message* outgoing_message = new_message(PEP_dir_outgoing);
    TEST_ASSERT(outgoing_message);
    outgoing_message->from = alice;
    outgoing_message->to = to_list;
    outgoing_message->shortmsg = strdup("Greetings, humans!");
    outgoing_message->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    outgoing_message->longmsg = strdup("This is a dumb message.\nBut it's done.\n");
    TEST_ASSERT(outgoing_message->longmsg);
    cout << "message created.\n";

    char* encoded_text = nullptr;

    message* encrypted_msg = nullptr;
    cout << "calling encrypt_message\n";
    PEP_STATUS status = encrypt_message (session, outgoing_message, NULL, &encrypted_msg, PEP_enc_PGP_MIME, 0);
    cout << "encrypt_message() returns " << tl_status_string(status) << '.' << endl;
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(encrypted_msg);
    cout << "message encrypted.\n";
    
    status = mime_encode_message(encrypted_msg, false, &encoded_text);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(encoded_text);
    
    bool contains_version = false;
    
    const char* version_str = "X-pEp-Version: ";
    size_t version_prefix_len = strlen(version_str);
    
    istringstream f(encoded_text);
    string enc_string;
    while (getline(f, enc_string)) {
        if (strncmp(enc_string.c_str(), version_str, version_prefix_len) == 0)
            contains_version = true;
    }
    TEST_ASSERT(contains_version);
    
    if (contains_version)
        cout << "Version string in encrypted message, as it should be." << endl;    
}
