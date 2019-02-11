// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cstring>
#include <cpptest.h>

#include "pEpEngine.h"

#include "TestUtils.h"
#include "EngineTestIndividualSuite.h"
#include "Engine358Tests.h"

using namespace std;

Engine358Tests::Engine358Tests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Engine358Tests::check_engine358"),
                                                                      static_cast<Func>(&Engine358Tests::check_engine358)));
}

void Engine358Tests::check_engine358() {
    bool ok = false;
    ok = slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    TEST_ASSERT(ok);    
    ok = slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");    
    TEST_ASSERT(ok);
    ok = slurp_and_import_key(session, "test_keys/pub/inquisitor-0xA4728718_full_expired.pub.asc");    
    TEST_ASSERT(ok);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    pEp_identity* alice_from = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Cooper");

    PEP_STATUS status = set_own_key(session, alice_from, alice_fpr); 
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));

    pEp_identity* expired_inquisitor = new_identity("inquisitor@darthmama.org", NULL, NULL, "Lady Claire Trevelyan");
    message* msg = new_message(PEP_dir_outgoing);    

    msg->from = alice_from;
    msg->to = new_identity_list(expired_inquisitor);
    msg->shortmsg = strdup("Blah!");
    msg->longmsg = strdup("Blahblahblah!");
    msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    message* enc_msg = NULL;
    
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    TEST_ASSERT(!enc_msg);
    TEST_ASSERT(msg->to && msg->to->ident);
    TEST_ASSERT_MSG((status == PEP_UNENCRYPTED), tl_status_string(status));
}

