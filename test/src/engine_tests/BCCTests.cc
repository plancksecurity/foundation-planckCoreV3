// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <assert.h>

#include "pEpEngine.h"
#include "message_api.h"

#include <cpptest.h>
#include "test_util.h"
#include "EngineTestIndividualSuite.h"
#include "BCCTests.h"

using namespace std;

BCCTests::BCCTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("BCCTests::check_single_BCC"),
                                                                      static_cast<Func>(&BCCTests::check_single_BCC)));
}

void BCCTests::setup() {
    EngineTestIndividualSuite::setup();
    string keystr = slurp("test_keys/priv/bcc_test_dude_0-0x1CCCFC41_priv.asc");
    PEP_STATUS status = import_key(session, keystr.c_str(), keystr.size(), NULL);
    assert(status == PEP_STATUS_OK);    
    pEp_identity * me = new_identity("bcc_test_dude_0@darthmama.cool", "0AE9AA3E320595CF93296BDFA155AC491CCCFC41", PEP_OWN_USERID, "BCC Test Sender");    
    status = set_own_key(session, me, "0AE9AA3E320595CF93296BDFA155AC491CCCFC41");
    keystr = slurp("test_keys/pub/bcc_test_dude_0-0x1CCCFC41_pub.asc");
    status = import_key(session, keystr.c_str(), keystr.size(), NULL);
    assert(status == PEP_STATUS_OK);
    keystr = slurp("test_keys/pub/bcc_test_dude_1-0xDAC746BE_pub.asc");
    status = import_key(session, keystr.c_str(), keystr.size(), NULL);
    assert(status == PEP_STATUS_OK);
    keystr = slurp("test_keys/pub/bcc_test_dude_2-0x53CECCF7_pub.asc");
    status = import_key(session, keystr.c_str(), keystr.size(), NULL);
    assert(status == PEP_STATUS_OK);    
}

void BCCTests::check_single_BCC() {
    PEP_STATUS status = PEP_UNKNOWN_ERROR;
    
    // 0AE9AA3E320595CF93296BDFA155AC491CCCFC41
    // D0AF2F9695E186A8DC058B935FE2793DDAC746BE
    // B36E468E7A381946FCDBDDFA84B1F3E853CECCF7
    pEp_identity* sender = new_identity("bcc_test_dude_0@darthmama.cool", NULL, PEP_OWN_USERID, "BCC Test Sender");
    pEp_identity* open_recip = new_identity("bcc_test_dude_1@darthmama.cool", NULL, NULL, "BCC Test Recip");
    pEp_identity* bcc_recip = new_identity("bcc_test_dude_2@darthmama.cool", NULL, NULL, "BCC Super Sekrit Test Recip");
    
    message *msg = new_message(PEP_dir_outgoing);
    TEST_ASSERT_MSG((msg), "msg");
    msg->from = sender;
//    msg->to = new_identity_list(open_recip); FYI, this is supposed to fail for now. Unfortunately.
    msg->bcc = new_identity_list(bcc_recip);
    msg->shortmsg = strdup("Hello, world");
    msg->longmsg = strdup("Your mother was a hamster and your father smelt of elderberries.");
    msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    message *enc_msg = nullptr;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);

    TEST_ASSERT(status == PEP_STATUS_OK);
}

