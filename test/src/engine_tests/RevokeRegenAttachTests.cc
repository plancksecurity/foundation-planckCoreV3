// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cstring>
#include <time.h>
#include <iostream>
#include <fstream>
#include <assert.h>

#include "pEpEngine.h"
#include "platform.h"
#include "mime.h"
#include "message_api.h"

#include "TestUtils.h"

#include <cpptest.h>
#include "EngineTestSessionSuite.h"
#include "RevokeRegenAttachTests.h"

using namespace std;

RevokeRegenAttachTests::RevokeRegenAttachTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("RevokeRegenAttachTests::check_revoke_regen_attach"),
                                                                      static_cast<Func>(&RevokeRegenAttachTests::check_revoke_regen_attach)));
}

void RevokeRegenAttachTests::setup() {
    EngineTestSessionSuite::setup();
    string recip_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    PEP_STATUS status = import_key(session, recip_key.c_str(), recip_key.size(), NULL);
    assert(status == PEP_TEST_KEY_IMPORT_SUCCESS);
}


void RevokeRegenAttachTests::check_revoke_regen_attach() {
    PEP_STATUS status = PEP_STATUS_OK;   

    cout << "creating own id for : ";
    char *uniqname = strdup("AAAAtestuser@testdomain.org");
    srandom(time(NULL));
    for(int i=0; i < 4;i++)
        uniqname[i] += random() & 0xf;
    
    cout << uniqname << "\n";
    pEp_identity * me = new_identity(uniqname, NULL, PEP_OWN_USERID, "Test User");
    free(uniqname);
    myself(session, me);

    cout << "generated fingerprint \n";
    cout << me->fpr << "\n";

    const char *prev_fpr = strdup(me->fpr);
    
    cout << "revoke \n";
    
    key_mistrusted(session, me);

    cout << "re-generated fingerprint \n";
    free(me->fpr);
    me->fpr = NULL;
    status = myself(session, me);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), "status == PEP_STATUS_OK");
    cout << me->fpr << "\n";
    
    TEST_ASSERT_MSG((me->fpr), "me->fpr");
    TEST_ASSERT_MSG((strcmp(me->fpr, prev_fpr) != 0), "strcmp(me->fpr, prev_fpr) != 0");
    cout << "New fpr is: " << me->fpr;
    
    me->fpr = NULL;
    me->comm_type = PEP_ct_unknown;
    myself(session, me);
    
    identity_list *to = new_identity_list(new_identity("pep.test.alice@pep-project.org", NULL, "42", "pEp Test Alice (test key don't use)"));
    message *msg = new_message(PEP_dir_outgoing);
    TEST_ASSERT_MSG((msg), "msg");
    msg->from = me;
    msg->to = to;
    msg->shortmsg = strdup("hello, world");
    cout << "message created.\n";

    cout << "encrypting message as MIME multipart…\n";
    message *enc_msg;
    cout << "calling encrypt_message()\n";
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), "status == PEP_STATUS_OK");
    TEST_ASSERT_MSG((enc_msg), "enc_msg");
    cout << "message encrypted.\n";

    // cout << msg->attachments->filename;
    // int bl_len = bloblist_length(msg->attachments);
    // cout << "Message contains " << bloblist_length(msg->attachments) << " attachments." << endl;
    // TEST_ASSERT_MSG((bloblist_length(msg->attachments) == 2), "bloblist_length(msg->attachments) == 2");
    // TEST_ASSERT_MSG((strcmp(msg->attachments->filename, "file://pEpkey.asc") == 0), "strcmp(msg->attachments->filename, \"file://pEpkey.asc\") == 0");
    // TEST_ASSERT_MSG((strcmp(msg->attachments->next->filename, "file://pEpkey.asc") == 0), "strcmp(msg->attachments->next->filename, \"file://pEpkey.asc\") == 0");
    // 
    // cout << "message contains 2 key attachments.\n";

    free_message(msg);
    free_message(enc_msg);
   
    // TODO: check that revoked key isn't sent after some time.

}
