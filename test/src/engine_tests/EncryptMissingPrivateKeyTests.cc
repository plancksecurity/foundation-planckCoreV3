// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()
#include <assert.h>
#include <cpptest.h>

#include "blacklist.h"
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"
#include "test_util.h"

#include "pEpEngine.h"

using namespace std;

#include "EngineTestSessionSuite.h"
#include "EncryptMissingPrivateKeyTests.h"

using namespace std;

EncryptMissingPrivateKeyTests::EncryptMissingPrivateKeyTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EncryptMissingPrivateKeyTests::check_encrypt_missing_private_key"),
                                                                      static_cast<Func>(&EncryptMissingPrivateKeyTests::check_encrypt_missing_private_key)));
}

void EncryptMissingPrivateKeyTests::setup() {
    EngineTestSessionSuite::setup();
    string recip_key = slurp("test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
    PEP_STATUS status = import_key(session, recip_key.c_str(), recip_key.size(), NULL);
    assert(status == PEP_TEST_KEY_IMPORT_SUCCESS);
}

void EncryptMissingPrivateKeyTests::check_encrypt_missing_private_key() {
    
    pEp_identity* no_key_identity = new_identity("blacklistself@kgrothoff.org",
                                                      NULL,
                                                      PEP_OWN_USERID,
                                                      "Blacklist Self");
    no_key_identity->me = true;
    PEP_STATUS status8 = myself(session, no_key_identity);
    TEST_ASSERT (status8 == PEP_STATUS_OK);

    /* Now let's try to encrypt a message. */
        
    message* tmp_msg = NULL;
    message* enc_msg = NULL;
    
    const string mailtext = slurp("test_mails/blacklist_no_key.eml");

    PEP_STATUS status = mime_decode_message(mailtext.c_str(), mailtext.length(), &tmp_msg, NULL);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), "status == PEP_STATUS_OK");
    
    status = update_identity(session, tmp_msg->from);
    identity_list* to_list = tmp_msg->to;

    while (to_list) {
        if (to_list->ident)
            update_identity(session, to_list->ident);
        to_list = to_list->next;
    }
    
    // This isn't incoming, though... so we need to reverse the direction
    tmp_msg->dir = PEP_dir_outgoing;
    status = encrypt_message(session,
                             tmp_msg,
                             NULL,
                             &enc_msg,
                             PEP_enc_PGP_MIME,
                             0);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), "status == PEP_STATUS_OK");
    

    char* new_key = enc_msg->from->fpr;
    cout << "Encrypted with key " << new_key << endl;
    
    free_message(tmp_msg);    
    free_message(enc_msg);
}
