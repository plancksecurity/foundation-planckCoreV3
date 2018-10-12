// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring> // for strcmp()
#include <cpptest.h>

#include "test_util.h"

#include "pEpEngine.h"
#include "blacklist.h"
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"

#include "EngineTestSessionSuite.h"
#include "BlacklistAcceptNewKeyTests.h"

using namespace std;

BlacklistAcceptNewKeyTests::BlacklistAcceptNewKeyTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("BlacklistAcceptNewKeyTests::check_blacklist_accept_new_key"),
                                                                      static_cast<Func>(&BlacklistAcceptNewKeyTests::check_blacklist_accept_new_key)));
}

void BlacklistAcceptNewKeyTests::check_blacklist_accept_new_key() {

    // blacklist test code

    cout << "blacklist only key for identity / add key / check which key is used" << endl;
    
    // 2797 65A2 FEB5 B7C7 31B8  61D9 3E4C EFD9 F7AF 4684 - this is the blacklisted key in blacklisted_pub.asc

    /* read the key into memory */
    const string keytext = slurp("blacklisted_pub.asc");
    
    /* import it into pep */
    PEP_STATUS status7 = import_key(session, keytext.c_str(), keytext.length(), NULL);
    
    const char* bl_fpr_1 = "279765A2FEB5B7C731B861D93E4CEFD9F7AF4684";
    bool is_blacklisted = false;
    
    pEp_identity* blacklisted_identity = new_identity("blacklistedkeys@kgrothoff.org",
                                                      bl_fpr_1,
                                                      NULL,
                                                      "Blacklist Keypair");
    PEP_STATUS status8 = update_identity(session, blacklisted_identity);
    PEP_STATUS status9 = blacklist_add(session, bl_fpr_1);
    PEP_STATUS status10 = blacklist_is_listed(session, bl_fpr_1, &is_blacklisted);
    TEST_ASSERT_MSG((is_blacklisted), "is_blacklisted");
    PEP_STATUS status11 = update_identity(session, blacklisted_identity);
    TEST_ASSERT_MSG((status11 == PEP_STATUS_OK), "status11 == PEP_STATUS_OK");
    TEST_ASSERT_MSG((_streq(bl_fpr_1, blacklisted_identity->fpr)), "_streq(bl_fpr_1, blacklisted_identity->fpr)");
    
    bool id_def, us_def, addr_def;
    status11 = get_valid_pubkey(session, blacklisted_identity,
                                &id_def, &us_def, &addr_def, true);
    TEST_ASSERT_MSG((blacklisted_identity->comm_type == PEP_ct_unknown), "blacklisted_identity->comm_type == PEP_ct_unknown");
                        
    if (!(blacklisted_identity->fpr))
        cout << "OK! blacklisted_identity->fpr is empty. Yay!" << endl;
    else
        cout << "Not OK. blacklisted_identity->fpr is " << blacklisted_identity->fpr << "." << endl
             << "Expected it to be empty." << endl;
    TEST_ASSERT_MSG((!(blacklisted_identity->fpr) || blacklisted_identity->fpr[0] == '\0'), "!(blacklisted_identity->fpr) || blacklisted_identity->fpr[0] == '\0'");

    /* identity is blacklisted. Now let's read in a message which contains a new key for that ID. */
    
    const char* new_key = "634FAC4417E9B2A5DC2BD4AAC4AEEBBE7E62701B";
    const string mailtext = slurp("test_mails/blacklist_new_key_attached.eml");
    pEp_identity * me1 = new_identity("blacklist_test@kgrothoff.org", NULL, PEP_OWN_USERID, "Blacklisted Key Message Recipient");    

    PEP_STATUS status = update_identity(session, me1);
    message* msg_ptr = nullptr;
    message* dest_msg = nullptr;
    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), "status == PEP_STATUS_OK");
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);

    PEP_STATUS status12 = get_valid_pubkey(session, blacklisted_identity,
                                           &id_def, &us_def, &addr_def, true);

    TEST_ASSERT_MSG((strcasecmp(blacklisted_identity->fpr, new_key) == 0), "strcasecmp(blacklisted_identity->fpr, new_key) == 0");

    PEP_STATUS status13 = blacklist_delete(session, bl_fpr_1);
    PEP_STATUS status14 = update_identity(session, blacklisted_identity);

    free_message(msg_ptr);
    free_message(dest_msg);
    free_stringlist(keylist);
}
