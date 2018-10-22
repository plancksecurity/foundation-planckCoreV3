// This file is under GNU General Public License 3.0
// see LICENSE.txt

// #include <iostream>
// #include <iostream>
// #include <fstream>
// #include <string>
// #include <cstring> // for strcmp()
// #include <TEST_ASSERT.h>
// #include "blacklist.h"
// #include "keymanagement.h"
// #include "test_util.h"
// 
// // This file is under GNU General Public License 3.0
// // see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring> // for strcmp()

#include <cpptest.h>

#include "pEpEngine.h"

#include "blacklist.h"
#include "keymanagement.h"
#include "test_util.h"

#include "EngineTestSessionSuite.h"
#include "BlacklistTests.h"

using namespace std;

BlacklistTests::BlacklistTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("BlacklistTests::check_blacklist"),
                                                                      static_cast<Func>(&BlacklistTests::check_blacklist)));
}

void BlacklistTests::check_blacklist() {
    // blacklist test code

    cout << "adding 23 to blacklist\n";
    PEP_STATUS status2 = blacklist_add(session, "23");
    TEST_ASSERT_MSG((status2 == PEP_STATUS_OK), "status2 == PEP_STATUS_OK");
    cout << "added.\n";

    bool listed;
    PEP_STATUS status3 = blacklist_is_listed(session, "23", &listed);
    TEST_ASSERT_MSG((status3 == PEP_STATUS_OK), "status3 == PEP_STATUS_OK");
    TEST_ASSERT_MSG((listed), "listed");
    cout << "23 is listed.\n";

    stringlist_t *blacklist;
    PEP_STATUS status6 = blacklist_retrieve(session, &blacklist);
    TEST_ASSERT_MSG((status6 == PEP_STATUS_OK), "status6 == PEP_STATUS_OK");
    TEST_ASSERT_MSG((blacklist), "blacklist");

    bool in23 = false;
    cout << "the blacklist contains now: ";
    for (stringlist_t *bl = blacklist; bl && bl->value; bl = bl->next) {
        cout << bl->value << ", ";
        if (std::strcmp(bl->value, "23") == 0)
            in23 = true;
    }
    cout << "END\n";
    TEST_ASSERT_MSG((in23), "in23");
    free_stringlist(blacklist);

    cout << "deleting 23 from blacklist\n";
    PEP_STATUS status4 = blacklist_delete(session, "23");
    TEST_ASSERT_MSG((status4 == PEP_STATUS_OK), "status4 == PEP_STATUS_OK");
    cout << "deleted.\n";
    
    PEP_STATUS status5 = blacklist_is_listed(session, "23", &listed);
    TEST_ASSERT_MSG((status5 == PEP_STATUS_OK), "status5 == PEP_STATUS_OK");
    TEST_ASSERT_MSG((!listed), "!listed");
    cout << "23 is not listed any more.\n";

    cout << "blacklist only key for identity / unblacklist key / add key" << endl;

    
    // 2797 65A2 FEB5 B7C7 31B8  61D9 3E4C EFD9 F7AF 4684 - this is the blacklisted key in blacklisted_pub.asc

    const string keytext = slurp("blacklisted_pub.asc");
    
    /* FIXME: put in automated test stuff (N.B. only gdb mem examination to this point to get
     *        fix in */
    /* import it into pep */
    PEP_STATUS status7 = import_key(session, keytext.c_str(), keytext.length(), NULL);
    
    const char* bl_fpr_1 = "279765A2FEB5B7C731B861D93E4CEFD9F7AF4684";
    const char* bl_fpr_2 = "634FAC4417E9B2A5DC2BD4AAC4AEEBBE7E62701B"; 
    bool is_blacklisted = false;

    // Clean up from previous runs
    PEP_STATUS status10 = blacklist_is_listed(session, bl_fpr_1, &is_blacklisted);
    if (is_blacklisted) {
        is_blacklisted = false;
        blacklist_delete(session, bl_fpr_1);
    }
    
    pEp_identity* blacklisted_identity = new_identity("blacklistedkeys@kgrothoff.org",
                                                      bl_fpr_1,
                                                      NULL,
                                                      "Blacklist Keypair");

    PEP_STATUS status8 = update_identity(session, blacklisted_identity);
        
    // THERE IS NO BLACKLISTING OF PEP KEYS
    //blacklisted_identity->comm_type = PEP_ct_pEp;
    blacklisted_identity->comm_type = PEP_ct_OpenPGP_unconfirmed;

    PEP_STATUS status99 = set_identity(session, blacklisted_identity);
    
    trust_personal_key(session, blacklisted_identity);

    PEP_STATUS status999 = update_identity(session, blacklisted_identity);

    TEST_ASSERT_MSG((blacklisted_identity->comm_type == PEP_ct_OpenPGP), "blacklisted_identity->comm_type == PEP_ct_OpenPGP");

    PEP_STATUS status9 = blacklist_add(session, bl_fpr_1);
    status10 = blacklist_is_listed(session, bl_fpr_1, &is_blacklisted);
    PEP_STATUS status11 = update_identity(session, blacklisted_identity);
    /* new!!! */
    TEST_ASSERT_MSG((is_blacklisted), "is_blacklisted");
    TEST_ASSERT_MSG((status11 == PEP_STATUS_OK), "status11 == PEP_STATUS_OK");
    TEST_ASSERT_MSG((_streq(bl_fpr_1, blacklisted_identity->fpr)), "_streq(bl_fpr_1, blacklisted_identity->fpr)");
    
    bool id_def, us_def, addr_def;
    status11 = get_valid_pubkey(session, blacklisted_identity,
                                &id_def, &us_def, &addr_def, true);
    
    if (!(blacklisted_identity->fpr))
        cout << "OK! blacklisted_identity->fpr is empty. Yay!" << endl;
    else if (strcmp(blacklisted_identity->fpr, bl_fpr_2) == 0)
        cout << "OK! While this should be empty, you are probably running " << 
                "this in your home directory instead of the test environment " << 
                "and have leftover keys. This is an acceptable result here then. But you " <<
                "should probably clean up after yourself :)" << endl;
    else
        cout << "Not OK. blacklisted_identity->fpr is " << blacklisted_identity->fpr << "." << endl
             << "Expected it to be empty or (possibly) " << bl_fpr_2 << endl;
    TEST_ASSERT_MSG((!(blacklisted_identity->fpr) || blacklisted_identity->fpr[0] == '\0'|| (strcmp(blacklisted_identity->fpr, bl_fpr_2) == 0)), "!(blacklisted_identity->fpr) || blacklisted_identity->fpr[0] == '\0'|| (strcmp(blacklisted_identity->fpr, bl_fpr_2) == 0)");

    pEp_identity *me = new_identity("alice@peptest.ch", NULL, "423", "Alice Miller");
    TEST_ASSERT(me);
    PEP_STATUS status24 = myself(session, me);
    TEST_ASSERT_MSG((status24 == PEP_STATUS_OK), "myself: status24 == PEP_STATUS_OK");

    message *msg23 = new_message(PEP_dir_outgoing);
    TEST_ASSERT(msg23);
    msg23->from = me;
    msg23->to = new_identity_list(identity_dup(blacklisted_identity));
    TEST_ASSERT(msg23->to && msg23->to->ident);
    PEP_rating rating23;

    cout << "testing outgoing_message_rating() with blacklisted key in to\n";
    PEP_STATUS status23 = outgoing_message_rating(session, msg23, &rating23);
    TEST_ASSERT_MSG((status23 == PEP_STATUS_OK), "outgoing_message_rating: status must be PEP_STATUS_OK");
    TEST_ASSERT_MSG((rating23 == PEP_rating_unencrypted), "outgoing_message_rating: rating must be PEP_rating_unencrypted");

    free_message(msg23);

    const string keytext2 = slurp("blacklisted_pub2.asc");
    PEP_STATUS status14 = import_key(session, keytext2.c_str(), keytext2.length(), NULL);
    
    pEp_identity* blacklisted_identity2 = new_identity("blacklistedkeys@kgrothoff.org",
                                                       bl_fpr_2,
                                                        NULL,
                                                       "Blacklist Keypair");
    PEP_STATUS status15 = update_identity(session, blacklisted_identity2);
    // 
    // TEST_ASSERT_MSG((blacklisted_identity2->fpr && strcmp(blacklisted_identity2->fpr, bl_fpr_2) == 0), "blacklisted_identity2->fpr && strcmp(blacklisted_identity2->fpr, bl_fpr_2) == 0");
    // if (blacklisted_identity2->fpr && strcmp(blacklisted_identity2->fpr, bl_fpr_2) == 0)
    //     cout << "blacklisted identity's fpr successfully replaced by the unblacklisted one" << endl;
    // // else
    // //     cout << "blacklisted_identity->fpr should be " << bl_fpr_2 << " but is " << blacklisted_identity->fpr << endl;
    // 
    // PEP_STATUS status12 = blacklist_delete(session, bl_fpr_1);
    // PEP_STATUS status13 = update_identity(session, blacklisted_identity);
    //     
    // pEp_identity* stored_identity = new_identity("blacklistedkeys@kgrothoff.org",
    //                                               NULL,
    //                                               blacklisted_identity->user_id,
    //                                               "Blacklist Keypair");
    //  
    // PEP_STATUS status00 = update_identity(session, stored_identity);
    // 
    // // FIXME
    // // TEST_ASSERT_MSG((stored_identity->comm_type == PEP_ct_pEp), "stored_identity->comm_type == PEP_ct_pEp");    
    
    PEP_STATUS status16 = delete_keypair(session, bl_fpr_1);
    update_identity(session, blacklisted_identity);
    PEP_STATUS status17 = delete_keypair(session, bl_fpr_2);
    update_identity(session, blacklisted_identity2);
        
    free_identity(blacklisted_identity);
    free_identity(blacklisted_identity2);
}
