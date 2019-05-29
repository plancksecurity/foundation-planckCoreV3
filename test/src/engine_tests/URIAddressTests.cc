// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include <cpptest.h>
#include "test_util.h"

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "URIAddressTests.h"

using namespace std;

URIAddressTests::URIAddressTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("URIAddressTests::check_uri_address_genkey"),
                                                                      static_cast<Func>(&URIAddressTests::check_uri_address_genkey)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("URIAddressTests::check_uri_address_encrypt"),
                                                                      static_cast<Func>(&URIAddressTests::check_uri_address_encrypt)));
}

// FIXME: URL, URN
void URIAddressTests::check_uri_address_genkey() {
    const char* uri_addr = "shark://grrrr/39874293847092837443987492834";
    const char* uname = "GRRRR, the angry shark";
    
    pEp_identity* me = new_identity(uri_addr, NULL, PEP_OWN_USERID, uname);
    
    PEP_STATUS status = myself(session, me);
    
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(me->fpr && me->fpr[0] != '\0');
    
    char* keydata = NULL;
    size_t keysize = 0;
    status = export_key(session, me->fpr, 
                        &keydata, &keysize);

    TEST_ASSERT(keydata && keysize > 0);
    // no guarantee of NUL-termination atm.
//    cout << keydata << endl;

    free(keydata);
    free_identity(me);
}

// FIXME: URL, URN
void URIAddressTests::check_uri_address_encrypt() {
    const char* uri_addr = "shark://grrrr/39874293847092837443987492834";
    const char* uname = "GRRRR, the angry shark";
    
    pEp_identity* me = new_identity(uri_addr, NULL, PEP_OWN_USERID, uname);
    
    PEP_STATUS status = myself(session, me);
    
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(me->fpr && me->fpr[0] != '\0');
    
    const char* you_uri_addr = "shark://bait/8uyoi3lu4hl2..dfoif983j4b@%";
    const char* youname = "Nemo, the delicious fish";
    pEp_identity* you = new_identity(you_uri_addr, NULL, "Food for Shark", youname);
    status = generate_keypair(session, you);
    TEST_ASSERT(status == PEP_STATUS_OK);

    stringlist_t* keylist = NULL;
    status = find_keys(session, you_uri_addr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT(keylist && keylist->value);

    status = update_identity(session, you);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(you->fpr && you->fpr[0] != '\0');
    
    message* msg = new_message(PEP_dir_outgoing);
    
    msg->from = me;
    msg->to = new_identity_list(you);
    msg->shortmsg = strdup("Invitation");
    msg->longmsg = strdup("Yo Neems, wanna come over for dinner?");

    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
}
