// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"
#include "TestUtils.h"

#include <cpptest.h>
#include "EngineTestIndividualSuite.h"
#include "LeastCommonDenomColorTests.h"

using namespace std;

LeastCommonDenomColorTests::LeastCommonDenomColorTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("LeastCommonDenomColorTests::check_least_common_denom_color"),
                                                                      static_cast<Func>(&LeastCommonDenomColorTests::check_least_common_denom_color)));
}

void LeastCommonDenomColorTests::check_least_common_denom_color() {

    const char* mailfile = "test_mails/Test_Message_JSON-21_Color_Problems.eml";
            
    // import keys
    const string keytextkey1 = slurp("test_keys/pub/banmeonce-0x07B29090_pub.asc");
    const string keytextkey2 = slurp("test_keys/pub/banmetwice-0x4080C3E7_pub.asc");
    const string keytextkey3 = slurp("test_keys/pub/pep.never.me.test-0x79C11D1D_pub.asc");
    const string keytextkey4 = slurp("test_keys/priv/pep.never.me.test-0x79C11D1D_priv.asc");

    PEP_STATUS statuskey1 = import_key(session, keytextkey1.c_str(), keytextkey1.length(), NULL);
    PEP_STATUS statuskey2 = import_key(session, keytextkey2.c_str(), keytextkey2.length(), NULL);
    PEP_STATUS statuskey3 = import_key(session, keytextkey3.c_str(), keytextkey3.length(), NULL);
    PEP_STATUS statuskey4 = import_key(session, keytextkey4.c_str(), keytextkey4.length(), NULL);

    pEp_identity * sender = new_identity("pep.never.me.test@kgrothoff.org", NULL, "TOFU_pep.never.me.test@kgrothoff.org", "pEp Never Me Test");    
    sender->me = false;    
    PEP_STATUS status = update_identity(session, sender);
        
    // reset the trust on both keys before we start
    pEp_identity * recip1 = new_identity("banmeonce@kgrothoff.org", NULL, "TOFU_banmeonce@kgrothoff.org", "Ban Me Once");    
    recip1->me = false;    
    status = update_identity(session, recip1);
    key_reset_trust(session, recip1);
    
    pEp_identity * recip2 = new_identity("banmetwice@kgrothoff.org", NULL, "TOFU_banmetwice@kgrothoff.org", "Ban Me Twice");    
    recip2->me = false;    
    status = update_identity(session, recip2);
    key_reset_trust(session, recip2);
        
    const string mailtext = slurp(mailfile);

    // trust_personal_key(session, you);
    // 
    // status = update_identity(session, you);
    
    message* msg_ptr = nullptr;
    message* dest_msg = nullptr;
    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((msg_ptr), "msg_ptr");

    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((dest_msg), "dest_msg");
    /* message is signed and no recip is mistrusted... */
    TEST_ASSERT_MSG((color_from_rating(rating) == PEP_color_yellow), "color_from_rating(rating) == PEP_color_yellow");

    cout << "shortmsg: " << dest_msg->shortmsg << endl << endl;
    cout << "longmsg: " << dest_msg->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (dest_msg->longmsg_formatted ? dest_msg->longmsg_formatted : "(empty)") << endl << endl;

    PEP_rating decrypt_rating = rating;
    
    /* re-evaluate rating, counting on optional fields */
    status = re_evaluate_message_rating(session, dest_msg, NULL, PEP_rating_undefined, &rating);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((color_from_rating(rating) == PEP_color_yellow), "color_from_rating(rating) == PEP_color_yellow");

    /* re-evaluate rating, without optional fields */
    status = re_evaluate_message_rating(session, dest_msg, keylist, decrypt_rating, &rating);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((color_from_rating(rating) == PEP_color_yellow), "color_from_rating(rating) == PEP_color_yellow");

    /* Ok, now mistrust one recip */
    key_mistrusted(session, recip2);

    /* re-evaluate rating, counting on optional fields */
    status = re_evaluate_message_rating(session, dest_msg, NULL, PEP_rating_undefined, &rating);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((color_from_rating(rating) == PEP_color_red), "color_from_rating(rating) == PEP_color_red");

    /* re-evaluate rating, without optional fields */
    status = re_evaluate_message_rating(session, dest_msg, keylist, decrypt_rating, &rating);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((color_from_rating(rating) == PEP_color_red), "color_from_rating(rating) == PEP_color_red");

    free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);
    
    msg_ptr = nullptr;
    dest_msg = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((msg_ptr), "msg_ptr");
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
  
    cout << "shortmsg: " << dest_msg->shortmsg << endl << endl;
    cout << "longmsg: " << dest_msg->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (dest_msg->longmsg_formatted ? dest_msg->longmsg_formatted : "(empty)") << endl << endl;

    /* message is signed and no recip is mistrusted... */
    TEST_ASSERT_MSG((color_from_rating(rating) == PEP_color_red), "color_from_rating(rating) == PEP_color_red");

    free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    msg_ptr = nullptr;
    dest_msg = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    TEST_ASSERT(true);
}
