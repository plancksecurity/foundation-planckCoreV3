// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-textoutput.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()
#include "platform.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"
#include "test_util.h" // for slurp()

#include "EngineTestSuite.h"
#include "EngineTestSessionSuite.h"
#include "AppleMailTests.h"

using namespace std;

AppleMailTests::AppleMailTests(string suitename, string test_home_dir) : 
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {            
    TEST_ADD(AppleMailTests::check_apple_mail);
}

void AppleMailTests::check_apple_mail() {
    
    const char* mailfile = "test_mails/apple_mail_TC_signed_encrypted.eml";
    
    const string keytextkey1 = slurp("test_keys/pub/pep-test-apple-0x1CCBC7D7_pub.asc");
    const string keytextkey2 = slurp("test_keys/priv/pep-test-recip-0x08DB0AEE_priv.asc");
    const string keytextkey3 = slurp("test_keys/pub/pep-test-recip-0x08DB0AEE_pub.asc");

    PEP_STATUS statuskey1 = import_key(session, keytextkey1.c_str(), keytextkey1.length(), NULL);
    PEP_STATUS statuskey2 = import_key(session, keytextkey2.c_str(), keytextkey2.length(), NULL);
    PEP_STATUS statuskey3 = import_key(session, keytextkey3.c_str(), keytextkey3.length(), NULL);
        
    const string mailtext = slurp(mailfile);
    pEp_identity * me = new_identity("pep.test.recip@kgrothoff.org", "93D19F24AD6F4C4BA9134AAF84D9217908DB0AEE", PEP_OWN_USERID, "pEp Test Recipient");    
    me->me = true;    
    PEP_STATUS status = set_own_key(session, me, "93D19F24AD6F4C4BA9134AAF84D9217908DB0AEE");
    
    pEp_identity * you = new_identity("pep.test.apple@pep-project.org", NULL, "pep.test.apple@pep-project.org", "pEp Apple Test");    
    you->me = false;    
    status = update_identity(session, you);

    trust_personal_key(session, you);
    
    status = update_identity(session, you);
    
    message* msg_ptr = nullptr;
    message* dest_msg = nullptr;
    message* final_ptr = nullptr;
    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), "status == PEP_STATUS_OK");
    TEST_ASSERT_MSG((msg_ptr), "msg_ptr");
    
    update_identity(session, msg_ptr->from);
    update_identity(session, msg_ptr->to->ident);
    
    final_ptr = msg_ptr;
    
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    TEST_ASSERT_MSG((color_from_rating(rating) == PEP_color_green), "color_from_rating(rating) == PEP_color_green");

    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    flags = 0;
    
    const char* mailfile2 = "test_mails/apple_mail_TC_html_signed_encrypted.eml";
    const string mailtext2 = slurp(mailfile2);
    
    status = mime_decode_message(mailtext2.c_str(), mailtext2.length(), &msg_ptr);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), "status == PEP_STATUS_OK");
    TEST_ASSERT_MSG((msg_ptr), "msg_ptr");
    final_ptr = msg_ptr;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    TEST_ASSERT_MSG((color_from_rating(rating) == PEP_color_green), "color_from_rating(rating) == PEP_color_green");

    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;        
}
