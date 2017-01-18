#include <iostream>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()
#include <assert.h>
#include "blacklist.h"
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"

using namespace std;

int main(int argc, char** argv) {
    

    const char* mailfile = "test_mails/apple_mail_TC_signed_encrypted.eml";
    
    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    ifstream infilekey1("test_keys/pub/pep-test-apple-0x1CCBC7D7_pub.asc");
    string keytextkey1;
    while (!infilekey1.eof()) {
        static string line;
        getline(infilekey1, line);
        keytextkey1 += line + "\n";
    }
    infilekey1.close(); 
    
    ifstream infilekey2("test_keys/priv/pep-test-recip-0x08DB0AEE_priv.asc");
    string keytextkey2;
    while (!infilekey2.eof()) {
        static string line;
        getline(infilekey2, line);
        keytextkey2 += line + "\n";
    }
    infilekey2.close(); 

    PEP_STATUS statuskey1 = import_key(session, keytextkey1.c_str(), keytextkey1.length(), NULL);
    PEP_STATUS statuskey2 = import_key(session, keytextkey2.c_str(), keytextkey2.length(), NULL);
        
    ifstream infile(mailfile);
    string mailtext;
    while (!infile.eof()) {
        static string line;
        getline(infile, line);
        mailtext += line + "\n";
    }
    infile.close(); 

    pEp_identity * me = new_identity("pep.test.recip@kgrothoff.org", NULL, PEP_OWN_USERID, "pEp Test Recipient");    
    me->me = true;    
    PEP_STATUS status = update_identity(session, me);

    pEp_identity * you = new_identity("pep.test.apple@pep-project.org", NULL, "TOFU_pep.test.apple@pep-project.org", "pEp Test Recipient");    
    you->me = false;    
    status = update_identity(session, you);

    trust_personal_key(session, you);
    
    status = update_identity(session, you);
    
    message* msg_ptr = nullptr;
    message* dest_msg = nullptr;
    message* final_ptr = nullptr;
    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(color_from_rating(rating) == PEP_color_green);

    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    const char* mailfile2 = "test_mails/apple_mail_TC_html_signed_encrypted.eml";
    
    ifstream infile2(mailfile2);
    string mailtext2;
    while (!infile2.eof()) {
        static string line;
        getline(infile2, line);
        mailtext2 += line + "\n";
    }
    infile2.close(); 
    
    status = mime_decode_message(mailtext2.c_str(), mailtext2.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(color_from_rating(rating) == PEP_color_green);

    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
        
    cout << "calling release()\n";
    release(session);
    return 0;
}
