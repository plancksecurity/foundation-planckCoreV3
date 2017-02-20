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
        
    const char* mailfile = "test_mails/Test_Message_JSON-21_Color_Problems.eml";
    
    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";
    
    // import keys

    ifstream infilekey1("test_keys/pub/banmeonce-0x07B29090_pub.asc");
    string keytextkey1;
    while (!infilekey1.eof()) {
        static string line;
        getline(infilekey1, line);
        keytextkey1 += line + "\n";
    }
    infilekey1.close(); 
    
    ifstream infilekey2("test_keys/pub/banmetwice-0x4080C3E7_pub.asc");
    string keytextkey2;
    while (!infilekey2.eof()) {
        static string line;
        getline(infilekey2, line);
        keytextkey2 += line + "\n";
    }
    infilekey2.close(); 

    ifstream infilekey3("test_keys/pub/pep.never.me.test-0x79C11D1D_pub.asc");
    string keytextkey3;
    while (!infilekey3.eof()) {
        static string line;
        getline(infilekey3, line);
        keytextkey3 += line + "\n";
    }
    infilekey3.close(); 
    
    ifstream infilekey4("test_keys/priv/pep.never.me.test-0x79C11D1D_priv.asc");
    string keytextkey4;
    while (!infilekey4.eof()) {
        static string line;
        getline(infilekey4, line);
        keytextkey4 += line + "\n";
    }
    infilekey4.close(); 

    PEP_STATUS statuskey1 = import_key(session, keytextkey1.c_str(), keytextkey1.length(), NULL);
    PEP_STATUS statuskey2 = import_key(session, keytextkey2.c_str(), keytextkey2.length(), NULL);
    PEP_STATUS statuskey3 = import_key(session, keytextkey3.c_str(), keytextkey3.length(), NULL);
    PEP_STATUS statuskey4 = import_key(session, keytextkey4.c_str(), keytextkey4.length(), NULL);

    pEp_identity * sender = new_identity("pep.never.me.test@kgrothoff.org", NULL, "TOFU_pep.never.me.test@kgrothoff.org", "pEp Never Me Test");    
    sender->me = false;    
    PEP_STATUS status = update_identity(session, sender);
        
    // reset the trust on both keys before we start
    pEp_identity * recip1 = new_identity("banmeonce@kgrothoff.org", NULL, "TOFU_banemeonce@kgrothoff.org", "Ban Me Once");    
    recip1->me = false;    
    status = update_identity(session, recip1);
    
    pEp_identity * recip2 = new_identity("banmetwice@kgrothoff.org", NULL, "TOFU_banemetwice@kgrothoff.org", "Ban Me Twice");    
    recip2->me = false;    
    status = update_identity(session, recip2);
        
    ifstream infile(mailfile);
    string mailtext;
    while (!infile.eof()) {
        static string line;
        getline(infile, line);
        mailtext += line + "\n";
    }
    infile.close(); 

    // trust_personal_key(session, you);
    // 
    // status = update_identity(session, you);
    
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

    /* message is signed and no recip is mistrusted... */
    assert(color_from_rating(rating) == PEP_color_yellow);

    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    /* Ok, now mistrust one recip */
    key_mistrusted(session, recip2);
    
    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    /* message is signed and no recip is mistrusted... */
    assert(color_from_rating(rating) == PEP_color_red);

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
