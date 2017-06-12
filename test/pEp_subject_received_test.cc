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
#include "test_util.h" // for slurp()

using namespace std;

int main(int argc, char** argv) {

    cout << "\n*** check that pEp subject is handled properly in received mails ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    const char* keytexts[3];

    const string keytextkey1 = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string keytextkey2 = slurp("test_keys/priv/pep-test-recip-0x08DB0AEE_priv.asc");
    const string keytextkey3 = slurp("test_keys/pub/pep-test-recip-0x08DB0AEE_pub.asc");
    PEP_STATUS statuskey1 = import_key(session, keytextkey1.c_str(), keytextkey1.length(), NULL);
    PEP_STATUS statuskey2 = import_key(session, keytextkey2.c_str(), keytextkey2.length(), NULL);
    PEP_STATUS statuskey3 = import_key(session, keytextkey3.c_str(), keytextkey3.length(), NULL);

    pEp_identity * me = new_identity("pep.test.recip@kgrothoff.org", "93D19F24AD6F4C4BA9134AAF84D9217908DB0AEE", PEP_OWN_USERID, "pEp Test Recipient");    
    me->me = true;    
    PEP_STATUS status = myself(session, me);
    
    pEp_identity * you = new_identity("pep.test.apple@pep-project.org", NULL, "TOFU_pep.test.apple@pep-project.org", "pEp Test Recipient");    
    you->me = false;    
    
    status = update_identity(session, you);
    trust_personal_key(session, you);
    status = update_identity(session, you);


    
    const char* mailfiles[] = {"test_mails/pEp_encrypted_subject_IS_pEp.eml",
                                "test_mails/pEp_subject_normal.eml",
                                "test_mails/pEp_subject_normal_signed.eml",
                                "test_mails/pEp_subject_normal_unencrypted.eml",
                                "test_mails/pEp_subject_pEp.eml",
                                "test_mails/pEp_unencrypted_pEp_subject.eml"};
                                

    cout << "------------------------------------------------------------------------------------------" << endl;
    cout << "Test 1: Normal encrypted mail, pEp as substitute subject, regular subject in crypto text." << endl;
    cout << "------------------------------------------------------------------------------------------" << endl;
        
    string mailtext = slurp(mailfiles[1]);
    
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

    assert(strcmp("This is the usual pEp subject that should replace the above.", final_ptr->shortmsg) == 0);

    cout << "Test 1: Subject replaced as expected." << endl << endl;

    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    cout << "-------------------------------------------------------------------------------------------------" << endl;
    cout << "Test 2: Normal encrypted/signed mail, pEp as substitute subject, regular subject in crypto text." << endl;
    cout << "-------------------------------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp(mailfiles[2]);
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("Now signed!", final_ptr->shortmsg) == 0);

    cout << "Test 2: Subject replaced as expected." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);
    
    cout << "-----------------------------------------------------------------------" << endl;
    cout << "Test 3: Encrypted mail, pEp as actual subject, no subject in body text." << endl;
    cout << "-----------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp(mailfiles[0]);
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("pEp", final_ptr->shortmsg) == 0);

    cout << "Test 3: Subject remains intact as desired." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    cout << "-----------------------------------------------------------------------" << endl;
    cout << "Test 4: Encrypted mail, pEp as actual subject, pEp subject in body text." << endl;
    cout << "-----------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp(mailfiles[4]);
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("pEp", final_ptr->shortmsg) == 0);

    cout << "Test 4: Subject correct, in any event." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    cout << "-------------------------------------------------------------------------" << endl;
    cout << "Test 5: Unencrypted variant where pEp in the subject line is the subject." << endl;
    cout << "-------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp(mailfiles[5]);
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("pEp", final_ptr->shortmsg) == 0);

    cout << "Test 5: Subject remains intact." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

        
    cout << "calling release()\n";
    release(session);
    return 0;
}
