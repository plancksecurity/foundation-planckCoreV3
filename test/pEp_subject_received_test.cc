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

    cout << "\n*** check that p≡p subject is handled properly in received mails ***\n\n";

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
    
    pEp_identity * you = new_identity("pep.test.alice@pep-project.org", NULL, "TOFU_pep.test.alice@pep-project.org", "Alice Test");    
    you->me = false;

    status = update_identity(session, you);
    trust_personal_key(session, you);
    status = update_identity(session, you);

    cout << "------------------------------------------------------------------------------------------" << endl;
    cout << "Test 1a: Normal encrypted mail, pEp as substitute subject, regular subject in crypto text." << endl;
    cout << "------------------------------------------------------------------------------------------" << endl;
        
    string mailtext = slurp("test_mails/pEp_subject_normal_1a.eml");
    
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
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("This is the usual pEp subject that should replace the above.", final_ptr->shortmsg) == 0);

    cout << "Test 1a: Subject replaced as expected." << endl << endl;

    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    cout << "------------------------------------------------------------------------------------------" << endl;
    cout << "Test 1b: Normal encrypted mail, p≡p as substitute subject, regular subject in crypto text." << endl;
    cout << "------------------------------------------------------------------------------------------" << endl;
        
    mailtext = slurp("test_mails/p3p_subject_normal_1b.eml");
    
    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("This is the usual pEp subject that should replace the above.", final_ptr->shortmsg) == 0);

    cout << "Test 1b: Subject replaced as expected." << endl << endl;

    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    cout << "-------------------------------------------------------------------------------------------------" << endl;
    cout << "Test 2a: Normal encrypted/signed mail, pEp as substitute subject, regular subject in crypto text." << endl;
    cout << "-------------------------------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp("test_mails/pEp_subject_normal_signed_2a.eml");
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("Now signed!", final_ptr->shortmsg) == 0);

    cout << "Test 2a: Subject replaced as expected." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    cout << "-------------------------------------------------------------------------------------------------" << endl;
    cout << "Test 2b: Normal encrypted/signed mail, p≡p as substitute subject, regular subject in crypto text." << endl;
    cout << "-------------------------------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp("test_mails/p3p_subject_normal_signed_2b.eml");
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("Now signed!", final_ptr->shortmsg) == 0);

    cout << "Test 2b: Subject replaced as expected." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    
    cout << "---------------------------------------------------------------------------" << endl;
    cout << "Test 3a: Encrypted mail, pEp as displayed subject, no subject in body text." << endl;
    cout << "---------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp("test_mails/pEp_encrypted_subject_IS_pEp_3a.eml");
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("pEp", final_ptr->shortmsg) == 0);

    cout << "Test 3a: Subject remains intact as desired." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    cout << "---------------------------------------------------------------------------" << endl;
    cout << "Test 3b: Encrypted mail, p≡p as displayed subject, no subject in body text." << endl;
    cout << "---------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp("test_mails/p3p_encrypted_subject_IS_pEp_3b.eml");
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("p≡p", final_ptr->shortmsg) == 0);

    cout << "Test 3: Subject remains intact as desired." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);


    cout << "----------------------------------------------------------------------------" << endl;
    cout << "Test 4a: Encrypted mail, pEp as displayed subject, pEp subject in body text." << endl;
    cout << "----------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp("test_mails/pEp_subject_pEp_replaced_w_pEp_4a.eml");
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("pEp", final_ptr->shortmsg) == 0);

    cout << "Test 4a: Subject correct." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    cout << "----------------------------------------------------------------------------" << endl;
    cout << "Test 4b: Encrypted mail, p≡p as displayed subject, pEp subject in body text." << endl;
    cout << "----------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp("test_mails/pEp_subject_pEp_replaced_w_p3p_4b.eml");
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("pEp", final_ptr->shortmsg) == 0);

    cout << "Test 4b: Subject correct." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    cout << "----------------------------------------------------------------------------" << endl;
    cout << "Test 4c: Encrypted mail, pEp as displayed subject, p≡p subject in body text." << endl;
    cout << "----------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp("test_mails/pEp_subject_p3p_replaced_w_pEp_4c.eml");
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("p≡p", final_ptr->shortmsg) == 0);

    cout << "Test 4c: Subject correct." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    cout << "----------------------------------------------------------------------------" << endl;
    cout << "Test 4d: Encrypted mail, p≡p as displayed subject, p≡p subject in body text." << endl;
    cout << "----------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp("test_mails/pEp_subject_p3p_replaced_w_p3p_4d.eml");
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("p≡p", final_ptr->shortmsg) == 0);

    cout << "Test 4d: Subject correct, in any event." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);


    cout << "-------------------------------------------------------------------------" << endl;
    cout << "Test 5a: Unencrypted variant where pEp in the subject line is the subject." << endl;
    cout << "-------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp("test_mails/pEp_unencrypted_pEp_subject_5a.eml");
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("pEp", final_ptr->shortmsg) == 0);

    cout << "Test 5a: Subject remains intact." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);


    cout << "--------------------------------------------------------------------------" << endl;
    cout << "Test 5b: Unencrypted variant where p≡p in the subject line is the subject." << endl;
    cout << "--------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp("test_mails/pEp_unencrypted_p3p_subject_5b.eml");
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("p≡p", final_ptr->shortmsg) == 0);

    cout << "Test 5b: Subject remains intact." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    cout << "----------------------------------------------------------------------------------------------------------------------" << endl;
    cout << "Test 6: Normal unencrypted email where a subject line exists in the text but the subject is not a replacement subject." << endl;
    cout << "----------------------------------------------------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;
    
    mailtext = slurp("test_mails/pEp_subject_normal_unencrypted_6.eml");
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    assert(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;
  
    cout << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    cout << "longmsg: " << final_ptr->longmsg << endl << endl;
    cout << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    assert(strcmp("This is just a normal subject, really", final_ptr->shortmsg) == 0);

    cout << "Test 6: Subject remains intact." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);
        
    cout << "calling release()\n";
    release(session);
    return 0;
}
