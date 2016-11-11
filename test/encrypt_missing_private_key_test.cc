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

int main() {
    cout << "\n*** blacklist_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // blacklist test code

    cout << "blacklist only key for identity / add key / check which key is used" << endl;
    
    // 2797 65A2 FEB5 B7C7 31B8  61D9 3E4C EFD9 F7AF 4684 - this is the blacklisted key in blacklisted_pub.asc

    /* read the key into memory */
    ifstream infile("blacklisted_pub.asc");
    string keytext;
    while (!infile.eof()) {
        static string line;
        getline(infile, line);
        keytext += line + "\n";
    }
    infile.close(); 
    
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
    PEP_STATUS status11 = update_identity(session, blacklisted_identity);

    /* identity is blacklisted. Now let's try to encrypt a message. */
    
    const char* new_key = NULL;    
    
    ifstream infile2("test_mails/blacklist_no_key.eml");
    string mailtext;
    while (!infile2.eof()) {
        static string line;
        getline(infile2, line);
        mailtext += line + "\n";
    }     infile2.close(); 

    message* enc_msg = NULL;
    
    PEP_STATUS status69 = MIME_encrypt_message(session, mailtext.c_str(), mailtext.length(), NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
//    pEp_identity * me1 = new_identity("blacklist_test@kgrothoff.org", NULL, PEP_OWN_USERID, "Blacklisted Key Message Recipient");    

    new_key = enc_msg->from->fpr;
    cout << "Encrypted with key " << new_key << endl;
//     PEP_STATUS status = update_identity(session, me1);
//     message* msg_ptr = nullptr;
//     message* dest_msg = nullptr;
//     stringlist_t* keylist = nullptr;
//     PEP_rating rating;
//     PEP_decrypt_flags_t flags;
//     
//     status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
//     assert(status == PEP_STATUS_OK);
//     status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
// 
//     PEP_STATUS status12 = update_identity(session, blacklisted_identity);
// 
//     assert(strcasecmp(blacklisted_identity->fpr, new_key) == 0);
    
    PEP_STATUS status = delete_keypair(session, new_key);
    PEP_STATUS status13 = blacklist_delete(session, bl_fpr_1);
    PEP_STATUS status14 = update_identity(session, blacklisted_identity);

    
    free_message(enc_msg);
    
    cout << "calling release()\n";
    release(session);
    return 0;
}

