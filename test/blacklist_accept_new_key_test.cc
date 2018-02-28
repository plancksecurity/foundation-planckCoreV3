// This file is under GNU General Public License 3.0
// see LICENSE.txt

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
#include "test_util.h"

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
    assert(is_blacklisted);
    PEP_STATUS status11 = update_identity(session, blacklisted_identity);
    assert(status11 == PEP_KEY_BLACKLISTED);
    assert(_streq(bl_fpr_1, blacklisted_identity->fpr));
    
    bool id_def, us_def, addr_def;
    status11 = get_valid_pubkey(session, blacklisted_identity,
                                &id_def, &us_def, &addr_def, true);
    if (!(blacklisted_identity->fpr))
        cout << "OK! blacklisted_identity->fpr is empty. Yay!" << endl;
    else
        cout << "Not OK. blacklisted_identity->fpr is " << blacklisted_identity->fpr << "." << endl
             << "Expected it to be empty." << endl;
    assert(!(blacklisted_identity->fpr) || blacklisted_identity->fpr[0] == '\0');

    /* identity is blacklisted. Now let's read in a message which contains a new key for that ID. */
    
    const char* new_key = "634FAC4417E9B2A5DC2BD4AAC4AEEBBE7E62701B";
    const string mailtext = slurp("test_mails/blacklist_new_key_attached.eml");
    pEp_identity * me1 = new_identity("blacklist_test@kgrothoff.org", NULL, PEP_OWN_USERID, "Blacklisted Key Message Recipient");    

    PEP_STATUS status = update_identity(session, me1);
    message* msg_ptr = nullptr;
    message* dest_msg = nullptr;
    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    
    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
    assert(status == PEP_STATUS_OK);
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);

    PEP_STATUS status12 = get_valid_pubkey(session, blacklisted_identity,
                                           &id_def, &us_def, &addr_def, true);

    assert(strcasecmp(blacklisted_identity->fpr, new_key) == 0);

    PEP_STATUS status13 = blacklist_delete(session, bl_fpr_1);
    PEP_STATUS status14 = update_identity(session, blacklisted_identity);

    status = delete_keypair(session, new_key);
    update_identity(session, blacklisted_identity);
    status = delete_keypair(session, bl_fpr_1);
    update_identity(session, blacklisted_identity);
    
    free_message(msg_ptr);
    free_message(dest_msg);
    free_stringlist(keylist);
    
    cout << "calling release()\n";
    release(session);
    return 0;
}
