#include <iostream>
#include <iostream>
#include <vector>
#include <cstring> // for strcmp()
#include <assert.h>
#include "blacklist.h"
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"
#include "test_util.h"

using namespace std;

int main(int argc, char** argv) {
    cout << "\n*** least_color_group_test.cc ***\n\n";
    
    const char* mailfile = "test_mails/color_test.eml";
    
    const std::vector<const char*> keynames = {
                              "test_keys/priv/pep.color.test.P-0x3EBE215C_priv.asc",
                              "test_keys/pub/pep.color.test.H-0xD17E598E_pub.asc",
                              "test_keys/pub/pep.color.test.L-0xE9CDB4CE_pub.asc",
                              "test_keys/pub/pep.color.test.P-0x3EBE215C_pub.asc",
                              "test_keys/pub/pep.color.test.V-0x71FC6D28_pub.asc"
                          };
    
    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";
    
    for (auto name : keynames) {
        cout << "\t read keyfile \"" << name << "\"..." << std::endl;
        const string keytextkey = slurp(name);
        PEP_STATUS statuskey = import_key(session, keytextkey.c_str(), keytextkey.length(), NULL);
        assert(statuskey == PEP_STATUS_OK);
    }
    
    cout << "\t read keyfile mailfile \"" << mailfile << "\"..." << std::endl;
    const string mailtext = slurp(mailfile);
    cout << "\t All files read successfully." << std::endl;

    pEp_identity * me1 = new_identity("pep.color.test.P@kgrothoff.org", 
                                      "7EE6C60C68851954E1797F81EA59715E3EBE215C", 
                                      PEP_OWN_USERID, "Pep Color Test P (recip)");
    me1->me = true;
    PEP_STATUS status = update_identity(session, me1);
    
    pEp_identity * sender1 = new_identity("pep.color.test.V@kgrothoff.org",
                                          NULL, "TOFU_pep.color.test.V@kgrothoff.org",
                                          "Pep Color Test V (sender)");
    
    status = update_identity(session, sender1);
    trust_personal_key(session, sender1);
    status = update_identity(session, sender1);
    
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
    cout << "rating: " << rating << endl << endl;
    cout << "keys used: " << endl;
    
    int i = 0;
    for (stringlist_t* k = keylist; k; k = k->next) {
        if (i == 0)
            cout << "\t Signer (key 0):\t" << k->value << endl;
        else
            cout << "\t #" << i << ":\t" << k->value << endl;
        i++;
    }
    
//    free_identity(me1);
    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);
    
    cout << "calling release()\n";
    release(session);
    return 0;
}
