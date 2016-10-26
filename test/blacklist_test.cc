#include <iostream>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()
#include <assert.h>
#include "blacklist.h"
#include "keymanagement.h"

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

    cout << "adding 23 to blacklist\n";
    PEP_STATUS status2 = blacklist_add(session, "23");
    assert(status2 == PEP_STATUS_OK);
    cout << "added.\n";

    bool listed;
    PEP_STATUS status3 = blacklist_is_listed(session, "23", &listed);
    assert(status3 == PEP_STATUS_OK);
    assert(listed);
    cout << "23 is listed.\n";

    stringlist_t *blacklist;
    PEP_STATUS status6 = blacklist_retrieve(session, &blacklist);
    assert(status6 == PEP_STATUS_OK);
    assert(blacklist);

    bool in23 = false;
    cout << "the blacklist contains now: ";
    for (stringlist_t *bl = blacklist; bl && bl->value; bl = bl->next) {
        cout << bl->value << ", ";
        if (std::strcmp(bl->value, "23") == 0)
            in23 = true;
    }
    cout << "END\n";
    assert(in23);
    free_stringlist(blacklist);

    cout << "deleting 23 from blacklist\n";
    PEP_STATUS status4 = blacklist_delete(session, "23");
    assert(status4 == PEP_STATUS_OK);
    cout << "deleted.\n";
    
    PEP_STATUS status5 = blacklist_is_listed(session, "23", &listed);
    assert(status5 == PEP_STATUS_OK);
    assert(!listed);
    cout << "23 is not listed any more.\n";

    cout << "blacklist only key for identity / unblacklist key / add key" << endl;
    
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
    
    /* FIXME: put in automated test stuff (N.B. only gdb mem examination to this point to get
     *        fix in */
    /* import it into pep */
    PEP_STATUS status7 = import_key(session, keytext.c_str(), keytext.length(), NULL);
    
    const char* bl_fpr_1 = "279765A2FEB5B7C731B861D93E4CEFD9F7AF4684";
    const char* bl_fpr_2 = "634FAC4417E9B2A5DC2BD4AAC4AEEBBE7E62701B";
    bool is_blacklisted = false;
    
    pEp_identity* blacklisted_identity = new_identity("blacklistedkeys@kgrothoff.org",
                                                      bl_fpr_1,
                                                      NULL,
                                                      "Blacklist Keypair");
    PEP_STATUS status8 = update_identity(session, blacklisted_identity);

    PEP_STATUS status9 = blacklist_add(session, bl_fpr_1);
    PEP_STATUS status10 = blacklist_is_listed(session, bl_fpr_1, &is_blacklisted);
    PEP_STATUS status11 = update_identity(session, blacklisted_identity);

    /* read the key into memory */
    ifstream infile2("blacklisted_pub2.asc");
    string keytext2;
    while (!infile2.eof()) {
        static string line2;
        getline(infile2, line2);
        keytext2 += line2 + "\n";
    }
    infile2.close(); 
    
    PEP_STATUS status14 = import_key(session, keytext.c_str(), keytext.length(), NULL);
    
    pEp_identity* blacklisted_identity2 = new_identity("blacklistedkeys@kgrothoff.org",
                                                       bl_fpr_2,
                                                        NULL,
                                                       "Blacklist Keypair");
    PEP_STATUS status15 = update_identity(session, blacklisted_identity2);
    PEP_STATUS status12 = blacklist_delete(session, bl_fpr_1);
    PEP_STATUS status13 = update_identity(session, blacklisted_identity);
    
    /* FIXME: remove both keys again from everywhere and clean up identities */
    free_identity(blacklisted_identity);
    free_identity(blacklisted_identity2);
    
    
    cout << "calling release()\n";
    release(session);
    return 0;
}

