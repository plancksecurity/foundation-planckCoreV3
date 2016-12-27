// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>

#include "identity_list.h"

using namespace std;

/*
 *     char *address;              // C string with address UTF-8 encoded
    char *fpr;                  // C string with fingerprint UTF-8 encoded
    char *user_id;              // C string with user ID UTF-8 encoded
    char *username;             // C string with user name UTF-8 encoded
    PEP_comm_type comm_type;    // type of communication with this ID
    char lang[3];               // language of conversation
                                // ISO 639-1 ALPHA-2, last byte is 0
    bool me;                    // if this is the local user herself/himself
    */

int test_identity_equals(pEp_identity* val1, pEp_identity* val2) {
    assert(val1);
    assert(val2);
    assert(val1->address);
    assert(val2->address);
    assert(val1->fpr);
    assert(val2->fpr);
    assert(val1->username);
    assert(val2->username);
    return((strcmp(val1->address, val2->address) == 0) && (strcmp(val1->fpr, val2->fpr) == 0)
        && (strcmp(val1->username, val2->username) == 0) && (val1->comm_type == val2->comm_type)
        && (val1->lang[0] == val2->lang[0]) && (val1->lang[1] == val2->lang[1])
        && (val1->lang[2] == val2->lang[2]) && (val1->me == val2->me));
}

int main() {
    cout << "\n*** data structures: identity_list_test ***\n\n";

    pEp_identity* id1 = new_identity(
        "leon.schumacher@digitalekho.com",
        "8BD08954C74D830EEFFB5DEB2682A17F7C87F73D",
        "23",
        "Leon Schumacher"
    );
    id1->comm_type = PEP_ct_pEp;
    
    pEp_identity* id2 = new_identity(
        "krista@kgrothoff.org",
        "62D4932086185C15917B72D30571AFBCA5493553",
        "42",
        "Krista Bennett Grothoff"
    );
    
    id2->comm_type = PEP_ct_OpenPGP;

    pEp_identity* id3 = new_identity(
        "krista@pep-project.org",
        "51BF42D25BB5B154D71BF6CD3CF25B776D149247",
        "10",
        "Krista Grothoff"
    );
    
    id3->comm_type = PEP_ct_OTR;

    pEp_identity* id4 = new_identity(
        "papa@smurf.lu",
        "00001111222233334444555566667777DEADBEEF",
        "667",
        "Papa Smurf"
    );
    
    id4->comm_type = PEP_ct_key_b0rken;
    
    pEp_identity* id_arr[4] = {id1, id2, id3, id4};
        
    int i;
        
    cout << "creating one-element identity_list...\n";
    
    pEp_identity* new_id = identity_dup(id1);
    assert(new_id);
    identity_list* idlist = new_identity_list(new_id);
    assert(idlist->ident);
    assert(test_identity_equals(id1, idlist->ident));
    assert(idlist->next == NULL);
    cout << "one-element identity_list created, next element is NULL\n\n";
    
    cout << "duplicating one-element list...\n";
    identity_list* duplist = identity_list_dup(idlist);
    pEp_identity* srcid = idlist->ident;
    pEp_identity* dstid = duplist->ident;
    assert(dstid);
    assert(test_identity_equals(srcid, dstid));
    assert(srcid->address != dstid->address);   // test deep copies 
    assert(srcid->fpr != dstid->fpr);
    assert(srcid->username != dstid->username);
    assert(duplist->next == NULL);
    cout << "one-element identity_list duplicated.\n\n";
    
    cout << "freeing identity_lists...\n";
    free_identity_list(idlist); // will free srcid
    free_identity_list(duplist);
    idlist = NULL;
    duplist = NULL;
    srcid = NULL;
    
    identity_list* p;
    cout << "\ncreating four-element list...\n";
    idlist = identity_list_add(idlist, identity_dup(id_arr[0]));
    for (i = 1; i < 4; i++) {
        p = identity_list_add(idlist, identity_dup(id_arr[i]));
        assert(p);
    }
    
    p = idlist;
    
    for (i = 0; i < 4; i++) {
        assert(p);
        
        srcid = p->ident;
        assert(srcid);
        
        assert(test_identity_equals(srcid, id_arr[i]));
        assert(srcid->address != id_arr[i]->address);   // test deep copies
        assert(srcid->fpr != id_arr[i]->fpr);
        assert(srcid->username != id_arr[i]->username);

        p = p->next;
    }
    assert(p == NULL);
    
    cout << "\nduplicating four-element list...\n\n";
    duplist = identity_list_dup(idlist);
    
    p = idlist;
    identity_list* dup_p = duplist;
    
    while (dup_p) {
        srcid = p->ident;
        dstid = dup_p->ident;

        assert(dstid);
        
        assert(test_identity_equals(srcid, dstid));

        assert(srcid != dstid);   // test deep copies
        assert(srcid->address != dstid->address);   // test deep copies
        assert(srcid->fpr != dstid->fpr);
        assert(srcid->username != dstid->username);
        
        i++;
        p = p->next;

        dup_p = dup_p->next;
        assert((p == NULL) == (dup_p == NULL));
    }
    cout << "\nfour-element identity_list successfully duplicated.\n\n";

    cout << "freeing identity_lists...\n";
    free_identity_list(idlist); // will free srcid
    free_identity_list(duplist);
    idlist = NULL;
    duplist = NULL;
    
    cout << "done.\n";
        
    
    return 0;
}

