#include <iostream>
#include <string>
#include <assert.h>
#include "pEpEngine.h"
#include "identity_list.h"

using namespace std;

void print_id_list(identity_list* idl) {
    for ( ; idl != NULL; idl = idl->next) {
        if (idl->ident) {
            cout << "Identity:" << endl;
            if (idl->ident->fpr)
                cout << "\tFPR: " << idl->ident->fpr << endl;
            if (idl->ident->address)
                cout << "\tAddress: " << idl->ident->address << endl; 
            if (idl->ident->user_id)
                cout << "\tUID: " << idl->ident->user_id << endl;
            if (idl->ident->username)
                cout << "\tName: " << idl->ident->username << endl << endl;
        }
    }
}

int main() {
    cout << "\n*** pgp_list_keys_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    identity_list* all_the_ids = NULL;
    list_keys(session, &all_the_ids);
    print_id_list(all_the_ids);
    free_identity_list(all_the_ids);

    cout << "calling release()\n";
    release(session);
    return 0;
}

