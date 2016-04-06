#include <iostream>
#include <string>
#include <cstring> // for strcmp()
#include <assert.h>
#include "blacklist.h"

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

    cout << "calling release()\n";
    release(session);
    return 0;
}

