// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <iostream>

#include "pEpEngine.h"
#include "pEpEngine.h"
#include "stringpair.h"
#include "openpgp_compat.h"

#include <cpptest.h>
#include "EngineTestSessionSuite.h"
#include "PgpListKeysTests.h"

using namespace std;

PgpListKeysTests::PgpListKeysTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("PgpListKeysTests::check_pgp_list_keys"),
                                                                      static_cast<Func>(&PgpListKeysTests::check_pgp_list_keys)));
}

static void print_stringpair_list(stringpair_list_t* spl) {
    for ( ; spl != NULL; spl = spl->next) {
        if (spl->value) {
            cout << "Key:" << endl;
            if (spl->value->key)
                cout << "\tFPR: " << spl->value->key << endl;
            if (spl->value->value)
                cout << "\tUID: " << spl->value->value << endl;
        }
    }
}

void PgpListKeysTests::check_pgp_list_keys() {

    cout << "Listing all the keys:" << endl;
    stringpair_list_t* all_the_ids = NULL;
    OpenPGP_list_keyinfo(session, "", &all_the_ids);
    print_stringpair_list(all_the_ids);
    free_stringpair_list(all_the_ids);
    
    cout << "**********************" << endl << endl << "Checking on Alice, Bob and John" << endl;
    all_the_ids = NULL;
    OpenPGP_list_keyinfo(session, "pEp Test", &all_the_ids);
    print_stringpair_list(all_the_ids);
    free_stringpair_list(all_the_ids);

    cout << "**********************" << endl << endl << "Compare to find_keys for Alice, Bob and John" << endl;
    stringlist_t* all_the_keys;
    find_keys(session, "pEp Test", &all_the_keys);
    stringlist_t* i;
    for (i = all_the_keys; i; i = i->next) {
        cout << i->value << endl;
    }
    free_stringlist(all_the_keys);

    
    cout << "**********************" << endl << endl << "Checking FPR" << endl;
    all_the_ids = NULL;
    OpenPGP_list_keyinfo(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", &all_the_ids);
    print_stringpair_list(all_the_ids);
    free_stringpair_list(all_the_ids);

    cout << "**********************" << endl << endl << "Checking on nothing" << endl;
    all_the_ids = NULL;
    OpenPGP_list_keyinfo(session, "ekhwr89234uh4rknfjsklejfnlskjflselkflkserjs", &all_the_ids);
    print_stringpair_list(all_the_ids);
    free_stringpair_list(all_the_ids);

    cout << "calling release()\n";
}
