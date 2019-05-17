// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include "pEpEngine.h"
#include "keymanagement.h"

#include <cpptest.h>
#include "EngineTestIndividualSuite.h"
#include "OwnIdentitiesRetrieveTests.h"

using namespace std;

OwnIdentitiesRetrieveTests::OwnIdentitiesRetrieveTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("OwnIdentitiesRetrieveTests::check_own_identities_retrieve"),
                                                                      static_cast<Func>(&OwnIdentitiesRetrieveTests::check_own_identities_retrieve)));
}

void OwnIdentitiesRetrieveTests::check_own_identities_retrieve() {
    stringlist_t* keylist = NULL;
    PEP_STATUS status = own_keys_retrieve(session, &keylist);
    TEST_ASSERT(keylist == NULL);
    TEST_ASSERT(status == PEP_STATUS_OK);

    identity_list* id_list = NULL;
    status = own_identities_retrieve(session, &id_list);
    TEST_ASSERT(id_list == NULL || !(id_list->ident));
    TEST_ASSERT(status == PEP_STATUS_OK);
    
    pEp_identity* me = new_identity("krista_b@darthmama.cool", NULL, "MyOwnId", "Krista B.");
    status = myself(session, me);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(me->fpr);
    
    // Ok, there's a me identity in the DB.
    // Call the naughty function.
    
    status = own_keys_retrieve(session, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist);
    TEST_ASSERT(keylist->value);
    cout << keylist->value << endl;

    status = own_identities_retrieve(session, &id_list);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(id_list);
    TEST_ASSERT(id_list->ident);    
}
