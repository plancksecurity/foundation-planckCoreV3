// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include <cpptest.h>
#include "test_util.h"

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "GetKeyRatingForUserTests.h"

using namespace std;

GetKeyRatingForUserTests::GetKeyRatingForUserTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GetKeyRatingForUserTests::check_get_key_rating_for_user"),
                                                                      static_cast<Func>(&GetKeyRatingForUserTests::check_get_key_rating_for_user)));
}

void GetKeyRatingForUserTests::check_get_key_rating_for_user() {
    pEp_identity* alice = NULL;
    PEP_STATUS status = set_up_preset(session, ALICE, false, false, false, false, false, &alice);
    pEp_identity* test_null = NULL;
    const char* fpr_save = alice->fpr;
    alice->fpr = NULL;
    status = get_identity(session, alice->address, alice->user_id, &test_null);
    TEST_ASSERT(!test_null);
    TEST_ASSERT(status == PEP_CANNOT_FIND_IDENTITY);
    TEST_ASSERT_MSG(alice->comm_type == PEP_ct_unknown, tl_ct_string(alice->comm_type));

    // Ok, so we have no info really, let's set it.
    status = set_identity(session, alice);
    
    status = update_identity(session, alice);
    TEST_ASSERT(alice->fpr);

    PEP_rating rating;
    status = get_key_rating_for_user(session, alice->user_id, alice->fpr, &rating);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    cout << tl_rating_string(rating) << endl;
    TEST_ASSERT(true);
}
