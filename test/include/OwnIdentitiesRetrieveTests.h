// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef OWN_IDENTITIES_RETRIEVE_H
#define OWN_IDENTITIES_RETRIEVE_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class OwnIdentitiesRetrieveTests : public EngineTestIndividualSuite {
    public:
        OwnIdentitiesRetrieveTests(string test_suite, string test_home_dir);
    private:
        void check_own_identities_retrieve();
};

#endif
