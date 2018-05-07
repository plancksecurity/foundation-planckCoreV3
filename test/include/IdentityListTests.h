// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef IDENTITY_LIST_H
#define IDENTITY_LIST_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class IdentityListTests : public EngineTestSessionSuite {
    public:
        IdentityListTests(string test_suite, string test_home_dir);
    private:
        void check_identity_list();
};

#endif
