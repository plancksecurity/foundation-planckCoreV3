// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef USERID_ALIAS_TESTS_H
#define USERID_ALIAS_TESTS_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class UserIDAliasTests : public EngineTestIndividualSuite {
    public:
        UserIDAliasTests(string suitename, string test_home_dir);
    private:
        void check_userid_aliases();
};

#endif
