// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef SIGN_ONLY_H
#define SIGN_ONLY_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class SignOnlyTests : public EngineTestIndividualSuite {
    public:
        SignOnlyTests(string test_suite, string test_home_dir);
    private:
        void check_sign_only();
};

#endif
