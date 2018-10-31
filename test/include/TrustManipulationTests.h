// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef TRUST_MANIPULATION_TESTS_H
#define TRUST_MANIPULATION_TESTS_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class TrustManipulationTests : public EngineTestSessionSuite {
    public:
        TrustManipulationTests(string suitename, string test_home_dir);
    private:
        void check_trust_manipulation();
};

#endif
