// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef TRUSTWORDS_TESTS_H
#define TRUSTWORDS_TESTS_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class TrustwordsTests : public EngineTestIndividualSuite {
    public:
        TrustwordsTests(string suitename, string test_home_dir);
    private:
        void check_trustwords();
};

#endif
