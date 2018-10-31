// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef CASE_AND_DOT_ADDRESS_TESTS_H
#define CASE_AND_DOT_ADDRESS_TESTS_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class CaseAndDotAddressTests : public EngineTestSessionSuite {
    public:
        CaseAndDotAddressTests(string suitename, string test_home_dir);
    private:
        void check_case_and_dot_address();
};

#endif
