// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef LEAST_COMMON_DENOM_COLOR_H
#define LEAST_COMMON_DENOM_COLOR_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class LeastCommonDenomColorTests : public EngineTestSessionSuite {
    public:
        LeastCommonDenomColorTests(string test_suite, string test_home_dir);
    private:
        void check_least_common_denom_color();
};

#endif
