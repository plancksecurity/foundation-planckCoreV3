// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef LEAST_COLOR_GROUP_H
#define LEAST_COLOR_GROUP_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class LeastColorGroupTests : public EngineTestSessionSuite {
    public:
        LeastColorGroupTests(string test_suite, string test_home_dir);
    private:
        void check_least_color_group();
};

#endif
