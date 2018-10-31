// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef DECORATE_TESTS_H
#define DECORATE_TESTS_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class DecorateTests : public EngineTestSessionSuite {
    public:
        DecorateTests(string suitename, string test_home_dir);
    private:
        void check_decorate();
};

#endif
