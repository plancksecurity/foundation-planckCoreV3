// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef CRASHDUMP_H
#define CRASHDUMP_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class CrashdumpTests : public EngineTestSessionSuite {
    public:
        CrashdumpTests(string test_suite, string test_home_dir);
    private:
        void check_crashdump();
};

#endif
