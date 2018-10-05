// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef ENGINE463_H
#define ENGINE463_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class Engine463Tests : public EngineTestIndividualSuite {
    public:
        Engine463Tests(string test_suite, string test_home_dir);
    private:
        void check_engine_463_no_own_key();
        void check_engine_463_own_key();
};

#endif
