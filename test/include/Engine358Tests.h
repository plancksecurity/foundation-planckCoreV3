// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef ENGINE358_H
#define ENGINE358_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class Engine358Tests : public EngineTestIndividualSuite {
    public:
        Engine358Tests(string test_suite, string test_home_dir);
    private:
        void check_engine358();
};

#endif
