// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef I_O_S1664_H
#define I_O_S1664_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class IOS1664Tests : public EngineTestIndividualSuite {
    public:
        IOS1664Tests(string test_suite, string test_home_dir);
    private:
        void check_i_o_s1664();
};

#endif
