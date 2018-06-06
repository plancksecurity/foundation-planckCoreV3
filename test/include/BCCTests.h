// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef BCC_H
#define BCC_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class BCCTests : public EngineTestIndividualSuite {
    public:
        BCCTests(string test_suite, string test_home_dir);
    protected:
	void setup();
    private:
        void check_single_BCC();
};

#endif
