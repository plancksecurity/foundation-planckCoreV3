// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef LOOKUP_H
#define LOOKUP_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class LookupTests : public EngineTestSessionSuite {
    public:
        LookupTests(string test_suite, string test_home_dir);
	protected:
        void setup();
        void tear_down();
    private:
        void lookup();
};

#endif
