// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef REVOCATION_H
#define REVOCATION_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class RevocationTests : public EngineTestSessionSuite {
    public:
        RevocationTests(string test_suite, string test_home_dir);
	protected:
        void setup();
        void tear_down();
    private:
        void revocation();
};

#endif
