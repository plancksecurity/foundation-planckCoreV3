// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef LOTS_OF_KEYS_H
#define LOTS_OF_KEYS_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class LotsOfKeysTests : public EngineTestIndividualSuite {
    public:
        LotsOfKeysTests(string test_suite, string test_home_dir);
    private:
        void check();
};

#endif
