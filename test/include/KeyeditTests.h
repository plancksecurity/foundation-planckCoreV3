// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef KEYEDIT_H
#define KEYEDIT_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class KeyeditTests : public EngineTestSessionSuite {
    public:
        KeyeditTests(string test_suite, string test_home_dir);
    private:
        void check_keyedit();
};

#endif
