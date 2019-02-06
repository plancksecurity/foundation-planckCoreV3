// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef MESSAGE2_0_H
#define MESSAGE2_0_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class Message2_0Tests : public EngineTestSessionSuite {
    public:
        Message2_0Tests(string test_suite, string test_home_dir);
    private:
        void check_message2_0();
};

#endif
