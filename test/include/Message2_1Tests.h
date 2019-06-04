// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef MESSAGE2_1_H
#define MESSAGE2_1_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class Message2_1Tests : public EngineTestIndividualSuite {
    public:
        Message2_1Tests(string test_suite, string test_home_dir);
    private:
        void check_message2_1();
};

#endif
