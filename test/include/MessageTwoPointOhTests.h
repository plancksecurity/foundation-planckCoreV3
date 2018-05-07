// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef MESSAGE_TWO_POINT_OH_H
#define MESSAGE_TWO_POINT_OH_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class MessageTwoPointOhTests : public EngineTestSessionSuite {
    public:
        MessageTwoPointOhTests(string test_suite, string test_home_dir);
    private:
        void check_message_two_point_oh();
};

#endif
