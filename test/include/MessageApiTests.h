// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef MESSAGE_API_H
#define MESSAGE_API_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class MessageApiTests : public EngineTestSessionSuite {
    public:
        MessageApiTests(string test_suite, string test_home_dir);
    private:
        void check_message_api();
};

#endif
