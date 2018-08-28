// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef MESSAGE_NULL_FROM_H
#define MESSAGE_NULL_FROM_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class MessageNullFromTests : public EngineTestIndividualSuite {
    public:
        MessageNullFromTests(string test_suite, string test_home_dir);
    private:
        void check_message_null_from_no_header_key_unencrypted();
};

#endif
