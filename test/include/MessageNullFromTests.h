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
    protected:
        void setup();
    private:
        void check_message_null_from_no_header_key_unencrypted();
        void check_message_null_from_header_key_unencrypted();
        void check_message_null_from_encrypted_not_signed();
        void check_message_null_from_encrypted_and_signed(); 
        void import_bob_pair_and_set_own();
        void import_alice_pub();
};

#endif
