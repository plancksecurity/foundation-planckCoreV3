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
        bool verify_message_version_produced(message* enc_msg, unsigned int* maj_inout, unsigned int* min_inout);
        
        void check_message2_1_recip_2_0();
        void check_message2_1_recip_OpenPGP();
        void check_message2_1_recip_2_1();
        void check_message2_1_recip_1_0_from_msg_OpenPGP();
        void check_message2_1_recip_2_0_from_msg();
        void check_message2_1_recip_2_1_from_msg();
        void check_message2_1_recip_mixed_2_0();
        void check_message2_1_recip_mixed_1_0_OpenPGP();
};

#endif
