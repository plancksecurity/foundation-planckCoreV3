// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef SENDER_F_P_R_H
#define SENDER_F_P_R_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class SenderFPRTests : public EngineTestIndividualSuite {
    public:
        SenderFPRTests(string test_suite, string test_home_dir);
    private:
        void check_sender_f_p_r();
};

#endif
