// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef KEY_RESET_MESSAGE_H
#define KEY_RESET_MESSAGE_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class KeyResetMessageTests : public EngineTestIndividualSuite {
    public:
        KeyResetMessageTests(string test_suite, string test_home_dir);
    protected:
        char* sender_revoked_key_fpr;
        char* recip_revoked_key_fpr;
    private:
        void check_key_reset_message();        
};

#endif
