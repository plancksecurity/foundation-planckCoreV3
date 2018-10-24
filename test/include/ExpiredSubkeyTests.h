// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef EXPIRED_SUBKEY_H
#define EXPIRED_SUBKEY_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class ExpiredSubkeyTests : public EngineTestIndividualSuite {
    public:
        ExpiredSubkeyTests(string test_suite, string test_home_dir);
    private:
        void expired_subkey_with_valid_subkeys_and_main_key();
        void expired_subkey_with_valid_subkeys_expired_main();        
        void all_valid_with_leftover_expired_subkeys();         
        void no_valid_encryption_subkey();       
};

#endif
