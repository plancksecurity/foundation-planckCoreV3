// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef NO_OWN_IDENT_WRITES_ON_DECRYPT_H
#define NO_OWN_IDENT_WRITES_ON_DECRYPT_H

#include <string>
#include "EngineTestIndividualSuite.h"
#include "pEpEngine.h"
#include "message.h"

using namespace std;

class NoOwnIdentWritesOnDecryptTests : public EngineTestIndividualSuite {
    public:
        NoOwnIdentWritesOnDecryptTests(string test_suite, string test_home_dir);
        ~NoOwnIdentWritesOnDecryptTests();
        message* _to_decrypt;
    private:
        void check_no_own_ident_writes_on_decrypt();        
        void check_address_only_no_overwrite();
        void check_full_info_no_overwrite();
};

#endif
