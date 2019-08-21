// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef REENCRYPT_PLUS_EXTRA_KEYS_H
#define REENCRYPT_PLUS_EXTRA_KEYS_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class ReencryptPlusExtraKeysTests : public EngineTestSessionSuite {
    public:
        ReencryptPlusExtraKeysTests(string test_suite, string test_home_dir);
    private:
        void check_reencrypt_plus_extra_keys();
        void check_efficient_reencrypt();
};

#endif
