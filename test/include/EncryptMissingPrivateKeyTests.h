// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef ENCRYPT_MISSING_PRIVATE_KEY_H
#define ENCRYPT_MISSING_PRIVATE_KEY_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class EncryptMissingPrivateKeyTests : public EngineTestSessionSuite {
    public:
        EncryptMissingPrivateKeyTests(string test_suite, string test_home_dir);
    protected:
        void setup();
    private:
        void check_encrypt_missing_private_key();
};

#endif
