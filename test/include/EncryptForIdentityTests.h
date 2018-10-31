// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef ENCRYPT_FOR_IDENTITY_H
#define ENCRYPT_FOR_IDENTITY_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class EncryptForIdentityTests : public EngineTestSessionSuite {
    public:
        EncryptForIdentityTests(string test_suite, string test_home_dir);
    private:
        void check_encrypt_for_identity();
};

#endif
