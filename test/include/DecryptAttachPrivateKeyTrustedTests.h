// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef DECRYPT_ATTACH_PRIVATE_KEY_TRUSTED_H
#define DECRYPT_ATTACH_PRIVATE_KEY_TRUSTED_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class DecryptAttachPrivateKeyTrustedTests : public EngineTestSessionSuite {
    public:
        DecryptAttachPrivateKeyTrustedTests(string test_suite, string test_home_dir);
    private:
        void check_decrypt_attach_private_key_trusted();
};

#endif
