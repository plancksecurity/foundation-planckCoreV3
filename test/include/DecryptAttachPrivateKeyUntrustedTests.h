// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef DECRYPT_ATTACH_PRIVATE_KEY_UNTRUSTED_H
#define DECRYPT_ATTACH_PRIVATE_KEY_UNTRUSTED_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class DecryptAttachPrivateKeyUntrustedTests : public EngineTestSessionSuite {
    public:
        DecryptAttachPrivateKeyUntrustedTests(string test_suite, string test_home_dir);
    private:
        void check_decrypt_attach_private_key_untrusted();
};

#endif
