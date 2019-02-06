// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef ENCRYPT_ATTACH_PRIVATE_KEY_H
#define ENCRYPT_ATTACH_PRIVATE_KEY_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class EncryptAttachPrivateKeyTests : public EngineTestSessionSuite {
    public:
        EncryptAttachPrivateKeyTests(string test_suite, string test_home_dir);
    private:
        void check_encrypt_attach_private_key();
};

#endif
