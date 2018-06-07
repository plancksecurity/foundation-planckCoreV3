// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef REVOKE_REGEN_ATTACH_H
#define REVOKE_REGEN_ATTACH_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class RevokeRegenAttachTests : public EngineTestSessionSuite {
    public:
        RevokeRegenAttachTests(string test_suite, string test_home_dir);
    protected:
        void setup();
    private:
        void check_revoke_regen_attach();
};

#endif
