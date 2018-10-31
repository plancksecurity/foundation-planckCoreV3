// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef EXTERNAL_REVOKE_H
#define EXTERNAL_REVOKE_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class ExternalRevokeTests : public EngineTestSessionSuite {
    public:
        ExternalRevokeTests(string test_suite, string test_home_dir);
    private:
        void check_external_revoke();
};

#endif
