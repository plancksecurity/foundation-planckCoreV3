// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PGP_BINARY_H
#define PGP_BINARY_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class PgpBinaryTests : public EngineTestSessionSuite {
    public:
        PgpBinaryTests(string test_suite, string test_home_dir);
    private:
        void check_pgp_binary();
};

#endif
