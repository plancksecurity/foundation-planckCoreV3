// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PGP_LIST_KEYS_H
#define PGP_LIST_KEYS_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class PgpListKeysTests : public EngineTestSessionSuite {
    public:
        PgpListKeysTests(string test_suite, string test_home_dir);
    private:
        void check_pgp_list_keys();
};

#endif
