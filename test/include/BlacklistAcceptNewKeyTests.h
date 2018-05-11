// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef BLACKLIST_ACCEPT_NEW_KEY_H
#define BLACKLIST_ACCEPT_NEW_KEY_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class BlacklistAcceptNewKeyTests : public EngineTestSessionSuite {
    public:
        BlacklistAcceptNewKeyTests(string test_suite, string test_home_dir);
    private:
        void check_blacklist_accept_new_key();
};

#endif
