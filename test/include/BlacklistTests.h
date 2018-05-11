// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef BLACKLIST_H
#define BLACKLIST_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class BlacklistTests : public EngineTestSessionSuite {
    public:
        BlacklistTests(string test_suite, string test_home_dir);
    private:
        void check_blacklist();
};

#endif
