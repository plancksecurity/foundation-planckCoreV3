// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef SYNC_H
#define SYNC_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class SyncTests : public EngineTestSessionSuite {
    public:
        SyncTests(string test_suite, string test_home_dir);
    private:
        void check_sync();
};

#endif
