// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef STRINGLIST_TESTS_H
#define STRINGLIST_TESTS_H

#include <string>
#include "EngineTestSuite.h"

using namespace std;

class StringlistTests : public EngineTestSuite {
    public:
        StringlistTests(string suitename, string test_home_dir);
    private:
        void check_stringlists();
};

#endif
