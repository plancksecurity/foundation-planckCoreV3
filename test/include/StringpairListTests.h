// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef STRINGPAIR_LIST_TESTS_H
#define STRINGPAIR_LIST_TESTS_H

#include <string>
#include "EngineTestSuite.h"

using namespace std;

class StringpairListTests : public EngineTestSuite {
    public:
        StringpairListTests(string suitename, string test_home_dir);
    private:
        void check_stringpair_lists();
        bool test_stringpair_equals(stringpair_t* val1, stringpair_t* val2);
};

#endif
