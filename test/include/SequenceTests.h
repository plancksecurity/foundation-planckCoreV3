// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef SEQUENCE_TESTS_H
#define SEQUENCE_TESTS_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class SequenceTests : public EngineTestSessionSuite {
    public:
        SequenceTests(string suitename, string test_home_dir);
    private:
        void check_sequences();
};

#endif
