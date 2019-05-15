// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef LITERAL_FILENAME_H
#define LITERAL_FILENAME_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class LiteralFilenameTests : public EngineTestIndividualSuite {
    public:
        LiteralFilenameTests(string test_suite, string test_home_dir);
    private:
        void check();
};

#endif
