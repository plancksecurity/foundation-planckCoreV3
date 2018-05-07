// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef MISTRUST_UNDO_H
#define MISTRUST_UNDO_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class MistrustUndoTests : public EngineTestSessionSuite {
    public:
        MistrustUndoTests(string test_suite, string test_home_dir);
    private:
        void check_mistrust_undo();
};

#endif
