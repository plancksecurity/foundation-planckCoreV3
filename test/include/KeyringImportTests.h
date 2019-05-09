// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef KEYRING_IMPORT_TESTS_H
#define KEYRING_IMPORT_TESTS_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class KeyringImportTests : public EngineTestSessionSuite {
    public:
        KeyringImportTests(string test_suite, string test_home_dir);
	protected:
        void setup();
        void tear_down();
    private:
        void import();
};

#endif
