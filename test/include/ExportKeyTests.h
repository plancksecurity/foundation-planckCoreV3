// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef EXPORT_KEY_H
#define EXPORT_KEY_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class ExportKeyTests : public EngineTestIndividualSuite {
    public:
        ExportKeyTests(string test_suite, string test_home_dir);
    private:
        void check_export_key_no_key();
        void check_export_key_no_secret_key();
};

#endif
