// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef EXPORT_KEY_UTIL_H
#define EXPORT_KEY_UTIL_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class ExportKeyUtilTests : public EngineTestIndividualSuite {
    public:
        ExportKeyUtilTests(string test_suite, string test_home_dir);
    protected:
        void setup();    
    private:
        void check_export_key_util();
};

#endif
