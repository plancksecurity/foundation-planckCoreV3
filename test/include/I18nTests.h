// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef I18N_H
#define I18N_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class I18nTests : public EngineTestSessionSuite {
    public:
        I18nTests(string test_suite, string test_home_dir);
    private:
        void check_i18n();
};

#endif
