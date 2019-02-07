// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef SIMPLE_BODY_NOT_ALT_H
#define SIMPLE_BODY_NOT_ALT_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class SimpleBodyNotAltTests : public EngineTestIndividualSuite {
    public:
        SimpleBodyNotAltTests(string test_suite, string test_home_dir);
    private:
        void check_text_w_html_attach();
        void check_html_w_text_attach();
};

#endif
