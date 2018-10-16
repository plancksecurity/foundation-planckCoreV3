// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef APPLE_MAIL_TESTS_H
#define APPLE_MAIL_TESTS_H

#include <string.h>
#include "EngineTestIndividualSuite.h"

using namespace std;

class AppleMailTests : public EngineTestIndividualSuite {
    public:
        AppleMailTests(string suitename, string test_home_dir);
    private:
        void check_apple_mail_text_signed_encrypted();
        void check_apple_mail_html_signed_encrypted();
};

#endif
