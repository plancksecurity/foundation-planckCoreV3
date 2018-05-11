// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef APPLE_MAIL_TESTS_H
#define APPLE_MAIL_TESTS_H

#include <string.h>
#include "EngineTestSessionSuite.h"

using namespace std;

class AppleMailTests : public EngineTestSessionSuite {
    public:
        AppleMailTests(string suitename, string test_home_dir);
    private:
        void check_apple_mail();
};

#endif
